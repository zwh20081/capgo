//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zwh20081/capgo"
	"github.com/zwh20081/capgo/caphttp"
	"github.com/zwh20081/capgo/capjs"
)

// The actual npm widget solves both Go and official instrumentation in its
// sandboxed iframe. Successful redemption must then issue a single-use token.
func TestWidgetBrowserRoundTrip(t *testing.T) {
	moduleDir, err := filepath.Abs("../interop")
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := capgo.GenerateRSWKeypair(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(moduleDir, "node_modules")))))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body><script>window.CAP_CUSTOM_WASM_URL='/assets/@cap.js/wasm/browser/cap_wasm_bg.wasm';</script><script src="/assets/@cap.js/widget/cap.min.js"></script></body></html>`)
	})
	var names []string
	var verified atomic.Int32
	official := capjs.NewInstrumentationGenerator(capjs.Options{ModuleDir: moduleDir})
	for _, provider := range []string{"go", "official"} {
		for level := 1; level <= 10; level++ {
			if provider == "go" && level != 1 && level != 3 && level != 6 && level != 10 {
				continue
			}
			for index, mode := range []string{"stored", "signed", "format2"} {
				if provider == "official" && level < 8 && index != (level-1)%3 {
					continue
				}
				name := fmt.Sprintf("%s-%s-%d", provider, mode, level)
				if filter := os.Getenv("CAPGO_BROWSER_CASE"); filter != "" && !strings.Contains(name, filter) {
					continue
				}
				names = append(names, name)
				opts := capgo.Options{
					Secret: bytes.Repeat([]byte{0x42}, 32), Stateless: mode == "signed",
					ChallengeCount: 1, ChallengeDifficulty: 1, RSWKeypair: keypair, RSWIterations: 100,
					Instrumentation: &capgo.InstrumentationOptions{ObfuscationLevel: level},
				}
				if mode == "format2" {
					opts.Format = 2
					// The current official WASM solver only hashes a single SHA-256
					// block. Format 2 expresses size in bytes, hence 16 => 32 hex chars.
					opts.ChallengeSize = 16
					opts.Protocols = []capgo.Protocol{capgo.ProtocolSHA256PoW, capgo.ProtocolRSW}
				}
				if provider == "official" {
					opts.InstrumentationGenerator = official
				}
				c, err := capgo.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				prefix := "/api/" + name
				caphttp.New(c, caphttp.Options{}).Register(mux, prefix)
				mux.HandleFunc("POST "+prefix+"/verify", func(w http.ResponseWriter, r *http.Request) {
					var body struct{ Token string }
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						http.Error(w, err.Error(), 400)
						return
					}
					for _, want := range []bool{true, false} {
						ok, err := c.Validate(r.Context(), body.Token, capgo.ValidateOptions{})
						if err != nil || ok != want {
							http.Error(w, fmt.Sprintf("Validate=%v err=%v want=%v", ok, err, want), 500)
							return
						}
					}
					verified.Add(1)
					w.WriteHeader(http.StatusNoContent)
				})
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("CAPGO_BROWSER_CASE matched no cases")
	}
	mux.HandleFunc("GET /cases", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(names) })
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "browser.mjs", server.URL)
	cmd.Dir = moduleDir
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("browser suite: %v", err)
	}
	if int(verified.Load()) != len(names) {
		t.Fatalf("verified %d/%d widget tokens", verified.Load(), len(names))
	}
}
