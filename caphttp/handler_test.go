package caphttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zwh20081/capgo"
	"github.com/zwh20081/capgo/caphttp"
)

func newServer(t *testing.T, opts caphttp.Options) (*httptest.Server, *caphttp.Handler) {
	t.Helper()
	c, err := capgo.New(capgo.Options{Secret: bytes.Repeat([]byte{7}, 32), ChallengeCount: 1, ChallengeDifficulty: 1, Stateless: true})
	if err != nil {
		t.Fatal(err)
	}
	h := caphttp.New(c, opts)
	mux := http.NewServeMux()
	h.Register(mux, "/api/cap")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, h
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	resp, err := http.Post(url, "application/json", reader)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestWidgetContract(t *testing.T) {
	srv, h := newServer(t, caphttp.Options{Scopes: []string{"login"}})
	status, body := post(t, srv.URL+"/api/cap/login/challenge", nil)
	if status != 200 || body["token"] == nil || body["challenge"] == nil {
		t.Fatalf("challenge = %d %v", status, body)
	}
	raw, _ := json.Marshal(body)
	var ch capgo.Challenge
	_ = json.Unmarshal(raw, &ch)
	solutions, _ := capgo.SolveChallenge(&ch)

	// Wrong scope path is rejected before touching the token.
	status, body = post(t, srv.URL+"/api/cap/signup/redeem", map[string]any{"token": ch.Token, "solutions": json.RawMessage(solutions)})
	if status != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("bad scope = %d %v", status, body)
	}
	// Unscoped redeem does not enforce scope (capjs-core semantics) but the
	// issued token still carries the challenge scope.
	status, body = post(t, srv.URL+"/api/cap/redeem", map[string]any{"token": ch.Token, "solutions": json.RawMessage(solutions)})
	if status != 200 || body["success"] != true {
		t.Fatalf("unscoped redeem = %d %v", status, body)
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if ok, _ := h.Validate(req, body["token"].(string), "signup"); ok {
		t.Fatal("token accepted for wrong scope")
	}
	if ok, _ := h.Validate(req, body["token"].(string), "login"); !ok {
		t.Fatal("token rejected for its own scope")
	}
	// Fresh challenge for the scoped path.
	_, body = post(t, srv.URL+"/api/cap/login/challenge", nil)
	raw, _ = json.Marshal(body)
	_ = json.Unmarshal(raw, &ch)
	solutions, _ = capgo.SolveChallenge(&ch)
	status, body = post(t, srv.URL+"/api/cap/login/redeem", map[string]any{"token": ch.Token, "solutions": json.RawMessage(solutions)})
	if status != 200 || body["success"] != true || body["token"] == nil || body["expires"] == nil {
		t.Fatalf("redeem = %d %v", status, body)
	}
	token := body["token"].(string)
	if ok, _ := h.Validate(req, token, "login"); !ok {
		t.Fatal("token rejected")
	}
	if ok, _ := h.Validate(req, token, "login"); ok {
		t.Fatal("token reused")
	}
	// Replay reports the capjs-core reason with success:false and HTTP 200.
	status, body = post(t, srv.URL+"/api/cap/login/redeem", map[string]any{"token": ch.Token, "solutions": json.RawMessage(solutions)})
	if status != 200 || body["success"] != false || body["error"] != capgo.ReasonAlreadyRedeemed {
		t.Fatalf("replay = %d %v", status, body)
	}
	status, body = post(t, srv.URL+"/api/cap/login/redeem", nil)
	if status != 400 || body["error"] != capgo.ReasonInvalidBody {
		t.Fatalf("invalid body = %d %v", status, body)
	}
	resp, _ := http.Get(srv.URL + "/api/cap/challenge")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
}

func TestRequireScopeAndCustomOptions(t *testing.T) {
	srv, _ := newServer(t, caphttp.Options{
		Scopes: []string{}, RequireScope: true,
		ChallengeOptions: func(r *http.Request, base capgo.ChallengeOptions) capgo.ChallengeOptions {
			base.ChallengeCount = 3
			return base
		},
	})
	if status, _ := post(t, srv.URL+"/api/cap/challenge", nil); status != 400 {
		t.Fatalf("unscoped status = %d", status)
	}
	status, body := post(t, srv.URL+"/api/cap/anything/challenge", nil)
	if status != 200 || body["challenge"].(map[string]any)["c"] != float64(3) {
		t.Fatalf("scoped = %d %v", status, body)
	}
}

func TestServeHTTPWithStripPrefix(t *testing.T) {
	c, _ := capgo.New(capgo.Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	h := caphttp.New(c, caphttp.Options{Scopes: []string{"x"}})
	srv := httptest.NewServer(http.StripPrefix("/cap", h))
	defer srv.Close()
	status, body := post(t, srv.URL+"/cap/x/challenge", nil)
	if status != 200 || body["token"] == nil {
		t.Fatalf("challenge = %d %v", status, body)
	}
	raw, _ := json.Marshal(body)
	var ch capgo.Challenge
	_ = json.Unmarshal(raw, &ch)
	solutions, _ := capgo.SolveChallenge(&ch)
	status, body = post(t, srv.URL+"/cap/x/redeem", map[string]any{"token": ch.Token, "solutions": json.RawMessage(solutions)})
	if status != 200 || body["success"] != true {
		t.Fatalf("redeem = %d %v", status, body)
	}
	ok, _ := c.Validate(context.Background(), body["token"].(string), capgo.ValidateOptions{Scope: "x"})
	if !ok {
		t.Fatal("token invalid")
	}
	resp, _ := http.Post(srv.URL+"/cap/x/nope", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 404 {
		t.Fatalf("unknown action status = %d", resp.StatusCode)
	}
}
