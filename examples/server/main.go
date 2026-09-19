// Command server is a minimal Cap backend using capgo.
//
//	go run ./examples/server            # in-memory store, format 2 (rsw)
//	REDIS_ADDR=127.0.0.1:6379 go run ./examples/server
//
// Then open http://127.0.0.1:8080/ and solve the widget.
package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/redis/go-redis/v9"

	"github.com/zwh20081/capgo"
	"github.com/zwh20081/capgo/caphttp"
	"github.com/zwh20081/capgo/capredis"
)

const page = `<!doctype html><html><head><meta charset="utf-8">
<script src="https://cdn.jsdelivr.net/npm/@cap.js/widget@0.1.56"></script></head>
<body style="font-family:system-ui;padding:2rem">
<h1>capgo demo</h1>
<cap-widget id="cap" data-cap-api-endpoint="/api/cap/login/"></cap-widget>
<pre id="out"></pre>
<script>
document.getElementById("cap").addEventListener("solve", async (e) => {
  const r = await fetch("/api/login", {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({capToken:e.detail.token})});
  document.getElementById("out").textContent = await r.text();
});
</script></body></html>`

func main() {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	// In production persist the keypair (json.Marshal) instead of regenerating.
	keypair, err := capgo.GenerateRSWKeypair(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	var store capgo.Store = capgo.NewMemoryStore()
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		store = capredis.New(redis.NewClient(&redis.Options{Addr: addr}))
	}

	c, err := capgo.New(capgo.Options{
		Secret:     secret,
		Store:      store,
		Format:     2,
		Protocols:  []capgo.Protocol{capgo.ProtocolRSW},
		RSWKeypair: keypair,
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	handler := caphttp.New(c, caphttp.Options{Scopes: []string{"login", "signup"}, RequireScope: true})
	handler.Register(mux, "/api/cap")

	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CapToken string `json:"capToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ok, err := c.Validate(r.Context(), body.CapToken, capgo.ValidateOptions{Scope: "login"})
		if err != nil {
			http.Error(w, "captcha backend unavailable", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			http.Error(w, "captcha required", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("logged in\n"))
	})

	log.Println("listening on http://127.0.0.1:8080/")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}
