# capgo

[![Go Reference](https://pkg.go.dev/badge/github.com/zwh20081/capgo.svg)](https://pkg.go.dev/github.com/zwh20081/capgo)
[![CI](https://github.com/zwh20081/capgo/actions/workflows/ci.yml/badge.svg)](https://github.com/zwh20081/capgo/actions/workflows/ci.yml)

Go server SDK for [Cap](https://capjs.js.org), the proof-of-work CAPTCHA
alternative. Drop-in backend for the official `@cap.js/widget`. The default
implementation needs no Node.js; the optional `capjs` adapter uses Node.js for
the official generator's advanced instrumentation obfuscation.

It implements **every** server-side protocol the widget understands and is
verified byte-for-byte against the official JavaScript packages
(`@cap.js/server 4.0.5`, `capjs-core 0.1.2`): tokens issued by one side
validate on the other.

| Feature | Package |
|---|---|
| Format 1, stateful challenges (`@cap.js/server` compatible) | `capgo` |
| Format 1, stateless signed challenges (`capjs-core` compatible) | `capgo` |
| Format 2 with `sha256-pow`, `rsw` (time-lock) and `instrumentation` | `capgo` |
| Action scopes, replay protection, single-use verification tokens | `capgo` |
| Custom token signing (`SignToken` / `VerifyToken`) | `capgo` |
| Custom instrumentation generators (global or per challenge) | `capgo` |
| Official instrumentation generator with advanced obfuscation | `capgo/capjs` (optional Node.js) |
| In-memory store (single process) | `capgo.MemoryStore` |
| Redis store (multi-replica, atomic Lua) | `capgo/capredis` |
| `net/http` handler with the widget's wire contract | `capgo/caphttp` |
| Go-side solvers for tests and server-to-server use | `capgo.SolveChallenge` |

## Install

```sh
go get github.com/zwh20081/capgo
```

Requires Go 1.24+. `capredis` additionally pulls in `github.com/redis/go-redis/v9`.

## Quick start

```go
package main

import (
	"crypto/rand"
	"log"
	"net/http"

	"github.com/zwh20081/capgo"
	"github.com/zwh20081/capgo/caphttp"
)

func main() {
	secret := make([]byte, 32)
	rand.Read(secret) // keep it stable and shared across replicas in production

	c, err := capgo.New(capgo.Options{
		Secret:    secret,
		Stateless: true, // signed tokens, nothing stored until redeem
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	h := caphttp.New(c, caphttp.Options{Scopes: []string{"login", "signup"}})
	h.Register(mux, "/api/cap") // POST /api/cap/{scope}/challenge and /redeem

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("capToken")
		ok, err := c.Validate(r.Context(), token, capgo.ValidateOptions{Scope: "login"})
		if err != nil || !ok {
			http.Error(w, "captcha required", http.StatusBadRequest)
			return
		}
		// ... proceed
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Frontend:

```html
<script src="https://cdn.jsdelivr.net/npm/@cap.js/widget"></script>
<cap-widget data-cap-api-endpoint="/api/cap/login/"></cap-widget>
```

A runnable demo lives in [`examples/server`](examples/server/main.go).

## Choosing a mode

```go
// 1. Classic @cap.js/server behaviour: challenge stored server-side.
capgo.New(capgo.Options{})

// 2. Stateless signed format-1 (capjs-core). Only nonces/tokens are stored.
capgo.New(capgo.Options{Secret: secret, Stateless: true})

// 3. Format 2 with the RSW time-lock puzzle (sequential, GPU-proof).
kp, _ := capgo.GenerateRSWKeypair(rand.Reader, 2048) // persist with json.Marshal(kp)
capgo.New(capgo.Options{Secret: secret, Format: 2, RSWKeypair: kp, RSWIterations: 75_000})

// 4. Format 2 mixing protocols, plus the browser-environment probe.
capgo.New(capgo.Options{
	Secret: secret, Format: 2, RSWKeypair: kp,
	ChallengeSize: 16, // 32 hex characters, compatible with the widget's WASM solver
	Protocols:       []capgo.Protocol{capgo.ProtocolSHA256PoW, capgo.ProtocolRSW},
	Instrumentation: &capgo.InstrumentationOptions{BlockAutomatedBrowsers: true},
})
```

Instrumentation also works with format 1 (the blob is returned in the
`instrumentation` field, exactly like `capjs-core`).

When using format-2 `sha256-pow` with the current official widget, set
`ChallengeSize: 16`. Format 2 measures this setting in random bytes (two hex
characters per byte); format 1 measures it in characters. The current WASM
solver only supports salt-plus-nonce inputs shorter than 56 bytes, so the
default format-2 size of 32 produces salts it cannot solve. This upstream
solver limitation also applies to challenges from `capjs-core`.

## Advanced instrumentation

Use `InstrumentationGenerator` to supply a custom script and its verification
metadata. The hook receives the request context, entropy source, effective
instrumentation options and clock. Set it on `Options` for the instance or on
`ChallengeOptions` for one request. Instrumentation must also be enabled through
`Instrumentation` or an explicit format-2 instrumentation protocol.

For the official generator, install the npm packages in a separate runtime
directory and retain its lockfile:

```sh
npm install --save-exact capjs-core@0.1.2
```

Then configure the optional adapter:

```go
import "github.com/zwh20081/capgo/capjs"

c, err := capgo.New(capgo.Options{
	Secret: secret, Stateless: true,
	Instrumentation: &capgo.InstrumentationOptions{
		ObfuscationLevel: 9,
	},
	InstrumentationGenerator: capjs.NewInstrumentationGenerator(capjs.Options{
		ModuleDir: "/srv/cap-runtime", // contains node_modules/capjs-core
	}),
})
```

| Level | Default Go generator | Optional official generator |
|---|---|---|
| 1–3 | Whitespace cleanup | Whitespace cleanup |
| 4–7 | Shuffled string table | String table and esbuild minification |
| 8 | Shuffled string table | RC4 string encoding, control-flow flattening and dead-code injection |
| 9 | Shuffled string table | Level 8 plus stronger transforms and self-defending code |
| 10 | Shuffled string table | Level 9 plus debug protection and console suppression |

Levels 4–7 require `esbuild`; levels 8–10 also require `javascript-obfuscator`.
Both are dependencies of `capjs-core`, but the latter is optional in npm:
do not omit optional dependencies for advanced levels. The adapter reports an
error if the required dependency cannot load, rather than silently falling back.

For levels 8–10 the adapter applies the upstream obfuscation profile while
preserving the dynamic `eval` probe's local names and direct calls. Unmodified
core 0.1.2 obfuscation can rename or relocate these bindings and cause valid
browser executions to time out. No browser checks are removed.

The adapter starts a Node.js process for each generated challenge and uses
Node.js crypto for entropy. Apply request deadlines and bound concurrent
generation in your application. Context cancellation terminates the process.
The default Go generator and existing applications remain independent of Node.js.

A custom generator returns `*capgo.Instrumentation`: `Blob` is a base64-encoded
raw-DEFLATE script and `Meta` contains its ID, variable names, expected values
and browser-blocking policy. The SDK rejects empty or inconsistent metadata,
preserves generator errors and does not publish a challenge after cancellation.

## Multi-replica deployments

Use the Redis store so nonces, challenges and tokens are shared and every
single-use check is atomic:

```go
import (
	"github.com/redis/go-redis/v9"
	"github.com/zwh20081/capgo/capredis"
)

store := capredis.New(redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"}),
	capredis.WithPrefix("cap:"))
c, _ := capgo.New(capgo.Options{Secret: secret, Store: store, Stateless: true})
```

Every key carries a TTL, so no cleanup job is needed. Any type implementing
`capgo.Store` (SQL, Memcached, ...) can be plugged in the same way.

## Wire contract

`caphttp` speaks exactly what the widget expects:

| Route | Response |
|---|---|
| `POST {prefix}/challenge` | format-1 `{challenge:{c,s,d},token,expires[,instrumentation]}` or format-2 `{token,format:2,challenges:[...],expires}` |
| `POST {prefix}/redeem` | `{success:true,token,expires}` or `{success:false,error:"<reason>"[,instr_error:true]}` |
| `POST {prefix}/{scope}/challenge`, `.../redeem` | same, bound to a scope from the allowlist |

Reason codes (`already_redeemed`, `scope_mismatch`, `invalid_solution`,
`instr_automated_browser`, ...) are identical to `capjs-core` and exposed as
`capgo.Reason*` constants and `capgo.Err*` sentinels for `errors.Is`.

## Verifying tokens

`Validate` consumes the token (single use) unless `Keep` is set, and enforces
the scope it was issued for:

```go
ok, err := c.Validate(ctx, token, capgo.ValidateOptions{Scope: "login"})
```

To issue your own tokens (for example a JWT your other services can check
without the store) set `Options.SignToken` and `Options.VerifyToken`.

## Interoperability tests

`testdata/` contains fixtures produced by the official packages; the suite
proves that:

- `PRNG`, salts and targets match the widget/`@cap.js/server` derivation;
- signed format-1 and format-2 tokens from `capjs-core` (including RSW and
  instrumentation) redeem successfully here and are rejected on replay;
- challenges generated by capgo redeem successfully in `capjs-core`
  (checked with the Node script in the release process);
- the generated instrumentation script, executed in a real browser, produces
  the values the server expects.

```sh
go test ./...
```

The integration test project additionally runs the pinned `@cap.js/widget
0.1.57` in Chromium. It exercises stored format 1, signed format 1 and mixed
format 2 with PoW, RSW and instrumentation. Official levels 1–10 are executed
in the widget's sandboxed iframe; levels 8–10 run in all three modes. Every
successful widget token is checked for single use. CI runs this suite and the
official `capjs-core 0.1.2` interoperability checks on pushes and pull requests.
See [`internal/interop`](internal/interop/README.md) for local commands.

## Security notes

- `Secret` must be at least 16 bytes; use 32 random bytes and rotate by
  calling `Cap.Reset` after swapping it.
- The RSW private factors `p`, `q` never leave the server; only `N`, `x`, `t`
  are sent to clients.
- Rate-limit `/challenge` and `/redeem` per client IP at your edge; the SDK
  deliberately does not include a limiter.
- Instrumentation is a heuristic signal, not a guarantee. Combine it with PoW
  or RSW.

## License

Apache-2.0. See [NOTICE](NOTICE) for upstream attribution.
