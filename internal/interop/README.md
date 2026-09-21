# Interoperability and browser tests

This test project pins `capjs-core` 0.1.2, `@cap.js/widget` 0.1.57 and
Playwright in `package-lock.json`. It checks:

- Go challenges against the official verifier, including wrong scopes, invalid
  RSW solutions and missing instrumentation.
- Custom generator selection, malformed output, failures and cancellation.
- Official generator levels, missing advanced dependencies and process cancellation.
- The actual widget running Go and official scripts in Chromium's sandboxed
  iframe, redeeming through `caphttp` and receiving single-use tokens.

Requires Go 1.24+, Node.js 24 and npm. Install from this directory:

```sh
npm ci
npx playwright install chromium
```

Run from the repository root:

```sh
go test ./...
go run ./internal/tools/emit_vectors.go > internal/interop/go-vectors.json
cd internal/interop
npm run verify
npm test
```

On Windows PowerShell 5, write `go-vectors.json` as UTF-8 (its default redirect
encoding is UTF-16). PowerShell 7 and POSIX shell redirects work as shown.

`npm test` runs Go tests tagged `integration`; it fails if Node.js, npm packages
or Chromium are unavailable. Regular `go test ./...` needs none of these.
Set `CAPGO_BROWSER_CASE` to a case-name substring (for example
`official-signed-9`) to diagnose one browser case; leave it unset for the full
28-case matrix. Advanced-level cases also regress the dynamic eval probe that
unmodified upstream obfuscation can break.
The browser tests serve pinned widget and WASM files locally and reject external
network requests. Format-2 PoW uses `ChallengeSize: 16` (32 hex characters):
the official WASM 0.0.7 solver only supports a single SHA-256 block and cannot
solve the 64-character salts produced by the upstream default size of 32.
CI installs Chromium's Linux dependencies with
`npx playwright install --with-deps chromium` before running the same checks.
