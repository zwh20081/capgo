# Reverse interoperability check

Validates challenges produced by capgo with the official `capjs-core` package.

```sh
go run ./internal/tools/emit_vectors.go > internal/interop/go-vectors.json
cd internal/interop && npm install && npm run verify
```
