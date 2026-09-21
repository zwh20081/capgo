# Changelog

## Unreleased

- Add global and per-challenge instrumentation generator hooks with request
  context propagation, cancellation and output validation in all formats.
- Add the optional `capjs` Node.js adapter for the official generator's
  esbuild minification and advanced obfuscation levels 8–10.
- Preserve the dynamic eval probe during advanced obfuscation so browser
  instrumentation does not fail after identifier or control-flow transforms.
- Upgrade interoperability checks to `capjs-core` 0.1.2 and commit the npm
  lockfile for reproducible integration tests.
- Add Chromium tests using `@cap.js/widget` 0.1.57 across all challenge modes,
  including actual instrumentation execution and single-use token validation.
- Run official interoperability and browser integration checks in CI.
- Make the signature-tampering regression deterministic by changing signature
  bytes instead of potentially changing only unused Base64 padding bits.
- Document the official WASM solver's salt-length limit and configure the
  mixed format-2 example with a compatible challenge size.

## v0.1.0

Initial release.

- Format-1 stateful challenges compatible with `@cap.js/server` 4.x.
- Format-1 stateless signed challenges and format-2 (`sha256-pow`, `rsw`,
  `instrumentation`) compatible with `capjs-core` 0.1.x.
- Scopes, nonce replay protection, single-use verification tokens,
  custom token signing hooks.
- `MemoryStore` and Redis (`capredis`) stores.
- `caphttp` handler implementing the widget wire contract.
- Interoperability fixtures generated with the official packages.
