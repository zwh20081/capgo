# Changelog

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
