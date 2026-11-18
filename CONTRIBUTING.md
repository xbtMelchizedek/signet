# Contributing

This is a standalone offer for [flop-labs/network#337](https://github.com/flop-labs/network/issues/337).
The FLOP CLI source in `flop-labs/flop-core` is not public, so work happens here.

## Checks

```bash
npm ci
npm run check
```

That runs `tsc --noEmit`, the unit tests, a secret scan, and a patch check
against published `@flop-labs/cli@0.5.0` (download, verify pinned hashes, apply,
`node --check`). The patched CLI is not executed against a network.

## Rules

- Use only public development secret URIs such as `//Alice`, or a throwaway
  generated in the test process. Never a real key, seed, or keystore.
- Keys and secrets never go in git, issues, logs, or the console. The loader
  must not log the URI.
- Do not sign, transfer, or submit anything on any chain from this repository.
- Leave the encrypted-keystore path, enrollment-wallet generation, and the
  gateway probe signer as they are in 0.5.0, except where a test shows a
  keystore still loads.
- Credit [almondous](https://github.com/almondous) if you change the URI-scheme
  approach they prototyped on #337.
