# Signet

Typed signer URIs for the FLOP CLI, so an agent with an Ed25519 `did:key`
can use its own account.

This is a standalone package and a patch against published
[`@flop-labs/cli@0.5.0`](https://www.npmjs.com/package/@flop-labs/cli),
offered for [flop-labs/network#337](https://github.com/flop-labs/network/issues/337).
The CLI source lives in private `flop-labs/flop-core` (`sdk/cli`) and is not
publicly readable, so this is not a fork of that tree.

Status: community offer. Devnet-oriented. This repository does not sign or
submit anything on any chain.

## The mismatch

`@flop-labs/cli` 0.5.0 builds a signer from a plain secret URI with
`new Keyring({ type: "sr25519" })`. Technocore and tclk agents hold an
Ed25519 `did:key`, and tclk-flop v1 uses that public key as the agent's
AccountId32. Passing the agent's seed as `--signer` quietly derives a
different sr25519 account. Encrypted keystores already keep their type
(`flop keys import --type ed25519`); only the plain-URI path has this
problem.

## The rule

```text
--signer ed25519:<secret-URI>     # Ed25519 pair (did:key / AccountId32)
--signer sr25519:<secret-URI>     # explicit sr25519
--signer <secret-URI>             # unchanged: still sr25519
--keystore <path> --password-env  # unchanged: type comes from the file
```

A missing URI after the prefix (`ed25519:` or `sr25519:`) is an error.
Unprefixed input, including `//Alice` on local, keeps its current
behavior. Enrollment-wallet generation and the gateway renew probe signer
are left as they are in 0.5.0.

The URI scheme follows the limited prototype [@almondous](https://github.com/almondous)
described on #337. This repository implements a shared loader, tests, help
text, and a patch against the published 0.5.0 bundle.

## Use the loader

```js
import { loadTypedUriPair, parseTypedSecretUri } from "./src/index.ts";

const pair = await loadTypedUriPair("ed25519://Alice");
// pair.type === "ed25519"
// pair.publicKey is the AccountId32 and the did:key public key
```

Only use public development URIs such as `//Alice`, or a throwaway you
generated, never a real seed.

## Apply the 0.5.0 patch

```bash
npm ci
node scripts/apply-cli-patch.mjs
```

The script downloads the official npm tarball, checks the pinned SHA-512
integrity and the `dist/cli.js` SHA-256, applies the same edits as
`patches/cli-0.5.0-typed-signer.patch`, and runs `node --check` on the
result. It does not execute the CLI against a network.

Pinned hashes for `@flop-labs/cli@0.5.0`:

- npm integrity: `sha512-zFLbjNdWHgc6IGO0kqwtU57dNsX29XYDWaxhbe0DtRw4QPekRpvz0yb2m/1q6dtzfTFyGz+1RBK4ll4iDnpW3w==`
- `dist/cli.js` SHA-256: `c94d7d6bdfee094c401aa5accd04faf19e6d48fd925ffd934f962c2ceca1de40`

## Checks

```bash
npm ci
npm run check    # lint, tests, secret scan, patch verify
```

## License

Source in `src/` is MIT, Copyright (c) 2026 xbtMelchizedek. The patch is a
modification of `@flop-labs/cli@0.5.0` (MIT OR Apache-2.0, Copyright (c)
2025-2026 The FLOP Network Contributors). See `LICENSE` and `NOTICE`.
