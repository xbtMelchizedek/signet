# Notes for flop-core maintainers

`@flop-labs/cli` 0.5.0 points at private `flop-labs/flop-core` (`sdk/cli`).
Until that tree is public, the TypeScript in `src/` is the form we would add
to `sdk/cli`, and `patches/cli-0.5.0-typed-signer.patch` is the equivalent
change against the published bundle.

## Shared loader

Add `parseTypedSecretUri` and `loadTypedUriPair` from `src/load-signer.ts`
and route every helper in `src/client-factory.ts` through
`loadClientFactorySigner`:

- `createClient` — explicit `ed25519:` / `sr25519:` URIs go through
  `FlopClient.createWithKeypair`; unprefixed URIs still call
  `FlopClient.create({ endpoint, signer })`.
- `agentSignerConfig` — explicit prefixes return `{ keypair }`; unprefixed
  URIs still return `{ signerUri }`.
- `sr25519KeyHex` — uses the same loader, then keeps the existing
  sr25519-only DA restriction.

`loadKeystore` is unchanged: the type still comes from
`encoding.content[1]`.

## Out of scope here (still open on #337)

- `--signer-type` as a separate flag (the URI scheme is enough for the
  mismatch).
- `flop keys inspect` / `whoami` for a did:key string.
- Enrollment wallet generation (`enrollmentWallet`).
- The gateway renew probe signer (`--probe-signer-env`).
- Automatic DID inference, default-type changes, or wallet migration.

## Help text

Update the global `--signer` option to:

> Signer secret URI (local/dev only; required outside local unless
> --keystore). Prefix ed25519:&lt;secret-URI&gt; or sr25519:&lt;secret-URI&gt;;
> unprefixed URIs stay sr25519

And add a README note that Technocore / tclk did:key agents should use
`ed25519:<secret-URI>` so the AccountId32 matches the did:key public key.
