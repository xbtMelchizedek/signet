import { decodePair } from "@polkadot/keyring/pair/decode";
import type { KeyringPair } from "@polkadot/keyring/types";
import {
  isKeystoreSigner,
  loadKeystore,
  loadTypedUriPair,
  parseKeystoreHandle,
  parseTypedSecretUri,
} from "./load-signer.ts";

/**
 * Minimal SDK surface used by the three 0.5.0 client-factory helpers.
 * Injected in tests so this package never talks to a chain.
 */
export type ClientFactorySdk = {
  FlopClient: {
    createWithKeypair: (
      rpcUrl: string,
      keypair: KeyringPair,
    ) => unknown | Promise<unknown>;
    create: (opts: { endpoint: string; signer?: string }) => unknown | Promise<unknown>;
  };
};

/**
 * Shared loader used by every client-factory helper.
 *
 * Encrypted keystores keep their encoded type. Explicit `ed25519:` /
 * `sr25519:` URIs become a Keyring pair. Unprefixed secret URIs stay a
 * string so the existing SDK sr25519 path is unchanged.
 */
export async function loadClientFactorySigner(signer: string): Promise<
  | { kind: "keypair"; keypair: KeyringPair }
  | { kind: "uri"; signerUri: string }
> {
  if (isKeystoreSigner(signer)) {
    const { path, envName } = parseKeystoreHandle(signer);
    return { kind: "keypair", keypair: await loadKeystore(path, envName) };
  }
  const parsed = parseTypedSecretUri(signer);
  if (parsed.explicit) {
    return { kind: "keypair", keypair: await loadTypedUriPair(signer) };
  }
  return { kind: "uri", signerUri: signer };
}

export async function createClient(
  rpcUrl: string,
  signer: string | undefined,
  sdk: ClientFactorySdk,
): Promise<unknown> {
  if (signer) {
    const loaded = await loadClientFactorySigner(signer);
    if (loaded.kind === "keypair") {
      return sdk.FlopClient.createWithKeypair(rpcUrl, loaded.keypair);
    }
  }
  const opts: { endpoint: string; signer?: string } = { endpoint: rpcUrl };
  if (signer) opts.signer = signer;
  return sdk.FlopClient.create(opts);
}

export async function agentSignerConfig(
  signer: string,
): Promise<{ keypair: KeyringPair } | { signerUri: string }> {
  const loaded = await loadClientFactorySigner(signer);
  if (loaded.kind === "keypair") {
    return { keypair: loaded.keypair };
  }
  return { signerUri: loaded.signerUri };
}

/**
 * DA shard helpers still require sr25519. An explicit ed25519: URI is
 * loaded (so the type is the real one), then rejected when required.
 * Optional calls return undefined instead of throwing.
 */
export async function sr25519KeyHex(
  signer: string,
  required = true,
): Promise<string | undefined> {
  const pair = isKeystoreSigner(signer)
    ? await loadKeystore(
        parseKeystoreHandle(signer).path,
        parseKeystoreHandle(signer).envName,
      )
    : await loadTypedUriPair(signer);
  if (pair.type !== "sr25519") {
    if (!required) return undefined;
    throw new Error(
      `DA shard uploads are signed with sr25519; this signer is ${pair.type}`,
    );
  }
  const { secretKey, publicKey } = decodePair(undefined, pair.encodePkcs8(), "none");
  return `0x${Buffer.from(secretKey).toString("hex")}${Buffer.from(publicKey).toString("hex")}`;
}
