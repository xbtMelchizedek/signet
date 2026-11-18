import { Keyring } from "@polkadot/keyring";
import type { KeyringPair, KeyringPair$Json } from "@polkadot/keyring/types";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import type { KeypairType } from "@polkadot/util-crypto/types";

/** Secret-URI crypto schemes accepted as an explicit --signer prefix. */
export const TYPED_SIGNER_SCHEMES = ["ed25519", "sr25519"] as const;

export type TypedSignerScheme = (typeof TYPED_SIGNER_SCHEMES)[number];

/** Default scheme when --signer has no ed25519: or sr25519: prefix. */
export const DEFAULT_SIGNER_SCHEME: TypedSignerScheme = "sr25519";

const TYPED_SIGNER_RE = /^(ed25519|sr25519):(.*)$/s;

export const EMPTY_TYPED_SIGNER_URI =
  "typed signer URI must not be empty";

export type ParsedTypedSigner = {
  type: TypedSignerScheme;
  uri: string;
  /** True when the caller wrote an explicit ed25519: or sr25519: prefix. */
  explicit: boolean;
};

/**
 * Parse a FLOP CLI --signer secret URI.
 *
 * `ed25519:<secret-URI>` and `sr25519:<secret-URI>` set the key type and
 * strip only that prefix. Anything else, including a bare `//Alice` or a
 * mnemonic, stays sr25519. Encrypted keystore handles (`keystore:...`) are
 * not parsed here; callers must keep that path separate.
 *
 * Never logs `signer` or the stripped URI.
 */
export function parseTypedSecretUri(signer: string): ParsedTypedSigner {
  const match = TYPED_SIGNER_RE.exec(signer);
  if (match) {
    const type = match[1] as TypedSignerScheme;
    const uri = match[2] ?? "";
    if (!uri) {
      throw new Error(EMPTY_TYPED_SIGNER_URI);
    }
    return { type, uri, explicit: true };
  }
  if (!signer) {
    throw new Error(EMPTY_TYPED_SIGNER_URI);
  }
  return { type: DEFAULT_SIGNER_SCHEME, uri: signer, explicit: false };
}

export function isKeystoreSigner(signer: string | undefined): boolean {
  return !!signer?.startsWith("keystore:");
}

/**
 * After cryptoWaitReady(), build a Keyring pair from a typed or legacy
 * secret URI. Does not accept keystore: handles.
 */
export async function loadTypedUriPair(signer: string): Promise<KeyringPair> {
  const { type, uri } = parseTypedSecretUri(signer);
  await cryptoWaitReady();
  return new Keyring({ type: type as KeypairType, ss58Format: 42 }).addFromUri(
    uri,
  );
}

/**
 * Load an encrypted Polkadot JSON keystore. Type comes from the file
 * (`encoding.content[1]`), defaulting to sr25519, matching @flop-labs/cli
 * 0.5.0. Password is read from the named environment variable only.
 */
export async function loadKeystore(
  path: string,
  envName: string,
): Promise<KeyringPair> {
  const password = process.env[envName];
  if (!password) {
    throw new Error(
      `keystore password environment variable is unset: ${envName}`,
    );
  }
  const { readFile } = await import("node:fs/promises");
  await cryptoWaitReady();
  const json = JSON.parse(await readFile(path, "utf8")) as KeyringPair$Json;
  const type = (json.encoding?.content?.[1] ?? "sr25519") as KeypairType;
  const keyring = new Keyring({ type, ss58Format: 42 });
  const pair = keyring.addFromJson(json);
  pair.decodePkcs8(password);
  return pair;
}

/** Split a `keystore:<path>:<env>` handle the same way the 0.5.0 CLI does. */
export function parseKeystoreHandle(signer: string): {
  path: string;
  envName: string;
} {
  const [, encodedPath, encodedEnv] = signer.split(":");
  return {
    path: decodeURIComponent(encodedPath ?? ""),
    envName: decodeURIComponent(encodedEnv ?? ""),
  };
}

export async function loadSignerPair(signer: string): Promise<KeyringPair> {
  if (isKeystoreSigner(signer)) {
    const { path, envName } = parseKeystoreHandle(signer);
    return loadKeystore(path, envName);
  }
  return loadTypedUriPair(signer);
}
