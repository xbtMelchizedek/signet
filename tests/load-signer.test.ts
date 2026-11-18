import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady, encodeAddress } from "@polkadot/util-crypto";
import {
  EMPTY_TYPED_SIGNER_URI,
  agentSignerConfig,
  createClient,
  decodeDidKeyEd25519,
  encodeDidKeyEd25519,
  loadKeystore,
  loadTypedUriPair,
  parseTypedSecretUri,
  sr25519KeyHex,
  type ClientFactorySdk,
} from "../src/index.ts";

/** Public Substrate development URI. Never a real key. */
const TEST_URI = "//Alice";

function recordingSdk() {
  const calls: Array<
    | { method: "createWithKeypair"; rpcUrl: string; address: string; type: string }
    | { method: "create"; endpoint: string; signer?: string }
  > = [];
  const sdk: ClientFactorySdk = {
    FlopClient: {
      createWithKeypair(rpcUrl, keypair) {
        calls.push({
          method: "createWithKeypair",
          rpcUrl,
          address: keypair.address,
          type: keypair.type,
        });
        return { route: "keypair", address: keypair.address, type: keypair.type };
      },
      create(opts) {
        const call: { method: "create"; endpoint: string; signer?: string } = {
          method: "create",
          endpoint: opts.endpoint,
        };
        if (opts.signer !== undefined) call.signer = opts.signer;
        calls.push(call);
        return { route: "uri", signer: opts.signer };
      },
    },
  };
  return { sdk, calls };
}

test("parse: ed25519 prefix strips only the scheme and keeps the URI", () => {
  const parsed = parseTypedSecretUri(`ed25519:${TEST_URI}`);
  assert.deepEqual(parsed, { type: "ed25519", uri: TEST_URI, explicit: true });
});

test("parse: sr25519 prefix strips only the scheme and keeps the URI", () => {
  const parsed = parseTypedSecretUri(`sr25519:${TEST_URI}`);
  assert.deepEqual(parsed, { type: "sr25519", uri: TEST_URI, explicit: true });
});

test("parse: no prefix defaults to sr25519 and leaves the URI intact", () => {
  const parsed = parseTypedSecretUri(TEST_URI);
  assert.deepEqual(parsed, { type: "sr25519", uri: TEST_URI, explicit: false });
});

test("parse: empty typed URI is rejected without echoing a secret", () => {
  for (const input of ["ed25519:", "sr25519:"]) {
    assert.throws(() => parseTypedSecretUri(input), (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err.message, EMPTY_TYPED_SIGNER_URI);
      assert.equal(err.message.includes("ed25519"), false);
      assert.equal(err.message.includes("sr25519"), false);
      assert.equal(err.message.includes(TEST_URI), false);
      return true;
    });
  }
});

test("load: explicit ed25519 derives the expected test public key", async () => {
  const pair = await loadTypedUriPair(`ed25519:${TEST_URI}`);
  assert.equal(pair.type, "ed25519");
  await cryptoWaitReady();
  const expected = new Keyring({ type: "ed25519", ss58Format: 42 }).addFromUri(TEST_URI);
  assert.equal(pair.address, expected.address);
  assert.deepEqual(pair.publicKey, expected.publicKey);
});

test("load: explicit sr25519 derives the expected test public key", async () => {
  const pair = await loadTypedUriPair(`sr25519:${TEST_URI}`);
  assert.equal(pair.type, "sr25519");
  await cryptoWaitReady();
  const expected = new Keyring({ type: "sr25519", ss58Format: 42 }).addFromUri(TEST_URI);
  assert.equal(pair.address, expected.address);
  assert.deepEqual(pair.publicKey, expected.publicKey);
});

test("load: unprefixed URI matches explicit sr25519, not ed25519", async () => {
  const bare = await loadTypedUriPair(TEST_URI);
  const sr = await loadTypedUriPair(`sr25519:${TEST_URI}`);
  const ed = await loadTypedUriPair(`ed25519:${TEST_URI}`);
  assert.equal(bare.type, "sr25519");
  assert.equal(bare.address, sr.address);
  assert.notEqual(bare.address, ed.address);
  assert.notDeepEqual(bare.publicKey, ed.publicKey);
});

test("ed25519 address from a known test seed matches the did:key pubkey", async () => {
  const pair = await loadTypedUriPair(`ed25519:${TEST_URI}`);
  assert.equal(pair.publicKey.length, 32);
  const did = encodeDidKeyEd25519(pair.publicKey);
  const fromDid = decodeDidKeyEd25519(did);
  assert.deepEqual(fromDid, pair.publicKey);
  // AccountId32 / SS58 is that same 32-byte public key.
  assert.equal(encodeAddress(fromDid, 42), pair.address);
  assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
});

test("createClient: explicit prefixes take the keypair route", async () => {
  const { sdk, calls } = recordingSdk();
  const ed = await loadTypedUriPair(`ed25519:${TEST_URI}`);
  const sr = await loadTypedUriPair(`sr25519:${TEST_URI}`);
  await createClient("ws://127.0.0.1:9944", `ed25519:${TEST_URI}`, sdk);
  await createClient("ws://127.0.0.1:9944", `sr25519:${TEST_URI}`, sdk);
  assert.deepEqual(calls, [
    { method: "createWithKeypair", rpcUrl: "ws://127.0.0.1:9944", address: ed.address, type: "ed25519" },
    { method: "createWithKeypair", rpcUrl: "ws://127.0.0.1:9944", address: sr.address, type: "sr25519" },
  ]);
});

test("createClient: unprefixed and no-signer routing are unchanged", async () => {
  const { sdk, calls } = recordingSdk();
  await createClient("ws://127.0.0.1:9944", TEST_URI, sdk);
  await createClient("ws://127.0.0.1:9944", undefined, sdk);
  assert.deepEqual(calls, [
    { method: "create", endpoint: "ws://127.0.0.1:9944", signer: TEST_URI },
    { method: "create", endpoint: "ws://127.0.0.1:9944" },
  ]);
});

test("createClient and agentSignerConfig reject an empty typed URI", async () => {
  const { sdk } = recordingSdk();
  await assert.rejects(
    () => createClient("ws://127.0.0.1:9944", "ed25519:", sdk),
    (err: unknown) => err instanceof Error && err.message === EMPTY_TYPED_SIGNER_URI,
  );
  await assert.rejects(
    () => agentSignerConfig("sr25519:"),
    (err: unknown) => err instanceof Error && err.message === EMPTY_TYPED_SIGNER_URI,
  );
});

test("agentSignerConfig: explicit prefix returns keypair; unprefixed returns signerUri", async () => {
  const typed = await agentSignerConfig(`ed25519:${TEST_URI}`);
  assert.ok("keypair" in typed);
  assert.equal(typed.keypair.type, "ed25519");
  const legacy = await agentSignerConfig(TEST_URI);
  assert.deepEqual(legacy, { signerUri: TEST_URI });
});

test("sr25519KeyHex: explicit and legacy sr25519 produce identical DA key bytes", async () => {
  const fromPrefix = await sr25519KeyHex(`sr25519:${TEST_URI}`, true);
  const fromLegacy = await sr25519KeyHex(TEST_URI, true);
  assert.equal(typeof fromPrefix, "string");
  assert.equal(fromPrefix, fromLegacy);
  assert.match(fromPrefix!, /^0x[0-9a-f]+$/);
});

test("sr25519KeyHex: ed25519 is rejected when required and undefined when optional", async () => {
  await assert.rejects(
    () => sr25519KeyHex(`ed25519:${TEST_URI}`, true),
    (err: unknown) =>
      err instanceof Error &&
      err.message === "DA shard uploads are signed with sr25519; this signer is ed25519",
  );
  const optional = await sr25519KeyHex(`ed25519:${TEST_URI}`, false);
  assert.equal(optional, undefined);
});

test("encrypted ed25519 and sr25519 test keystores retain their identity and type", async () => {
  await cryptoWaitReady();
  const dir = await mkdtemp(join(tmpdir(), "signet-keystore-"));
  const envName = "SIGNET_TEST_KEYSTORE_PASSWORD";
  const previous = process.env[envName];
  process.env[envName] = "test-password-not-a-secret";
  try {
    for (const type of ["ed25519", "sr25519"] as const) {
      const expected = new Keyring({ type, ss58Format: 42 }).addFromUri(TEST_URI);
      const path = join(dir, `${type}.json`);
      await writeFile(path, JSON.stringify(expected.toJson(process.env[envName]!)), {
        mode: 0o600,
      });
      const loaded = await loadKeystore(path, envName);
      assert.equal(loaded.type, type);
      assert.equal(loaded.address, expected.address);
      assert.deepEqual(loaded.publicKey, expected.publicKey);

      const handle = `keystore:${encodeURIComponent(path)}:${encodeURIComponent(envName)}`;
      const { sdk, calls } = recordingSdk();
      await createClient("ws://127.0.0.1:9944", handle, sdk);
      assert.equal(calls[0]?.method, "createWithKeypair");
      assert.equal(calls[0] && "address" in calls[0] ? calls[0].address : "", expected.address);
      assert.equal(calls[0] && "type" in calls[0] ? calls[0].type : "", type);

      const cfg = await agentSignerConfig(handle);
      assert.ok("keypair" in cfg);
      assert.equal(cfg.keypair.address, expected.address);
      assert.equal(cfg.keypair.type, type);
    }
  } finally {
    if (previous === undefined) delete process.env[envName];
    else process.env[envName] = previous;
    await rm(dir, { recursive: true, force: true });
  }
});

test("loader and helpers never log the secret URI", async () => {
  const chunks: string[] = [];
  const capture = (...args: unknown[]) => {
    chunks.push(args.map((a) => String(a)).join(" "));
  };
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const original = Object.fromEntries(
    methods.map((m) => [m, console[m].bind(console)]),
  ) as Record<(typeof methods)[number], typeof console.log>;
  for (const m of methods) console[m] = capture as typeof console.log;
  const { sdk } = recordingSdk();
  try {
    parseTypedSecretUri(`ed25519:${TEST_URI}`);
    await loadTypedUriPair(`ed25519:${TEST_URI}`);
    await loadTypedUriPair(`sr25519:${TEST_URI}`);
    await loadTypedUriPair(TEST_URI);
    await createClient("ws://127.0.0.1:9944", `ed25519:${TEST_URI}`, sdk);
    await agentSignerConfig(`sr25519:${TEST_URI}`);
    await sr25519KeyHex(TEST_URI, true);
    await assert.rejects(() => loadTypedUriPair("ed25519:"));
  } finally {
    for (const m of methods) console[m] = original[m];
  }
  const blob = chunks.join("\n");
  assert.equal(blob.includes(TEST_URI), false, "secret URI leaked to the console");
  assert.equal(blob.includes(`ed25519:${TEST_URI}`), false);
  assert.equal(blob.includes(`sr25519:${TEST_URI}`), false);
});
