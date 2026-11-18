#!/usr/bin/env node
/**
 * Download published @flop-labs/cli@0.5.0, verify pinned hashes, apply the
 * typed-signer patch, and syntax-check the result. Never runs the CLI against
 * a network and never signs.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = "0.5.0";
const TARBALL_URL = `https://registry.npmjs.org/@flop-labs/cli/-/cli-${VERSION}.tgz`;
const TARBALL_INTEGRITY =
  "sha512-zFLbjNdWHgc6IGO0kqwtU57dNsX29XYDWaxhbe0DtRw4QPekRpvz0yb2m/1q6dtzfTFyGz+1RBK4ll4iDnpW3w==";
const CLI_JS_SHA256 =
  "c94d7d6bdfee094c401aa5accd04faf19e6d48fd925ffd934f962c2ceca1de40";

const LOADER = `function parseTypedSecretUri(signer) {
  const match = /^(ed25519|sr25519):(.*)$/s.exec(signer);
  const type = match?.[1] ?? "sr25519";
  const uri = match ? match[2] : signer;
  if (!uri) throw new Error("typed signer URI must not be empty");
  return { type, uri, explicit: !!match };
}
async function loadTypedUriPair(signer) {
  const { type, uri } = parseTypedSecretUri(signer);
  const [{ Keyring: Keyring6 }, { cryptoWaitReady: cryptoWaitReady5 }] = await Promise.all([
    import("@polkadot/keyring"),
    import("@polkadot/util-crypto")
  ]);
  await cryptoWaitReady5();
  return new Keyring6({ type, ss58Format: 42 }).addFromUri(uri);
}
`;

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function sha512Integrity(buf) {
  return "sha512-" + createHash("sha512").update(buf).digest("base64");
}

function replaceOnce(haystack, needle, replacement, label) {
  const count = haystack.split(needle).length - 1;
  if (count !== 1) {
    throw new Error(`${label}: expected 1 occurrence, found ${count}`);
  }
  return haystack.replace(needle, replacement);
}

export function applyTypedSigner(cliJs, readme, changelog) {
  let next = cliJs;
  next = replaceOnce(
    next,
    `async function sr25519KeyHex(signer, required = true) {`,
    `${LOADER}async function sr25519KeyHex(signer, required = true) {`,
    "insert loader before sr25519KeyHex",
  );
  next = replaceOnce(
    next,
    `const pair = signer.startsWith("keystore:") ? await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv)) : new Keyring6({ type: "sr25519" }).addFromUri(signer);`,
    `const pair = signer.startsWith("keystore:") ? await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv)) : await loadTypedUriPair(signer);`,
    "sr25519KeyHex pair loader",
  );
  next = replaceOnce(
    next,
    `async function agentSignerConfig(signer) {
  const [, encodedPath, encodedEnv] = signer.split(":");
  return signer.startsWith("keystore:") ? { keypair: await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv)) } : { signerUri: signer };
}`,
    `async function agentSignerConfig(signer) {
  if (signer.startsWith("keystore:")) {
    const [, encodedPath, encodedEnv] = signer.split(":");
    return { keypair: await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv)) };
  }
  if (parseTypedSecretUri(signer).explicit) {
    return { keypair: await loadTypedUriPair(signer) };
  }
  return { signerUri: signer };
}`,
    "agentSignerConfig",
  );
  next = replaceOnce(
    next,
    `    return FlopClient7.createWithKeypair(
      rpcUrl,
      await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv))
    );
  }
  const opts = { endpoint: rpcUrl };`,
    `    return FlopClient7.createWithKeypair(
      rpcUrl,
      await loadKeystore(decodeURIComponent(encodedPath), decodeURIComponent(encodedEnv))
    );
  }
  if (signer && parseTypedSecretUri(signer).explicit) {
    return FlopClient7.createWithKeypair(rpcUrl, await loadTypedUriPair(signer));
  }
  const opts = { endpoint: rpcUrl };`,
    "createClient typed URI route",
  );
  next = replaceOnce(
    next,
    `.option("--signer <uri>", "Signer URI (local/dev only; required outside local unless --keystore)")`,
    `.option("--signer <uri>", "Signer secret URI (local/dev only; required outside local unless --keystore). Prefix ed25519:<secret-URI> or sr25519:<secret-URI>; unprefixed URIs stay sr25519")`,
    "CLI --signer help text",
  );

  let nextReadme = replaceOnce(
    readme,
    `| \`--signer <uri>\` | Local signer URI | \`//Alice\` on local only |`,
    `| \`--signer <uri>\` | Secret URI; prefix \`ed25519:<secret-URI>\` or \`sr25519:<secret-URI>\`. Unprefixed URIs stay sr25519. | \`//Alice\` on local only |`,
    "README --signer table",
  );
  const note = `A Technocore or tclk agent that holds an Ed25519 \`did:key\` should pass
\`--signer ed25519:<secret-URI>\` so the FLOP AccountId32 is that same public
key. A plain \`--signer <secret-URI>\` still derives sr25519, which is a
different account. Encrypted keystores (\`--keystore\`) already keep the type
they were imported or generated with.

`;
  nextReadme = replaceOnce(
    nextReadme,
    `| \`--json\` | Output as JSON | false |

### Commands
`,
    `| \`--json\` | Output as JSON | false |

${note}### Commands
`,
    "README did:key note",
  );

  let nextLog = changelog;
  const unreleased = `## [Unreleased]

### Added

- \`--signer\` accepts an explicit \`ed25519:<secret-URI>\` or
  \`sr25519:<secret-URI>\` prefix so a did:key agent can use its own ed25519
  account. Unprefixed secret URIs stay sr25519. Encrypted keystores are
  unchanged.

`;
  nextLog = replaceOnce(
    nextLog,
    `## [Unreleased]

`,
    unreleased,
    "CHANGELOG unreleased",
  );

  return { cliJs: next, readme: nextReadme, changelog: nextLog };
}

async function downloadVerified(cacheDir) {
  const tarballPath = join(cacheDir, `cli-${VERSION}.tgz`);
  const res = await fetch(TARBALL_URL);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const integrity = sha512Integrity(buf);
  if (integrity !== TARBALL_INTEGRITY) {
    throw new Error(`tarball integrity mismatch: ${integrity}`);
  }
  await writeFile(tarballPath, buf);
  return tarballPath;
}

function extract(tarballPath, dest) {
  const r = spawnSync("tar", ["-xzf", tarballPath, "-C", dest], { stdio: "inherit" });
  if (r.status !== 0) throw new Error("tar extract failed");
}

async function main() {
  const cacheDir = join(ROOT, ".cache", "cli-0.5.0");
  const work = join(cacheDir, "work");
  await rm(work, { recursive: true, force: true });
  await mkdir(work, { recursive: true });
  const tarballPath = await downloadVerified(cacheDir);
  extract(tarballPath, work);
  const pkg = join(work, "package");
  const cliPath = join(pkg, "dist/cli.js");
  const cliBuf = await readFile(cliPath);
  const digest = sha256(cliBuf);
  if (digest !== CLI_JS_SHA256) {
    throw new Error(`dist/cli.js SHA-256 mismatch: ${digest}`);
  }
  const originalCli = cliBuf.toString("utf8");
  const originalReadme = await readFile(join(pkg, "README.md"), "utf8");
  const originalChangelog = await readFile(join(pkg, "CHANGELOG.md"), "utf8");
  const patched = applyTypedSigner(originalCli, originalReadme, originalChangelog);
  await writeFile(cliPath, patched.cliJs);
  await writeFile(join(pkg, "README.md"), patched.readme);
  await writeFile(join(pkg, "CHANGELOG.md"), patched.changelog);

  const check = spawnSync("node", ["--check", cliPath], { encoding: "utf8" });
  if (check.status !== 0) {
    throw new Error(`patched dist/cli.js failed node --check:\n${check.stderr}`);
  }
  if (!patched.cliJs.includes("function parseTypedSecretUri")) {
    throw new Error("loader missing from patched bundle");
  }
  if (patched.cliJs.includes('new Keyring6({ type: "sr25519" }).addFromUri(signer)')) {
    throw new Error("plain-URI Keyring fallback still present in sr25519KeyHex");
  }
  // Enrollment wallet and gateway probe signer stay sr25519-only.
  if (!patched.cliJs.includes('const pair = new Keyring6({ type: "sr25519" }).addFromUri(mnemonicGenerate3(24));')) {
    throw new Error("session --new-wallet path was changed; it must stay untouched");
  }
  if (!patched.cliJs.includes('const signer = new Keyring5({ type: "sr25519" }).addFromUri(signerUri);')) {
    throw new Error("gateway probe signer path was changed; it must stay untouched");
  }

  const patchDir = join(cacheDir, "diff");
  await rm(patchDir, { recursive: true, force: true });
  await mkdir(join(patchDir, "a"), { recursive: true });
  await mkdir(join(patchDir, "b"), { recursive: true });
  // Write originals and patched copies for diff
  const origDir = join(cacheDir, "original");
  await rm(origDir, { recursive: true, force: true });
  await mkdir(origDir, { recursive: true });
  // Re-extract original into origDir
  extract(tarballPath, origDir);

  const diff = spawnSync(
    "diff",
    [
      "-u",
      "--label",
      "a/package/dist/cli.js",
      "--label",
      "b/package/dist/cli.js",
      join(origDir, "package/dist/cli.js"),
      cliPath,
    ],
    { encoding: "utf8" },
  );
  const diffReadme = spawnSync(
    "diff",
    [
      "-u",
      "--label",
      "a/package/README.md",
      "--label",
      "b/package/README.md",
      join(origDir, "package/README.md"),
      join(pkg, "README.md"),
    ],
    { encoding: "utf8" },
  );
  const diffLog = spawnSync(
    "diff",
    [
      "-u",
      "--label",
      "a/package/CHANGELOG.md",
      "--label",
      "b/package/CHANGELOG.md",
      join(origDir, "package/CHANGELOG.md"),
      join(pkg, "CHANGELOG.md"),
    ],
    { encoding: "utf8" },
  );
  // diff returns 1 when files differ
  if (![0, 1].includes(diff.status) || ![0, 1].includes(diffReadme.status) || ![0, 1].includes(diffLog.status)) {
    throw new Error("diff failed");
  }
  const patchPath = join(ROOT, "patches/cli-0.5.0-typed-signer.patch");
  await writeFile(
    patchPath,
    [diff.stdout, diffReadme.stdout, diffLog.stdout].join(""),
  );
  console.log(`verified @flop-labs/cli@${VERSION} tarball and dist/cli.js hashes`);
  console.log(`patched bundle passed node --check`);
  console.log(`wrote ${patchPath}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
