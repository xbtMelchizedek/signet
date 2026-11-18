/**
 * Path A: an Ed25519 did:key public key is the FLOP AccountId32
 * (32 raw bytes). This encoder is for tests and docs, not a general DID
 * library.
 */

const BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const size = Math.ceil((bytes.length * 138) / 100) + 1;
  const b = new Uint8Array(size);
  let length = 0;
  for (const byte of bytes) {
    let carry = byte;
    let i = 0;
    for (let j = size - 1; j >= 0; j--) {
      if (carry === 0 && i >= length) break;
      carry += 256 * b[j]!;
      b[j] = carry % 58;
      carry = Math.floor(carry / 58);
      i++;
    }
    length = i;
  }
  let it = size - length;
  while (it < size && b[it] === 0) it++;
  let out = "1".repeat(zeros);
  for (; it < size; it++) out += BASE58BTC[b[it]!]!;
  return out;
}

function decodeBase58btc(text: string): Uint8Array {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;
  const size = Math.ceil((text.length * 733) / 1000) + 1;
  const b = new Uint8Array(size);
  let length = 0;
  for (const ch of text) {
    const val = BASE58BTC.indexOf(ch);
    if (val < 0) throw new Error("invalid base58btc character");
    let carry = val;
    let i = 0;
    for (let j = size - 1; j >= 0; j--) {
      if (carry === 0 && i >= length) break;
      carry += 58 * b[j]!;
      b[j] = carry % 256;
      carry = Math.floor(carry / 256);
      i++;
    }
    length = i;
  }
  let it = size - length;
  while (it < size && b[it] === 0) it++;
  const out = new Uint8Array(zeros + (size - it));
  out.set(b.subarray(it), zeros);
  return out;
}

/** Encode a 32-byte Ed25519 public key as did:key:z... */
export function encodeDidKeyEd25519(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error("ed25519 public key must be 32 bytes");
  }
  const bytes = new Uint8Array(34);
  bytes[0] = 0xed;
  bytes[1] = 0x01;
  bytes.set(publicKey, 2);
  return `did:key:z${encodeBase58btc(bytes)}`;
}

/** Extract the 32-byte Ed25519 public key from a did:key:z... string. */
export function decodeDidKeyEd25519(did: string): Uint8Array {
  const prefix = "did:key:z";
  if (!did.startsWith(prefix)) {
    throw new Error("did:key must use the z base58btc multibase prefix");
  }
  const bytes = decodeBase58btc(did.slice(prefix.length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("did:key is not an ed25519-pub key");
  }
  return bytes.subarray(2);
}
