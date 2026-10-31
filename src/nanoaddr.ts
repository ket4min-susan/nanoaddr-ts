/**
 * Nano (XNO) account address codec and checksum validation in TypeScript.
 *
 * Zero runtime dependencies: pure TypeScript (RFC 7693 BLAKE2b implemented inline).
 * Direct port of `vendor/nanoaddr.py` from `dhyabi2/paid-work-queue`.
 *
 * Address shape:  <prefix>_ <52 chars: 4 pad bits + 256-bit public key> <8 chars: 40-bit checksum>
 * Checksum:       blake2b(public_key, digest_size=5).digest() reversed, base32-encoded.
 * Alphabet:       Nano base32 - "13456789abcdefghijkmnopqrstuwxyz" (no 0, 2, l, v).
 */

export const ALPHABET = "13456789abcdefghijkmnopqrstuwxyz";
const _DECODE: Record<string, bigint> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  _DECODE[ALPHABET[i]] = BigInt(i);
}

export const PREFIXES = ["nano_", "xrb_"] as const;
export type Prefix = (typeof PREFIXES)[number];
export const ACCOUNT_BODY_LEN = 52;
export const CHECKSUM_LEN = 8;
export const PUBLIC_KEY_BYTES = 32;

export type InvalidReason =
  | "not_a_string"
  | "empty"
  | "bad_prefix"
  | "bad_length"
  | "bad_padding"
  | "bad_character"
  | "bad_checksum"
  | "bad_public_key_length";

export type ValidationVerdict =
  | {
      valid: true;
      address: string;
      normalised: string;
      public_key: string;
      prefix: Prefix;
    }
  | {
      valid: false;
      reason: InvalidReason;
      message: string;
    };

export class InvalidAddress extends Error {
  public readonly reason: string;
  public readonly message: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "InvalidAddress";
    this.reason = reason;
    this.message = message;
    Object.setPrototypeOf(this, InvalidAddress.prototype);
  }
}

// ---------------------------------------------------------------------------
// RFC 7693 BLAKE2b (64-bit word variant) - pure TypeScript, zero dependencies
// ---------------------------------------------------------------------------

const BLAKE2B_IV: readonly bigint[] = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];

const BLAKE2B_SIGMA: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const MASK_64 = 0xffffffffffffffffn;

function rotr64(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & MASK_64;
}

function gMix(
  v: bigint[],
  a: number,
  b: number,
  c: number,
  d: number,
  x: bigint,
  y: bigint
): void {
  v[a] = (v[a] + v[b] + x) & MASK_64;
  v[d] = rotr64(v[d] ^ v[a], 32n);
  v[c] = (v[c] + v[d]) & MASK_64;
  v[b] = rotr64(v[b] ^ v[c], 24n);
  v[a] = (v[a] + v[b] + y) & MASK_64;
  v[d] = rotr64(v[d] ^ v[a], 16n);
  v[c] = (v[c] + v[d]) & MASK_64;
  v[b] = rotr64(v[b] ^ v[c], 63n);
}

/**
 * Compute unkeyed BLAKE2b digest of `input` with output length `outlen` (1..64 bytes).
 */
export function blake2b(input: Uint8Array, outlen = 64): Uint8Array {
  if (outlen < 1 || outlen > 64) {
    throw new RangeError(`blake2b outlen must be between 1 and 64, got ${outlen}`);
  }

  const h: bigint[] = [...BLAKE2B_IV];
  h[0] ^= 0x01010000n ^ BigInt(outlen);

  const totalLen = input.length;
  const numBlocks = totalLen === 0 ? 1 : Math.ceil(totalLen / 128);

  for (let blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
    const offset = blockIdx * 128;
    const isLast = blockIdx === numBlocks - 1;
    const bytesInBlock = isLast ? totalLen - offset : 128;
    const t0 = BigInt(offset + bytesInBlock);

    const block = new Uint8Array(128);
    if (bytesInBlock > 0) {
      block.set(input.subarray(offset, offset + bytesInBlock));
    }

    const m: bigint[] = new Array<bigint>(16);
    for (let i = 0; i < 16; i++) {
      let word = 0n;
      const base = i * 8;
      for (let j = 0; j < 8; j++) {
        word |= BigInt(block[base + j]) << BigInt(j * 8);
      }
      m[i] = word;
    }

    const v: bigint[] = [
      h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
      BLAKE2B_IV[0],
      BLAKE2B_IV[1],
      BLAKE2B_IV[2],
      BLAKE2B_IV[3],
      BLAKE2B_IV[4] ^ t0,
      BLAKE2B_IV[5],
      isLast ? (BLAKE2B_IV[6] ^ MASK_64) : BLAKE2B_IV[6],
      BLAKE2B_IV[7],
    ];

    for (let round = 0; round < 12; round++) {
      const s = BLAKE2B_SIGMA[round];
      gMix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      gMix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      gMix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      gMix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      gMix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      gMix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      gMix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      gMix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (let i = 0; i < 8; i++) {
      h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK_64;
    }
  }

  const out = new Uint8Array(outlen);
  for (let i = 0; i < outlen; i++) {
    const word = h[Math.floor(i / 8)];
    const shift = BigInt((i % 8) * 8);
    out[i] = Number((word >> shift) & 0xffn);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Nano base32 and byte conversions
// ---------------------------------------------------------------------------

function _b32Encode(value: bigint, length: number): string {
  const out: string[] = [];
  for (let shift = (length - 1) * 5; shift >= 0; shift -= 5) {
    const idx = Number((value >> BigInt(shift)) & 0x1fn);
    out.push(ALPHABET[idx]);
  }
  return out.join("");
}

function _b32Decode(text: string): bigint {
  let value = 0n;
  for (const ch of text) {
    const digit = _DECODE[ch];
    if (digit === undefined) {
      throw new InvalidAddress(
        "bad_character",
        `character '${ch}' is not in the Nano base32 alphabet (0, 2, l and v are never valid)`
      );
    }
    value = (value << 5n) | digit;
  }
  return value;
}

function _bytesToBigIntBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function _bigIntToBytesBE(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let rem = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return out;
}

function _toHexUpper(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0").toUpperCase();
  }
  return hex;
}

function _coercePublicKeyBytes(publicKey: Uint8Array | string): Uint8Array {
  if (typeof publicKey === "string") {
    const trimmed = publicKey.trim();
    if (!/^[0-9a-fA-F]*$/.test(trimmed) || trimmed.length % 2 !== 0) {
      throw new InvalidAddress(
        "bad_public_key_length",
        `public key must be ${PUBLIC_KEY_BYTES} bytes`
      );
    }
    const bytes = new Uint8Array(trimmed.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  if (publicKey instanceof Uint8Array) {
    return publicKey;
  }
  throw new InvalidAddress(
    "bad_public_key_length",
    `public key must be ${PUBLIC_KEY_BYTES} bytes`
  );
}

// ---------------------------------------------------------------------------
// Public API (matching vendor/nanoaddr.py)
// ---------------------------------------------------------------------------

/**
 * The 8-character checksum Nano appends to a 32-byte public key.
 */
export function checksumFor(publicKey: Uint8Array | string): string {
  const keyBytes = _coercePublicKeyBytes(publicKey);
  if (keyBytes.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidAddress(
      "bad_public_key_length",
      `public key must be ${PUBLIC_KEY_BYTES} bytes, got ${keyBytes.length}`
    );
  }
  const digest = blake2b(keyBytes, 5);
  const reversed = new Uint8Array(5);
  for (let i = 0; i < 5; i++) {
    reversed[i] = digest[4 - i];
  }
  return _b32Encode(_bytesToBigIntBE(reversed), CHECKSUM_LEN);
}

export const checksum_for = checksumFor;

/**
 * Render a 32-byte public key (Uint8Array or 64-char hex string) as a checksummed account address.
 */
export function encode(publicKey: Uint8Array | string, prefix: string = "nano_"): string {
  if (!(PREFIXES as readonly string[]).includes(prefix)) {
    throw new InvalidAddress(
      "bad_prefix",
      `prefix must be one of ('nano_', 'xrb_')`
    );
  }
  const keyBytes = _coercePublicKeyBytes(publicKey);
  if (keyBytes.length !== PUBLIC_KEY_BYTES) {
    throw new InvalidAddress(
      "bad_public_key_length",
      `public key must be ${PUBLIC_KEY_BYTES} bytes, got ${keyBytes.length}`
    );
  }
  const body = _b32Encode(_bytesToBigIntBE(keyBytes), ACCOUNT_BODY_LEN);
  return prefix + body + checksumFor(keyBytes);
}

/**
 * Return the 32-byte public key behind an address, or throw InvalidAddress.
 *
 * Every failure mode carries a distinct `reason`, matching `vendor/nanoaddr.py`:
 *   - not_a_string
 *   - empty
 *   - bad_prefix
 *   - bad_length
 *   - bad_padding
 *   - bad_character
 *   - bad_checksum
 */
export function decode(address: unknown): Uint8Array {
  if (typeof address !== "string") {
    const typeName = address === null ? "null" : typeof address;
    throw new InvalidAddress(
      "not_a_string",
      `address must be a string, got ${typeName}`
    );
  }

  const candidate = address.trim();
  if (!candidate) {
    throw new InvalidAddress("empty", "address is empty");
  }

  let matchedPrefix: Prefix | null = null;
  let rest = "";
  for (const prefix of PREFIXES) {
    if (candidate.startsWith(prefix)) {
      matchedPrefix = prefix;
      rest = candidate.slice(prefix.length);
      break;
    }
  }
  if (matchedPrefix === null) {
    throw new InvalidAddress(
      "bad_prefix",
      "address must start with 'nano_' or the legacy 'xrb_'"
    );
  }

  const expected = ACCOUNT_BODY_LEN + CHECKSUM_LEN;
  if (rest.length !== expected) {
    throw new InvalidAddress(
      "bad_length",
      `expected ${expected} characters after the prefix, got ${rest.length}`
    );
  }

  const body = rest.slice(0, ACCOUNT_BODY_LEN);
  const suppliedChecksum = rest.slice(ACCOUNT_BODY_LEN);

  if (body[0] !== "1" && body[0] !== "3") {
    throw new InvalidAddress(
      "bad_padding",
      `first character after the prefix must be '1' or '3', got '${body[0]}'`
    );
  }

  const decodedValue = _b32Decode(body);
  const paddedBytes = _bigIntToBytesBE(decodedValue, 33);
  const publicKey = paddedBytes.slice(1);
  const computed = checksumFor(publicKey);
  if (computed !== suppliedChecksum) {
    throw new InvalidAddress(
      "bad_checksum",
      `checksum mismatch: address carries '${suppliedChecksum}', the key implies '${computed}'`
    );
  }
  return publicKey;
}

/**
 * Never throws. Returns a JSON-serialisable verdict object matching `vendor/nanoaddr.py`.
 */
export function validate(address: unknown): ValidationVerdict {
  let publicKey: Uint8Array;
  try {
    publicKey = decode(address);
  } catch (err) {
    if (err instanceof InvalidAddress) {
      return {
        valid: false,
        reason: err.reason as InvalidReason,
        message: err.message,
      };
    }
    throw err;
  }

  const candidate = (address as string).trim();
  const prefix: Prefix = candidate.startsWith("nano_") ? "nano_" : "xrb_";
  return {
    valid: true,
    address: candidate,
    normalised: encode(publicKey, "nano_"),
    public_key: _toHexUpper(publicKey),
    prefix,
  };
}

/**
 * Boolean shorthand for `validate(address).valid`.
 */
export function isValid(address: unknown): boolean {
  return validate(address).valid;
}

export const is_valid = isValid;
