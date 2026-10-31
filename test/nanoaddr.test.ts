import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ALPHABET,
  ACCOUNT_BODY_LEN,
  CHECKSUM_LEN,
  PUBLIC_KEY_BYTES,
  InvalidAddress,
  blake2b,
  checksumFor,
  encode,
  decode,
  validate,
  isValid,
} from "../src/nanoaddr.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = path.join(__dirname, "..", "vectors", "mint-v1.json");
const PKG_PATH = path.join(__dirname, "..", "package.json");

interface MintVectorValid {
  address: string;
  valid: true;
  public_key_halves: [string, string];
  derived_from: string;
  index: number;
}

interface MintVectorInvalid {
  address: string;
  valid: false;
  reason: string;
  given_checksum: string;
  expected_checksum: string;
  note: string;
}

interface MintVectors {
  v: number;
  valid: MintVectorValid[];
  invalid: MintVectorInvalid[];
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHexUpper(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join("");
}

test("1. package.json has zero runtime dependencies", () => {
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, "utf-8"));
  const deps = Object.keys(pkg.dependencies ?? {});
  assert.deepEqual(deps, [], "package.json must have no runtime dependencies");
});

test("2. all-zero 32-byte public key encodes to the canonical Nano burn address", () => {
  const zeroKey = new Uint8Array(PUBLIC_KEY_BYTES);
  const burn = encode(zeroKey);
  assert.equal(
    burn,
    "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
  );

  const verdict = validate(burn);
  assert.equal(verdict.valid, true);
  if (verdict.valid) {
    assert.equal(verdict.public_key, "0".repeat(64));
    assert.equal(verdict.normalised, burn);
    assert.equal(verdict.prefix, "nano_");
  }
});

test("3. reproduces all 10 valid and 2 invalid known-answer vectors from vectors/mint-v1.json", () => {
  const vectors: MintVectors = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf-8"));
  assert.equal(vectors.valid.length, 10);
  assert.equal(vectors.invalid.length, 2);

  for (const row of vectors.valid) {
    const pubKeyHex = row.public_key_halves.join("");
    const pubKeyBytes = hexToBytes(pubKeyHex);

    // Verify encode(publicKey) -> expected address
    const encoded = encode(pubKeyBytes);
    assert.equal(encoded, row.address, `encode mismatch at index ${row.index}`);

    // Verify encode with hex string also works
    assert.equal(encode(pubKeyHex), row.address);

    // Verify validate(address) -> valid verdict + matching public key
    const verdict = validate(row.address);
    assert.equal(verdict.valid, true, `expected valid for ${row.address}`);
    if (verdict.valid) {
      assert.equal(verdict.address, row.address);
      assert.equal(verdict.normalised, row.address);
      assert.equal(verdict.public_key, pubKeyHex);
      assert.equal(verdict.prefix, "nano_");
    }

    // Verify legacy xrb_ prefix normalises to nano_ and decodes to identical key
    const legacy = "xrb_" + row.address.slice("nano_".length);
    const legacyVerdict = validate(legacy);
    assert.equal(legacyVerdict.valid, true);
    if (legacyVerdict.valid) {
      assert.equal(legacyVerdict.address, legacy);
      assert.equal(legacyVerdict.normalised, row.address);
      assert.equal(legacyVerdict.public_key, pubKeyHex);
      assert.equal(legacyVerdict.prefix, "xrb_");
    }
  }

  for (const row of vectors.invalid) {
    const verdict = validate(row.address);
    assert.equal(verdict.valid, false, `expected invalid for ${row.address}`);
    if (!verdict.valid) {
      assert.equal(verdict.reason, row.reason);
      assert.match(verdict.message, new RegExp(row.given_checksum));
      assert.match(verdict.message, new RegExp(row.expected_checksum));
    }
  }
});

test("4. validate() returns exact reason codes matching vendor/nanoaddr.py", () => {
  // 4a. wrong prefix -> bad_prefix
  for (const input of [
    "btc_1111111111111111111111111111111111111111111111111111hifc8npp",
    "NANO_1111111111111111111111111111111111111111111111111111hifc8npp",
    "nano1111111111111111111111111111111111111111111111111111hifc8npp",
  ]) {
    const v = validate(input);
    assert.deepEqual(
      { valid: v.valid, reason: !v.valid ? v.reason : null },
      { valid: false, reason: "bad_prefix" }
    );
  }

  // 4b. wrong length -> bad_length
  for (const input of [
    "nano_1111111111111111111111111111111111111111111111111111hifc8np", // 59 chars after prefix
    "nano_1111111111111111111111111111111111111111111111111111hifc8nppp", // 61 chars after prefix
    "xrb_1111",
  ]) {
    const v = validate(input);
    assert.deepEqual(
      { valid: v.valid, reason: !v.valid ? v.reason : null },
      { valid: false, reason: "bad_length" }
    );
  }

  // 4c. bad first character after prefix (padding bits) -> bad_padding
  for (const firstChar of ["4", "5", "a", "z", "0"]) {
    const input =
      "nano_" +
      firstChar +
      "111111111111111111111111111111111111111111111111111hifc8npp";
    const v = validate(input);
    assert.deepEqual(
      { valid: v.valid, reason: !v.valid ? v.reason : null },
      { valid: false, reason: "bad_padding" }
    );
  }

  // 4d. character outside the Nano base32 alphabet (0, 2, l, v, uppercase, symbols) -> bad_character
  for (const forbidden of ["0", "2", "l", "v", "A", "-"]) {
    const input =
      "nano_1" +
      forbidden +
      "11111111111111111111111111111111111111111111111111hifc8npp";
    const v = validate(input);
    assert.deepEqual(
      { valid: v.valid, reason: !v.valid ? v.reason : null },
      { valid: false, reason: "bad_character" }
    );
  }

  // 4e. altered checksum -> bad_checksum
  const alteredChecksum =
    "nano_1111111111111111111111111111111111111111111111111111hifc8npq";
  const vChecksum = validate(alteredChecksum);
  assert.deepEqual(
    { valid: vChecksum.valid, reason: !vChecksum.valid ? vChecksum.reason : null },
    { valid: false, reason: "bad_checksum" }
  );

  // 4f. empty and non-string inputs -> empty / not_a_string
  assert.deepEqual(
    validate("   "),
    { valid: false, reason: "empty", message: "address is empty" }
  );
  const nonStr = validate(12345);
  assert.equal(nonStr.valid, false);
  if (!nonStr.valid) {
    assert.equal(nonStr.reason, "not_a_string");
  }
});

test("5. changing any single character of a valid address makes validate() return valid: false", () => {
  const vectors: MintVectors = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf-8"));
  const sampleAddresses = [
    "nano_1111111111111111111111111111111111111111111111111111hifc8npp",
    vectors.valid[0].address,
    vectors.valid[5].address,
  ];

  const replacementPool = ALPHABET + "02lv_x";

  for (const addr of sampleAddresses) {
    assert.equal(isValid(addr), true);
    for (let pos = 0; pos < addr.length; pos++) {
      for (const ch of replacementPool) {
        if (ch === addr[pos]) continue;
        const mutated = addr.slice(0, pos) + ch + addr.slice(pos + 1);
        const verdict = validate(mutated);
        assert.equal(
          verdict.valid,
          false,
          `Mutating position ${pos} ('${addr[pos]}' -> '${ch}') in ${addr} unexpectedly stayed valid`
        );
      }
    }
  }
});

test("6. encode() validates prefix and public key length", () => {
  const zeroKey = new Uint8Array(PUBLIC_KEY_BYTES);
  assert.throws(
    () => encode(zeroKey, "btc_"),
    (err: unknown) =>
      err instanceof InvalidAddress && err.reason === "bad_prefix"
  );
  assert.throws(
    () => encode(new Uint8Array(31)),
    (err: unknown) =>
      err instanceof InvalidAddress && err.reason === "bad_public_key_length"
  );
  assert.throws(
    () => checksumFor(new Uint8Array(33)),
    (err: unknown) =>
      err instanceof InvalidAddress && err.reason === "bad_public_key_length"
  );
});

test("7. decode() round-trips back to the exact 32-byte public key", () => {
  const vectors: MintVectors = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf-8"));
  for (const row of vectors.valid) {
    const decoded = decode(row.address);
    assert.equal(bytesToHexUpper(decoded), row.public_key_halves.join(""));
  }
});

test("8. BLAKE2b matches RFC 7693 empty-input test vector", () => {
  const digest64 = blake2b(new Uint8Array(0), 64);
  assert.equal(
    bytesToHexUpper(digest64).toLowerCase(),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
  );
});
