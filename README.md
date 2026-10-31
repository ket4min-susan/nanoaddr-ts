# nanoaddr-ts

Zero-dependency TypeScript port of [`vendor/nanoaddr.py`](https://github.com/dhyabi2/paid-work-queue/blob/main/vendor/nanoaddr.py) from [`dhyabi2/paid-work-queue`](https://github.com/dhyabi2/paid-work-queue) (delivered for [`job-2026-09-26-003`](https://github.com/dhyabi2/paid-work-queue/issues/29)).

## Features & Conformance

- **Zero Runtime Dependencies (`"dependencies": {}` in `package.json`)**: Implements RFC 7693 `blake2b` (`digest_size = 5`) and Nano's custom Base32 alphabet (`13456789abcdefghijkmnopqrstuwxyz`) directly in pure TypeScript without external packages or native addons.
- **Identical Public Surface to `vendor/nanoaddr.py`**:
  - `validate(address)` — Never throws; returns a JSON-serialisable verdict object:
    - Valid: `{"valid": true, "address": "<candidate>", "normalised": "nano_...", "public_key": "<64 uppercase hex>", "prefix": "nano_" | "xrb_"}`
    - Invalid: `{"valid": false, "reason": "<code>", "message": "<human readable>"}` with exact reason codes (`bad_prefix`, `bad_length`, `bad_padding`, `bad_character`, `bad_checksum`, `empty`, `not_a_string`).
  - `encode(publicKey, prefix = "nano_")` — Encodes a 32-byte `Uint8Array` (or 64-character hex string) into a checksummed `nano_` or `xrb_` address.
  - `decode(address)` — Returns the 32-byte `Uint8Array` public key or throws `InvalidAddress(reason, message)`.
  - `checksumFor(publicKey)` / `checksum_for(publicKey)` — Computes the 8-character reversed BLAKE2b-40 Base32 checksum.
  - `isValid(address)` / `is_valid(address)` — Boolean helper.
- **Known-Answer Vectors (`vectors/mint-v1.json`)**:
  - Encodes the all-zero 32-byte public key to the canonical burn address `nano_1111111111111111111111111111111111111111111111111111hifc8npp`.
  - Reproduces all 10 valid zero-seed derived addresses and 2 `eddie_researcher` invalid checksum vectors from `vectors/mint-v1.json`.
  - Verifies that mutating any single character at any position (`0..64`) of a valid address causes `validate()` to return `valid: false`.

## Run Tests (One Command from Clean Clone)

Requires Node.js `>=22.6.0` (uses built-in TypeScript support and `node:test`, no `npm install` needed):

```bash
npm test
```

Or directly via `node`:

```bash
node --experimental-strip-types --test test/nanoaddr.test.ts
```
