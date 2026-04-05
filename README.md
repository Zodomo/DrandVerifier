# DrandVerifier

Stateless Solidity verifiers for **two drand BLS12-381 networks**:

- **Quicknet** (`DrandVerifierQuicknet`)
- **Default network** (`DrandVerifierDefault`, scheme `pedersen-bls-chained`)

Built with Foundry and the vendored [`randa-mu/bls-solidity`](https://github.com/randa-mu/bls-solidity) library.

---

## What this project includes

- `src/DrandVerifierQuicknet.sol`
  - Quicknet verifier.
  - Accepts **compressed** (48-byte) and **uncompressed** (96-byte) signatures.
  - Exposes `decompressSignature(...)` helper for offchain conversion.
- `src/DrandVerifierDefault.sol`
  - Default-network verifier.
  - Verifies chained beacons using `round + previous_signature`.
  - Accepts **uncompressed G2** signatures (192 bytes).
- `src/interfaces/IDrandVerifierQuicknet.sol`
  - Quicknet verifier interface.
- `src/interfaces/IDrandVerifierDefault.sol`
  - Default-network verifier interface.
- `test/DrandVerifierQuicknet.t.sol`
  - Quicknet unit/adversarial/fuzz/live-FFI coverage.
- `test/DrandVerifierDefault.t.sol`
  - Default-network unit/adversarial/fuzz/live-FFI coverage.

---

## Why there are two verifier contracts

drand quicknet and drand default do not use the same verification shape onchain.

### Quicknet (`bls-unchained-g1-rfc9380`)

- Message digest: `sha256(uint64(round))`
- Signature group: **G1**
- Public key group: **G2**
- Library fit: maps directly to `bls-solidity` G1-signature flow (`hashToPoint` on G1 + `verifySingle`)
- Input convenience: supports compressed/uncompressed signature formats

### Default (`pedersen-bls-chained`)

- Message digest: `sha256(previous_signature || uint64(round))`
- Chaining requirement: caller must provide previous round signature bytes
- Signature group: **G2**
- Public key group: **G1**
- Library fit: not the same turnkey path as quicknet, so verifier uses precompile-oriented G2 flow for this scheme

---

## Technical differences at a glance

| Property | Quicknet | Default |
|---|---|---|
| Contract | `DrandVerifierQuicknet` | `DrandVerifierDefault` |
| drand scheme | `bls-unchained-g1-rfc9380` | `pedersen-bls-chained` |
| Hash input | `round` | `previous_signature + round` |
| Signature bytes accepted | 48 (compressed) / 96 (uncompressed) | 192 (uncompressed G2) |
| Signature group | G1 | G2 |
| Public key group | G2 | G1 |
| Offchain preprocessing | Optional (decompress) | Usually required (decompress drand compressed G2 to uncompressed) |

---

## Practical integration differences

### Integrating quicknet

1. Fetch round and signature from quicknet API.
2. Optionally call `decompressSignature(...)` offchain if you received compressed form.
3. Call `verify(round, sig)`.

### Integrating default network

1. Fetch `round`, `signature`, and `previous_signature` from default-chain API.
2. Convert drand compressed G2 signature to 192-byte uncompressed form offchain.
3. Call `verify(round, previousSignature, uncompressedSignature)`.

If you omit or mismatch `previous_signature`, verification should fail by design.

---

## APIs

### `DrandVerifierQuicknet`

- `roundMessageHash(uint64 round) -> bytes32`
- `verify(uint64 round, bytes sig) -> bool`
- `decompressSignature(bytes compressedSig) -> bytes`
- metadata/constants: `DST`, `COMPRESSED_G1_SIG_LENGTH`, `UNCOMPRESSED_G1_SIG_LENGTH`, `PUBLIC_KEY`

### `DrandVerifierDefault`

- `roundMessageHash(uint64 round, bytes previousSignature) -> bytes32`
- `verify(uint64 round, bytes previousSignature, bytes signature) -> bool`
- metadata/constants: `DST`, `COMPRESSED_G2_SIG_LENGTH`, `UNCOMPRESSED_G2_SIG_LENGTH`, `PUBLIC_KEY`

---

## Test strategy

- Known vectors (positive)
- Wrong round / wrong previous signature / wrong signature negatives
- Adversarial malformed/non-canonical input coverage
- Fuzzing for bit flips and random payloads
- Live FFI tests against drand APIs

---

## FFI note

`foundry.toml` enables `ffi = true` for live tests (`curl` + local conversion helpers). In CI/security-sensitive environments, disable or gate FFI appropriately.

---

## Operational caveats

- Both contracts are stateless verifiers only (no freshness tracking or replay prevention).
- Both rely on target-chain compatibility with required BLS12-381 precompile behavior.
- For state-changing use, caller contracts should define freshness/replay policy explicitly.

---

## Dependencies

- `lib/bls-solidity`
- `lib/forge-std`
- `lib/solady` (JSON parsing in FFI live tests)

---

## References
- [drand](https://docs.drand.love/)

## License

VPL
