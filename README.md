# evm-drand-verifier

Stateless Solidity verifier for **drand quicknet** BLS12-381 round signatures, built with Foundry using the vendored [`randa-mu/bls-solidity`](https://github.com/randa-mu/bls-solidity) library.

This project gives you a minimal onchain primitive to answer one question:

> “Is this drand quicknet signature valid for this round?”

---

## What this project includes

- `src/DrandVerifier.sol`
  - Verifies quicknet signatures for a round.
  - Accepts both **compressed** (48-byte) and **uncompressed** (96-byte) G1 signatures.
  - Exposes `decompressSignature(...)` so callers can decompress offchain via `eth_call` and submit the cheaper uncompressed path onchain.
- `src/IDrandVerifier.sol`
  - Interface for integrating with `DrandVerifier` from other contracts.
- `test/DrandVerifier.t.sol`
  - Unit + adversarial + fuzz tests.
  - Live FFI tests that fetch latest quicknet rounds from drand API and verify in-contract.

---

## drand quicknet assumptions in this implementation

This verifier is intentionally pinned to quicknet semantics:

- **DST**: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`
- **Round message hash**: `sha256(abi.encodePacked(uint64(round)))`
- **Public key**: hardcoded quicknet G2 key (same as `bls-solidity` quicknet demo)
- **Live test chain hash**: `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`

If you need a different drand network/key/DST, you should deploy a different verifier configuration.

---

## Contract API

### Constants / metadata

- `DST() -> string`
- `COMPRESSED_SIG_LENGTH() -> uint256` (48)
- `UNCOMPRESSED_SIG_LENGTH() -> uint256` (96)
- `PUBLIC_KEY() -> BLS2.PointG2`

### Core functions

- `roundMessageHash(uint64 round) -> bytes32`
  - Computes the quicknet round digest used by this verifier.

- `verify(uint64 round, bytes sig) -> bool`
  - Returns `true` if `sig` is a valid quicknet signature for `round`.
  - `sig` may be 48-byte compressed or 96-byte uncompressed.
  - Returns `false` on invalid length/signature.
  - May revert for malformed compressed encodings (library-level validation behavior).

- `decompressSignature(bytes compressedSig) -> bytes`
  - Converts a 48-byte compressed G1 signature to 96-byte uncompressed form.
  - Intended for offchain `eth_call` usage.
  - Reverts on invalid compressed input.

---

## Why uncompressed signatures can be cheaper to verify

Compressed signatures require decompression before pairing checks. In this setup, the decompression path can be more expensive than submitting uncompressed signatures directly.

Typical integration pattern:

1. Fetch signature from drand API (compressed hex string).
2. Offchain-call `decompressSignature(...)` once.
3. Submit uncompressed bytes to `verify(...)`.

---

## Test strategy in this repo

`test/DrandVerifier.t.sol` includes:

- Known quicknet vectors (compressed + uncompressed)
- Wrong-round and wrong-signature negatives
- Invalid-length and malformed compressed-encoding tests
- Non-canonical field element rejection tests
- Fuzz tests for bit flips and random payloads
- Live FFI tests against latest quicknet round via drand API

---

## FFI note

`foundry.toml` currently has `ffi = true` so live API tests can execute `curl` in Foundry tests.

Use care in CI/security-sensitive environments where arbitrary FFI execution is undesirable.

---

## Operational caveats

- This verifier depends on BLS12-381 precompile behavior used by `bls-solidity`.
- Your deployment target must be compatible with this verification approach.
- Contract is stateless by design: it verifies signatures only; it does not track rounds or freshness.
- If you use this in state-changing flows, design your caller for invalid-input gas behavior and replay/freshness policy.

---

## Dependencies

- `lib/bls-solidity` (vendored, unmodified in this project)
- `lib/forge-std`
- `lib/solady` (used for JSON parsing in live tests)

---

## License

VPL
