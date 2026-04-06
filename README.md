<p align="center">
  <img src="logo.png" alt="DrandVerifier logo" width="50%" />
</p>

# DrandVerifier

Stateless Solidity verifiers for two drand BLS12-381 networks:

- **Quicknet** (`DrandVerifierQuicknet`, scheme `bls-unchained-g1-rfc9380`)
- **Default network** (`DrandVerifierDefault`, scheme `pedersen-bls-chained`)

Built with Foundry. The project currently uses both vendored `bls-solidity` (`BLS2`) and an in-repo internal library (`LibBLS`).

---

## Why verify drand signatures onchain?

For many apps, the value is not just “getting randomness”, but getting randomness that is publicly retrievable and independently verifiable without a privileged oracle callback path.

With drand, beacon data is public (`round`, `signature`) and can be fetched from public endpoints, then submitted onchain by anyone. That means integrators are not forced into a provider-managed callback flow with subscription/premium mechanics, and users can still supply proof data directly (including via a block explorer) if a frontend is unavailable. In this model, you pay normal transaction gas for your own app flow and verification, not an additional oracle fulfillment callback into your contract.

Security-wise, this only gives the intended “external randomness” properties if integration is done correctly: commit to a specific future round before reveal, stop accepting user inputs that could be adapted after commitment, and enforce freshness/replay policy in the consuming contract.

---

## What this project includes

- `src/DrandVerifierQuicknet.sol`
  - Quicknet verifier.
  - Accepts **compressed** (48-byte) and **uncompressed** (96-byte) G1 signatures.
  - Exposes `decompressSignature(...)` helper (compressed G1 -> uncompressed G1).
  - Exposes `deriveDrandRequest(uint64 round)` helper, returning the quicknet API URL for that round so users/integrators can easily fetch beacon signature data.
- `src/DrandVerifierDefault.sol`
  - Default network verifier.
  - Verifies chained beacons with `sha256(previous_signature || uint64(round))`.
  - Accepts **compressed** (96-byte) and **uncompressed** (192-byte) G2 signatures.
  - Requires `previousSignature.length == 96` (compressed previous round signature bytes).
  - Uses `LibBLS` for default network signature verification.
  - Exposes `deriveDrandRequest(uint64 round)` helper, returning the default network API URL for that round so users/integrators can easily fetch beacon signature data.
- `src/LibBLS.sol`
  - Internal BLS12-381 helper library used by `DrandVerifierDefault`.
- `src/interfaces/IDrandVerifierQuicknet.sol`
  - Quicknet verifier interface.
- `src/interfaces/IDrandVerifierDefault.sol`
  - Default verifier interface.
- `test/DrandVerifierQuicknet.t.sol`
  - Quicknet unit/adversarial/fuzz/live-FFI coverage.
- `test/DrandVerifierDefault.t.sol`
  - Default network unit/adversarial/fuzz/live-FFI coverage.
- `test/LibBLS.t.sol`
  - Direct coverage for LibBLS decoding/math/hash-to-curve/pairing wiring paths.

---

## Why there are two verifier contracts

Quicknet and Default use different BLS verification shapes, so they are implemented separately.

### Quicknet (`bls-unchained-g1-rfc9380`)

- Message digest input: `uint64(round)`
- Message digest: `sha256(uint64(round))`
- Signature group: **G1**
- Public key group: **G2**
- Contract flow: `BLS2.hashToPoint(...)` on G1 + `BLS2.verifySingle(...)`

### Default (`pedersen-bls-chained`)

- Message digest input: `previous_signature || uint64(round)`
- Message digest: `sha256(previous_signature || uint64(round))`
- Signature group: **G2**
- Public key group: **G1**
- Contract flow: `LibBLS.verifyDefaultSignature(...)`

### Which one should you use?

From an onchain randomness perspective, **both networks are functionally usable**: both provide publicly verifiable drand beacons you can verify onchain.

- Use **Quicknet** for most new integrations when you want faster cadence (3s rounds), simpler verification inputs (`round + signature`), and compatibility with drand timelock-encryption workflows.
- Use **Default** when you specifically need the chained scheme (`previous_signature` linked into the message) or compatibility with existing infrastructure/data flows already built around the default network.

### What “timelock-compatible” means here

Timelock encryption is a separate drand feature where data is encrypted now and can only be decrypted once a future round’s beacon becomes available. Quicknet is compatible with that model; Default is not. If your application plans to combine randomness with “reveal-at-future-time” encryption flows, choose Quicknet.

---

## LibBLS: what it is, why it exists, and how it is used

`LibBLS` is the internal library that powers `DrandVerifierDefault`. It exists because the default network uses a G2-signature / G1-public-key path with chained message construction, which is not the same turnkey path used by Quicknet.

In this repository, `LibBLS` provides the default network-specific cryptographic flow: compressed G2 decoding, canonical checks, G2 subgroup validation, hash-to-G2 mapping for the chained digest, and pairing-precompile wiring for final verification. `DrandVerifierDefault.verify(...)` computes the chained digest, then calls `LibBLS.verifyDefaultSignature(...)`; `decompressSignature(...)` calls `LibBLS.decompressG2Signature(...)`.

`LibBLS` does **not** currently replace Quicknet’s `BLS2` G1-verification flow. `DrandVerifierQuicknet` still uses `BLS2` directly.

---

## Technical differences at a glance

| Property | Quicknet | Default |
|---|---|---|
| Contract | `DrandVerifierQuicknet` | `DrandVerifierDefault` |
| drand scheme | `bls-unchained-g1-rfc9380` | `pedersen-bls-chained` |
| Hash input | `round` | `previous_signature + round` |
| Signature bytes accepted | 48 (compressed G1) / 96 (uncompressed G1) | 96 (compressed G2) / 192 (uncompressed G2) |
| Signature group | G1 | G2 |
| Public key group | G2 | G1 |
| Verification backend in this repo | `bls-solidity` (`BLS2`) | `LibBLS` |

---

## Practical integration notes

### Integrating Quicknet

1. Fetch round and signature from the Quicknet API.
2. Call `verify(round, sig)` with either compressed (48-byte) or uncompressed (96-byte) signature.
3. Use `decompressSignature(...)` offchain only if you explicitly need uncompressed bytes.

### Integrating Default network

1. Fetch `round`, `signature`, and `previous_signature` from the Default chain API.
2. Pass `previous_signature` exactly as 96-byte compressed bytes.
3. Call `verify(round, previousSignature, sig)` with either compressed (96-byte) or uncompressed (192-byte) signature.
4. `decompressSignature(...)` can be used offchain when you need uncompressed form.

If `previous_signature` is omitted, malformed, or from the wrong round, verification fails by design.

---

## APIs

### `DrandVerifierQuicknet`

- `roundMessageHash(uint64 round) -> bytes32`
- `verify(uint64 round, bytes sig) -> bool`
- `safeVerify(uint64 round, bytes sig) -> bool`
- `decompressSignature(bytes compressedSig) -> bytes`
- constants/metadata: `DST`, `COMPRESSED_G1_SIG_LENGTH`, `UNCOMPRESSED_G1_SIG_LENGTH`, `PUBLIC_KEY`

### `DrandVerifierDefault`

- `roundMessageHash(uint64 round, bytes previousSignature) -> bytes32`
- `verify(uint64 round, bytes previousSignature, bytes signature) -> bool`
- `safeVerify(uint64 round, bytes previousSignature, bytes signature) -> bool`
- `decompressSignature(bytes compressedSig) -> bytes`
- constants/metadata: `DST`, `COMPRESSED_G2_SIG_LENGTH`, `UNCOMPRESSED_G2_SIG_LENGTH`, `PUBLIC_KEY`

---

## Test strategy

- Known good values
- Wrong round / wrong previous signature / wrong signature negatives
- Adversarial malformed/non-canonical input coverage
- Fuzzing for bit flips and random payloads
- Live FFI tests against drand APIs
- Dedicated LibBLS coverage via harness tests

---

## FFI note

`foundry.toml` enables `ffi = true` for live tests (`curl` + local conversion helpers). In CI/security-sensitive environments, disable or gate FFI appropriately.

---

## Operational caveats

- Both contracts are stateless verifiers only (no freshness tracking or replay prevention).
- Both rely on target-chain support for required BLS12-381 precompiles.
- Quicknet and Default use different precompile paths; chain compatibility must be validated for your deployment target.
- For state-changing use, caller contracts should define freshness/replay policy explicitly.

---

## Why this works technically (and what assumptions you are taking)

### Why BLS threshold signatures make this verifiable onchain

drand nodes collectively produce threshold BLS signatures for each round. Anyone who has the network root-of-trust parameters (public key, period, genesis, scheme) can verify a beacon signature. Onchain, this contract family checks the same signature validity that offchain clients check.

This gives public verifiability without trusting a single node or a private API response. The critical assumption is threshold honesty: drand’s security model states malicious control must stay below threshold for unpredictability; if an attacker controls at least threshold shares, they can derive future chain beacons, while randomness remains unbiasable.

### Quicknet vs Default: security and integration shape

- **Quicknet (`bls-unchained-g1-rfc9380`)**: unchained mode, signatures on G1, 3s period, timelock-compatible network mode, and per-round verification without needing previous signature bytes.
- **Default (`pedersen-bls-chained`)**: chained mode, signatures on G2, 30s period, not timelock-compatible, and verification depends on `previous_signature` linkage.

Both can serve as onchain randomness sources; the practical choice is mostly integration shape and cadence: Quicknet is usually simpler/faster for new apps, while Default is chosen for chained-scheme compatibility requirements.

In this repo that means:
- `DrandVerifierQuicknet` verifies a round with `(round, signature)`.
- `DrandVerifierDefault` verifies with `(round, previousSignature, signature)` and enforces `previousSignature.length == 96`.

### drand vs Chainlink VRF vs `block.prevrandao` (practical model differences)

| Dimension | drand (this repo’s model) | Chainlink VRF | `block.prevrandao` |
|---|---|---|---|
| Delivery pattern | Public beacon + user/relayer submits proof | Oracle callback fulfillment | Native block field |
| Cost shape | Gas for your call + verification; no VRF premium/subscription flow | Gas + VRF premium + callback path; subscription/funding management | Minimal read cost |
| Influence surface | External threshold network; unpredictability requires < threshold corruption | Validator reorg/re-roll considerations + callback ordering/funding concerns | Proposer has bounded influence per slot (EIP-4399) |
| Commitment style | Clean when app commits to specific future round before reveal | Request/fulfill lifecycle; asynchronous callback semantics | Must use lookahead/cutoff discipline to reduce predictability/bias risk |

### Integration caveats that matter in production

- If your app uses drand, commit to the target round before reveal and stop accepting user inputs that could be adapted after commitment.
- Treat validator influence as mostly a **timing/censorship** issue on submission, not direct control of drand beacon value itself.
- Enforce freshness/replay policy in your stateful consumer contract (these verifier contracts are intentionally stateless).
- Handle round progression explicitly: drand can stall and later recover, and applications should define behavior for delayed/missed target rounds.
- Verify chain compatibility up front: this repo’s verifiers use BLS12-381 precompile paths, while drand `evmnet` exists specifically for BN254 EVM-precompile compatibility. These verifiers do not implement drand's `evmnet` scheme.

---

## Dependencies

- `lib/bls-solidity` (still used directly by Quicknet verifier and BLS2 types)
- `lib/forge-std`
- `lib/solady` (JSON parsing in FFI live tests)

---

## References

- [drand: Why decentralized randomness is important](https://drand.love/about/#why-decentralized-randomness-is-important)
- [drand developer docs](https://docs.drand.love/developer/)
- [drand security model](https://docs.drand.love/docs/security-model/)
- [drand protocol specification](https://docs.drand.love/docs/specification/)
- [drand timelock encryption](https://docs.drand.love/docs/timelock-encryption/)
- [Chainlink VRF security considerations](https://docs.chain.link/vrf/v2-5/security)
- [Chainlink VRF billing](https://docs.chain.link/vrf/v2-5/billing)
- [EIP-4399 (`PREVRANDAO`)](https://eips.ethereum.org/EIPS/eip-4399)
- [randa-mu/bls-solidity](https://github.com/randa-mu/bls-solidity)

## License

VPL
