<p align="center">
  <img src="logo.png" alt="DrandVerifier logo" width="50%" />
</p>

# DrandVerifier

Stateless Solidity drand verification stack for two BLS12-381 networks:

- **Quicknet** (`DrandOracleQuicknet` standalone oracle, `DrandVerifierQuicknet` internal library, `DrandVerifierQuicknetLib` linked library)
- **Default network** (`DrandOracleDefault` deployable oracle, `DrandVerifierDefault` internal library)

The project currently uses both vendored `bls-solidity` (`BLS2`) and an in-repo internal library (`LibBLS`) for cryptographic operations.

**DISCLAIMER:** This code has not been professionally audited. It was developed, tested, and self-audited with AI. The `bls-solidity` library may have been audited, but include any of this within your audit scope if you're getting one.

---

## Why verify drand signatures onchain?

For many apps, the value is not just “getting a provably random value", but getting randomness that is publicly retrievable and independently verifiable without a privileged oracle callback path. This is randomness your users can copy and paste into your app.

With drand, beacon data is public (`round`, `signature`) and can be fetched from public endpoints, then submitted onchain by anyone. That means integrators are not forced into a provider-managed callback flow with subscription/premium mechanics, and users can still supply signature data directly (including via a block explorer) if a frontend is unavailable. In this model, you pay normal transaction gas for your own app flow and verification, not an additional oracle fulfillment callback into your contract. You can then use this signature as a random number after hashing it.

Security-wise, this only gives the intended “external randomness” properties if integration is done correctly: commit to a specific future round before reveal, stop accepting user inputs that could be adapted after commitment, and enforce freshness/replay policy in the consuming contract.

---

## What this project includes

- `src/verifiers/DrandVerifierQuicknet.sol`
  - Internal quicknet verifier library (for embedding in other contracts).
  - Accepts **compressed** (48-byte) and **uncompressed** (96-byte) G1 signatures.
- `src/verifiers/DrandVerifierQuicknetLib.sol`
  - Linked Quicknet entrypoints that reuse the internal implementation.
  - Keeps BLS verification outside the consuming contract's bytecode.
- `src/verifiers/DrandVerifierDefault.sol`
  - Internal default network verifier library (for embedding in other contracts).
  - Verifies chained beacons with `sha256(previous_signature || uint64(round))`.
  - Accepts **compressed** (96-byte) and **uncompressed** (192-byte) G2 signatures.
  - Requires `previousSignature.length == 96` (compressed previous round signature bytes).
- `src/oracles/DrandOracleQuicknet.sol`
  - Deployable quicknet oracle contract exposing the external verifier API.
- `src/oracles/DrandOracleDefault.sol`
  - Deployable default network oracle contract exposing the external verifier API.
- `src/utils/LibBLS.sol`
  - Internal BLS12-381 helper library used by default verification paths.
- `src/interfaces/IDrandOracleQuicknet.sol`
  - Quicknet oracle interface.
- `src/interfaces/IDrandOracleDefault.sol`
  - Default oracle interface.
- `test/DrandVerifierQuicknet.t.sol`
  - Quicknet unit/adversarial/fuzz/live-FFI coverage.
- `test/DrandVerifierDefault.t.sol`
  - Default network unit/adversarial/fuzz/live-FFI coverage.
- `test/LibBLS.t.sol`
  - Direct coverage for LibBLS decoding/math/hash-to-curve/pairing wiring paths.

---

## Verifier libraries vs oracle contracts

The codebase provides three consumption modes:

- `DrandVerifierQuicknet` and `DrandVerifierDefault` have internal functions. The compiler embeds only the code each consumer uses.
- `DrandVerifierQuicknetLib` exposes the Quicknet core API as external library functions. Deploy it once and link consumers to its address; library calls use `DELEGATECALL`.
- `src/oracles/*` are standalone contracts. They use the internal implementation and do not require a linked library deployment.

### Quicknet (`bls-unchained-g1-rfc9380`)

- Message digest input: `uint64(round)`
- Message digest: `sha256(uint64(round))`
- Signature group: **G1**
- Public key group: **G2**
- Contract flow: `BLS2.hashToPoint(...)` on G1 + a bounded two-pair BLS12-381 pairing check.

### Default (`pedersen-bls-chained`)

- Message digest input: `previous_signature || uint64(round)`
- Message digest: `sha256(previous_signature || uint64(round))`
- Signature group: **G2**
- Public key group: **G1**
- Contract flow: `LibBLS.verifyDefaultSignature(...)`

### Which one should you use?

From an onchain randomness perspective, **both networks are functionally usable**. Both provide publicly verifiable drand beacons you can verify onchain.

- Use **Quicknet** for most new integrations when you want faster cadence (3s rounds) and simpler verification inputs (`round + signature`).
- Use **Default** when you specifically need the chained scheme (`previous_signature` linked into the message).

---

## LibBLS

`LibBLS` is the internal library that powers `DrandVerifierDefault`. It exists because the default network uses a G2-signature / G1-public-key path with chained message construction, which is not the same turnkey path used by Quicknet.

In this repository, `LibBLS` provides the default network-specific cryptographic flow: compressed G2 decoding, canonical checks, G2 subgroup validation, hash-to-G2 mapping for the chained digest, and pairing-precompile wiring for final verification. `DrandVerifierDefault.verify(...)` computes the chained digest, then calls `LibBLS.verifyDefaultSignature(...)`, decompression paths call `LibBLS.decompressG2Signature(...)`.

`LibBLS` is not used by Quicknet.

---

## Technical differences at a glance

| Property | Quicknet | Default |
|---|---|---|
| Oracle contract | `DrandOracleQuicknet` | `DrandOracleDefault` |
| Internal library | `DrandVerifierQuicknet` | `DrandVerifierDefault` |
| drand scheme | `bls-unchained-g1-rfc9380` | `pedersen-bls-chained` |
| Hash input | `round` | `previous_signature + round` |
| Signature bytes accepted | 48 (compressed G1) / 96 (uncompressed G1) | 96 (compressed G2) / 192 (uncompressed G2) |
| Signature group | G1 | G2 |
| Public key group | G2 | G1 |
| Verification backend in this repo | `BLS2` helpers + bounded native pairing | `LibBLS` |

---

## Practical integration notes

### Integrating Quicknet

1. Fetch round and signature from the Quicknet API.
2. Call `verify(round, sig)` with either compressed (48-byte) or uncompressed (96-byte) signature.
3. Use `decompressSignature(...)` offchain only if you explicitly need uncompressed bytes.
4. Or pass raw API JSON directly to `verifyAPI(apiResponse)` for simpler integration (with extra gas for JSON parsing).
5. Use `safeVerify` to return `false` for signature-decoding or precompile failures. Callers must still supply enough gas for verification.
6. Use `verifyNormalized(round, sig)` when you need consistent randomness outputs across compressed/uncompressed signature representations.

For linked Quicknet verification, call `DrandVerifierQuicknetLib.verifyCanonical(round, sig)` and use its internal `scopedHash(normalized)` only after successful verification. Linked `verifyNormalized` scopes its output to the consuming contract and current chain, not the library address. Ordinary calls to `DrandOracleQuicknet.verifyNormalized` scope the output to the oracle instead.

`safeVerify` and `verifyAPI` remain oracle entrypoints. The linked library provides verification and JSON decoding separately, malformed inputs can still revert. It does not assume that the consumer exposes a callable `verify` function.

The Quicknet verifier limits its two-pair pairing precompile call to the [EIP-2537 cost](https://eips.ethereum.org/EIPS/eip-2537#gas-schedule) of 102,900 gas. Pairing failure returns `false`, malformed compressed encodings can still revert. This limit covers only the pairing call, not decoding or hash-to-curve.

### Integrating Default network

1. Fetch `round`, `signature`, and `previous_signature` from the Default chain API.
2. Pass `previous_signature` exactly as 96-byte compressed bytes.
3. Call `verify(round, previousSignature, sig)` with either compressed (96-byte) or uncompressed (192-byte) signature.
4. `decompressSignature(...)` can be used offchain when you need uncompressed form.
5. Or pass raw API JSON directly to `verifyAPI(apiResponse)` for simpler integration (with extra gas for JSON parsing).
6. Use `safeVerify` to return `false` for signature-decoding or precompile failures. Callers must still supply enough gas for verification.
7. Use `verifyNormalized(round, previousSignature, sig)` when you need consistent randomness outputs across compressed/uncompressed signature representations.

If `previous_signature` is omitted, malformed, or from the wrong round, verification fails by design.

The Default verifier limits its single-point G2 subgroup precompile call to the [EIP-2537 cost](https://eips.ethereum.org/EIPS/eip-2537#gas-schedule) of 22,500 gas. Failure of this check still reverts through `verify` and returns `false` through `safeVerify`, but the precompile can burn no more than this allowance. This limit covers only that precompile call, callers must still provide enough gas for decoding and verification.

---

## APIs

Both networks reject parsed rounds above `type(uint64).max`: `decodeAPIResponse` reports decoding failure and `verifyAPI` returns `false`. JSON parsing or conversion to `uint256` can still revert.

### `DrandVerifierQuicknetLib`

- External verification: `verify`, `verifyCanonical`, `verifyNormalized`.
- External helpers: `decompressSignature`, `decodeAPIResponse`, `roundMessageHash`, `deriveDrandRequest`.
- External metadata getters: `DST`, `DRAND_API_REQUEST`, `PERIOD_SECONDS`, `GENESIS_TIMESTAMP`, `COMPRESSED_G1_SIG_LENGTH`, `UNCOMPRESSED_G1_SIG_LENGTH`, `PUBLIC_KEY`.
- Internal helper: `scopedHash(bytes32 normalized) -> bytes32`.

Verification return values match the internal implementation. `verifyCanonical` returns `(verified, normalizedRoundHash, canonicalSignature)`. Failed verification returns zero/empty values. `scopedHash` only hashes its input, it does not verify a signature.

### `DrandOracleQuicknet`

- `roundMessageHash(uint64 round) -> bytes32`
- `deriveDrandRequest(uint64 round) -> string`
- `verify(uint64 round, bytes sig) -> bool`
- `safeVerify(uint64 round, bytes sig) -> bool`
- `verifyAPI(string apiResponse) -> bool`
- `verifyNormalized(uint64 round, bytes sig) -> (bool verified, bytes32 normalizedRoundHash, bytes32 chainScopedHash)`
- `verifyCanonical(uint64 round, bytes sig) -> (bool verified, bytes32 normalizedRoundHash, bytes canonicalSignature)`
- `decompressSignature(bytes compressedSig) -> bytes`
- constants/metadata: `DST`, `DRAND_API_REQUEST`, `PERIOD_SECONDS`, `GENESIS_TIMESTAMP`, `COMPRESSED_G1_SIG_LENGTH`, `UNCOMPRESSED_G1_SIG_LENGTH`, `PUBLIC_KEY`

### `DrandOracleDefault`

- `roundMessageHash(uint64 round, bytes previousSignature) -> bytes32`
- `deriveDrandRequest(uint64 round) -> string`
- `verify(uint64 round, bytes previousSignature, bytes signature) -> bool`
- `safeVerify(uint64 round, bytes previousSignature, bytes signature) -> bool`
- `verifyAPI(string apiResponse) -> bool`
- `verifyNormalized(uint64 round, bytes previousSignature, bytes signature) -> (bool verified, bytes32 normalizedRoundHash, bytes32 chainScopedHash)`
- `decompressSignature(bytes compressedSig) -> bytes`
- constants/metadata: `DST`, `DRAND_API_REQUEST`, `PERIOD_SECONDS`, `GENESIS_TIMESTAMP`, `COMPRESSED_G2_SIG_LENGTH`, `UNCOMPRESSED_G2_SIG_LENGTH`, `PUBLIC_KEY`

---

## Test strategy

Install [Foundry](https://getfoundry.sh/introduction/installation), Python 3, and `curl`. From the repository root, initialize dependencies and run the checks in a Python virtual environment:

```bash
git submodule update --init --recursive
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install py-ecc
forge fmt --check
forge build --sizes
forge test -vv
```

Coverage includes:

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

- Both oracle contracts are stateless verifiers only (no freshness tracking or replay prevention).
- Both rely on target-chain support for required BLS12-381 precompiles included in the Pectra hard fork.
- Quicknet and Default use different precompile paths. The current Foundry build targets Osaka, validate both the EVM target and required precompiles on your deployment chain.
- For state-changing use, caller contracts should define freshness/replay policy explicitly.

---

## Normalized randomness outputs

`verify(...)` only answers signature validity. If an app derives randomness directly from raw signature bytes, compressed and uncompressed encodings of the same valid point hash to different values. To avoid that integration footgun, `verifyNormalized(...)` verifies first, then hashes the canonical signature point bytes plus `round`.

Both oracles return:
- `normalizedRoundHash = keccak256(canonicalSignaturePoint || round)`
- `chainScopedHash = keccak256(keccak256("DRAND_VERIFIER") || normalizedRoundHash || address(this) || block.chainid)`

This gives one consistent random value (`normalizedRoundHash`) and one chain/contract-scoped value (`chainScopedHash`).

Quicknet's `verifyCanonical(...)` decodes the signature once and returns its normalized hash and canonical 96-byte encoding after verification. It reuses verified uncompressed input, or marshals the verified compressed point. `verifyNormalized(...)` uses this helper without changing its hashes or return values. Failed verification returns `(false, bytes32(0), bytes(""))`, malformed compressed encodings can still revert.

---

## Why this works technically (and what assumptions you are taking)

### Why BLS threshold signatures make this verifiable onchain

drand nodes collectively produce threshold BLS signatures for each round. Anyone who has the network root-of-trust parameters (public key, period, genesis, scheme) can verify a beacon signature. Onchain, this contract family checks the same signature validity that offchain clients check.

This gives public verifiability without trusting a single node or a private API response. The critical assumption is threshold honesty: drand’s security model states malicious control must stay below threshold for unpredictability; if an attacker controls at least threshold shares, they can derive future chain beacons, while randomness remains unbiasable. Because multiple parties are involved in signing, it is impossible for any single party to influence the final signature.

### drand vs Chainlink VRF vs `block.prevrandao` (practical model differences)

| Dimension | drand (this repo’s model) | Chainlink VRF | `block.prevrandao` |
|---|---|---|---|
| Delivery pattern | Public beacon + user/relayer submits | Oracle callback fulfillment | Native block field |
| Cost shape | Gas for your call + verification, no VRF premium/subscription flow | Gas + VRF premium + callback path, subscription/funding management | Minimal read cost |
| Influence surface | External threshold network, unpredictability requires < threshold corruption | Validator reorg/re-roll considerations + callback ordering/funding concerns | Proposer has bounded influence per slot (EIP-4399) |
| Commitment style | Clean when app commits to specific future round before reveal | Request/fulfill lifecycle, asynchronous callback semantics | Must use lookahead/cutoff discipline to reduce predictability/bias risk |

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
- `lib/solady` (JSON parsing in verifier `verifyAPI(...)` helpers and FFI live tests)

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
