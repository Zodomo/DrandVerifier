// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";
import {LibString} from "lib/solady/src/utils/LibString.sol";
import {LibBLS} from "src/LibBLS.sol";
import {IDrandVerifierDefault} from "src/interfaces/IDrandVerifierDefault.sol";

/// @title DrandVerifierDefault
/// @notice Verifies drand default network (pedersen-bls-chained) BLS12-381 signatures.
/// @dev drand default network uses signatures on G2, public key on G1, and chained digest:
///      sha256(previous_signature || uint64(round) big-endian).
contract DrandVerifierDefault is IDrandVerifierDefault {
    using LibString for uint256;

    /// @notice Domain separation tag used by drand default network for hash-to-curve.
    string public constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    /// @notice Default network beacon period in seconds.
    uint64 public constant PERIOD_SECONDS = 30 seconds;

    /// @notice Default network genesis Unix timestamp.
    uint64 public constant GENESIS_TIMESTAMP = 1595431050;

    /// @notice Expected compressed G2 signature length in bytes.
    uint256 public constant COMPRESSED_G2_SIG_LENGTH = 96;

    /// @notice Expected uncompressed G2 signature length in bytes.
    uint256 public constant UNCOMPRESSED_G2_SIG_LENGTH = 192;

    /// @notice Returns drand default network public key in G1 form.
    function PUBLIC_KEY() public pure override returns (BLS2.PointG1 memory) {
        return BLS2.PointG1(
            0x068f005eb8e6e4ca0a47c8a77ceaa530,
            0x9a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31,
            0x026fa5eef143aaa17c53b3c150d96a18,
            0x051b718531af576803cfb9acf29b8774a8184e63c62da81ddf4d76fb0a65895c
        );
    }

    /// @notice Computes chained drand message digest for default network.
    /// @dev Digest is sha256(previous_signature || uint64(round) big-endian).
    function roundMessageHash(uint64 round, bytes calldata previousSignature) public pure override returns (bytes32) {
        return sha256(abi.encodePacked(previousSignature, round));
    }

    /// @notice Derives the drand HTTP API request URL for a specific default network round.
    /// @dev Uses explicit default chain-hash addressing on API v2.
    function deriveDrandRequest(uint64 round) public pure override returns (string memory) {
        return string.concat(
            "https://api.drand.sh/v2/chains/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/rounds/",
            uint256(round).toString()
        );
    }

    /// @notice Decompresses a 96-byte compressed BLS12-381 G2 signature to 192-byte uncompressed form.
    /// @dev Intended for offchain eth_call usage so callers can submit uncompressed signatures to save onchain gas.
    /// Reverts for invalid compressed encodings.
    /// @param compressedSig The compressed signature bytes.
    /// @return The uncompressed signature bytes.
    function decompressSignature(bytes calldata compressedSig) external view override returns (bytes memory) {
        bytes memory compressed = compressedSig;
        return LibBLS.decompressG2Signature(compressed);
    }

    /// @notice Verifies a drand default network signature for a round and previous signature.
    /// @param round The drand round number.
    /// @param previousSig The previous round signature bytes from drand beacon payload.
    /// @param sig The current round signature bytes in compressed (96) or uncompressed (192) G2 form.
    function verify(uint64 round, bytes calldata previousSig, bytes calldata sig) public view override returns (bool) {
        if (previousSig.length != COMPRESSED_G2_SIG_LENGTH) return false;

        bytes32 digest = roundMessageHash(round, previousSig);
        return LibBLS.verifyDefaultSignature(sig, PUBLIC_KEY(), bytes(DST), digest);
    }

    /// @notice Safe wrapper around verify that returns false instead of bubbling decode/precompile reverts.
    function safeVerify(uint64 round, bytes calldata previousSig, bytes calldata sig)
        external
        view
        override
        returns (bool)
    {
        try this.verify(round, previousSig, sig) returns (bool verified) {
            return verified;
        } catch {
            return false;
        }
    }
}
