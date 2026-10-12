// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {LibHex} from "../utils/LibHex.sol";
import {LibString} from "../../lib/solady/src/utils/LibString.sol";
import {BLS2} from "../../lib/bls-solidity/src/libraries/BLS2.sol";
import {BLS12_PAIRING_CHECK} from "../../lib/bls-solidity/src/libraries/Precompiles.sol";
import {JSONParserLib} from "../../lib/solady/src/utils/JSONParserLib.sol";

/// @title DrandVerifierQuicknet
/// @notice Internal verifier library for drand quicknet BLS12-381 signatures.
/// @dev Supports drand signatures encoded either as compressed G1 (48 bytes) or uncompressed G1 (96 bytes).
library DrandVerifierQuicknet {
    using LibString for uint256;
    using JSONParserLib for *;

    /// @notice Domain separation tag used by drand quicknet for hash-to-curve.
    string internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    /// @notice Quicknet beacon period in seconds.
    uint64 internal constant PERIOD_SECONDS = 3 seconds;

    /// @notice Quicknet genesis Unix timestamp.
    uint64 internal constant GENESIS_TIMESTAMP = 1692803367;

    /// @notice Expected compressed G1 signature length in bytes.
    uint256 internal constant COMPRESSED_G1_SIG_LENGTH = 48;

    /// @notice Expected uncompressed G1 signature length in bytes.
    uint256 internal constant UNCOMPRESSED_G1_SIG_LENGTH = 96;

    /// @notice Base drand API request URL for quicknet rounds.
    string internal constant DRAND_API_REQUEST =
        "https://api.drand.sh/v2/chains/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/rounds/";

    /// @notice Domain separator for chain-scoped normalized random values.
    bytes32 internal constant DOMAIN_SEPARATOR = keccak256("DRAND_VERIFIER");

    /// @notice Returns drand quicknet public key in G2 form.
    /// @dev Matches the quicknet key used by bls-solidity's QuicknetRegistry demo.
    function PUBLIC_KEY() internal pure returns (BLS2.PointG2 memory) {
        return BLS2.PointG2(
            0x03cf0f2896adee7eb8b5f01fcad39122,
            0x12c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d106451,
            0x0d1fec758c921cc22b0e17e63aaf4bcb,
            0x5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a,
            0x01a714f2edb74119a2f2b0d5a7c75ba9,
            0x02d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b,
            0x0e5db2b6bfbb01c867749cadffca88b3,
            0x6c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273
        );
    }

    /// @notice Computes the quicknet round message hash.
    /// @dev Quicknet uses sha256 over uint64 round encoded as 8-byte big-endian via abi.encodePacked.
    function roundMessageHash(uint64 round) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(round));
    }

    /// @notice Derives the drand HTTP API request URL for a specific quicknet round.
    /// @dev Uses explicit quicknet chain-hash addressing on API v2.
    function deriveDrandRequest(uint64 round) internal pure returns (string memory) {
        return string.concat(DRAND_API_REQUEST, uint256(round).toString());
    }

    /// @notice Decompresses a 48-byte compressed BLS12-381 G1 signature to 96-byte uncompressed form.
    /// @dev Intended for offchain eth_call usage so callers can submit uncompressed signatures to save onchain gas.
    /// Reverts for invalid compressed encodings.
    /// @param compressedSig The compressed signature bytes.
    /// @return The uncompressed signature bytes.
    function decompressSignature(bytes memory compressedSig) internal view returns (bytes memory) {
        return BLS2.g1Marshal(BLS2.g1UnmarshalCompressed(compressedSig));
    }

    /// @notice Decodes a raw drand quicknet JSON API response.
    /// @dev Expects a JSON object containing `round` and hex `signature` fields.
    function decodeAPIResponse(string memory response) internal pure returns (bool, uint64, bytes memory) {
        JSONParserLib.Item memory root = response.parse();
        JSONParserLib.Item memory roundItem = root.at('"round"');
        JSONParserLib.Item memory signatureItem = root.at('"signature"');

        if (roundItem.isUndefined() || signatureItem.isUndefined()) return (false, 0, bytes(""));
        if (!roundItem.isNumber() || !signatureItem.isString()) return (false, 0, bytes(""));

        uint256 parsedRound = JSONParserLib.parseUint(roundItem.value());
        if (parsedRound > type(uint64).max) return (false, 0, bytes(""));
        uint64 round = uint64(parsedRound);
        string memory signatureHex = JSONParserLib.decodeString(signatureItem.value());

        (bool decoded, bytes memory signature) = LibHex._tryDecodeHex(signatureHex);
        if (!decoded) return (false, 0, bytes(""));

        return (true, round, signature);
    }

    /// @notice Verifies a drand quicknet signature for a given round.
    /// @param round The drand round number.
    /// @param sig The current round signature bytes in compressed (48) or uncompressed (96) G1 form.
    /// @return True when the signature is valid for the provided round and quicknet public key.
    function verify(uint64 round, bytes memory sig) internal view returns (bool) {
        BLS2.PointG1 memory signaturePoint;
        uint256 signatureLength = sig.length;

        if (signatureLength == UNCOMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1Unmarshal(sig);
        } else if (signatureLength == COMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1UnmarshalCompressed(sig);
        } else {
            return false;
        }

        return _verifyPoint(round, signaturePoint);
    }

    /// @notice Verifies a signature and returns its normalized round hash and canonical 96-byte encoding.
    /// @dev Decodes the signature once. Invalid signatures return `(false, 0, "")`;
    /// malformed compressed encodings can revert.
    function verifyCanonical(uint64 round, bytes memory sig) internal view returns (bool, bytes32, bytes memory) {
        BLS2.PointG1 memory signaturePoint;
        uint256 signatureLength = sig.length;

        if (signatureLength == UNCOMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1Unmarshal(sig);
        } else if (signatureLength == COMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1UnmarshalCompressed(sig);
        } else {
            return (false, bytes32(0), bytes(""));
        }

        if (!_verifyPoint(round, signaturePoint)) return (false, bytes32(0), bytes(""));

        bytes memory canonicalSignature =
            signatureLength == UNCOMPRESSED_G1_SIG_LENGTH ? sig : BLS2.g1Marshal(signaturePoint);
        bytes32 normalizedRoundHash = keccak256(abi.encodePacked(canonicalSignature, round));
        return (true, normalizedRoundHash, canonicalSignature);
    }

    /// @notice Verifies signature and derives encoding-invariant random outputs.
    /// @dev Returns `(verified, normalizedRoundHash, chainScopedHash)` where:
    /// - `normalizedRoundHash = keccak256(canonicalG1SignaturePoint || round)`
    /// - `chainScopedHash = keccak256(DOMAIN_SEPARATOR || normalizedRoundHash || address(this) || block.chainid)`
    function verifyNormalized(uint64 round, bytes memory sig) internal view returns (bool, bytes32, bytes32) {
        (bool verified, bytes32 normalizedRoundHash,) = verifyCanonical(round, sig);
        if (!verified) return (false, bytes32(0), bytes32(0));

        return (true, normalizedRoundHash, scopedHash(normalizedRoundHash));
    }

    /// @notice Scopes an authenticated normalized round hash to the consuming contract and chain.
    function scopedHash(bytes32 normalized) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(DOMAIN_SEPARATOR, normalized, address(this), block.chainid));
    }

    function _verifyPoint(uint64 round, BLS2.PointG1 memory signaturePoint) private view returns (bool) {
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(bytes(DST), abi.encodePacked(roundMessageHash(round)));

        BLS2.PointG2 memory publicKey = PUBLIC_KEY();
        uint256[24] memory input = [
            signaturePoint.x_hi,
            signaturePoint.x_lo,
            signaturePoint.y_hi,
            signaturePoint.y_lo,
            // Negated G2 generator, in EIP-2537 coefficient order.
            0x024aa2b2f08f0a91260805272dc51051,
            0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
            0x13e02b6052719f607dacd3a088274f65,
            0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e,
            0x0d1b3cc2c7027888be51d9ef691d77bc,
            0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa,
            0x13fa4d4a0ad8b1ce186ed5061789213d,
            0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed,
            messagePoint.x_hi,
            messagePoint.x_lo,
            messagePoint.y_hi,
            messagePoint.y_lo,
            publicKey.x0_hi,
            publicKey.x0_lo,
            publicKey.x1_hi,
            publicKey.x1_lo,
            publicKey.y0_hi,
            publicKey.y0_lo,
            publicKey.y1_hi,
            publicKey.y1_lo
        ];
        uint256[1] memory out;
        bool callSuccess;
        // EIP-2537 charges 102,900 gas for two pairs; invalid input burns the forwarded gas.
        assembly {
            callSuccess := staticcall(102900, BLS12_PAIRING_CHECK, input, 768, out, 0x20)
        }
        return callSuccess && out[0] != 0;
    }
}
