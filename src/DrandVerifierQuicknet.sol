// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";
import {LibString} from "lib/solady/src/utils/LibString.sol";
import {JSONParserLib} from "lib/solady/src/utils/JSONParserLib.sol";
import {IDrandVerifierQuicknet} from "src/interfaces/IDrandVerifierQuicknet.sol";

/// @title DrandVerifierQuicknet
/// @notice Verifies drand quicknet BLS12-381 signatures using the vendored bls-solidity library.
/// @dev Supports drand signatures encoded either as compressed G1 (48 bytes) or uncompressed G1 (96 bytes).
contract DrandVerifierQuicknet is IDrandVerifierQuicknet {
    using LibString for uint256;
    using JSONParserLib for *;

    /// @notice Domain separation tag used by drand quicknet for hash-to-curve.
    string public constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    /// @notice Quicknet beacon period in seconds.
    uint64 public constant PERIOD_SECONDS = 3 seconds;

    /// @notice Quicknet genesis Unix timestamp.
    uint64 public constant GENESIS_TIMESTAMP = 1692803367;

    /// @notice Expected compressed G1 signature length in bytes.
    uint256 public constant COMPRESSED_G1_SIG_LENGTH = 48;

    /// @notice Expected uncompressed G1 signature length in bytes.
    uint256 public constant UNCOMPRESSED_G1_SIG_LENGTH = 96;

    /// @notice Returns drand quicknet public key in G2 form.
    /// @dev Matches the quicknet key used by bls-solidity's QuicknetRegistry demo.
    function PUBLIC_KEY() public pure override returns (BLS2.PointG2 memory) {
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
    function roundMessageHash(uint64 round) public pure override returns (bytes32) {
        return sha256(abi.encodePacked(round));
    }

    /// @notice Derives the drand HTTP API request URL for a specific quicknet round.
    /// @dev Uses explicit quicknet chain-hash addressing on API v2.
    function deriveDrandRequest(uint64 round) public pure override returns (string memory) {
        return string.concat(
            "https://api.drand.sh/v2/chains/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/rounds/",
            uint256(round).toString()
        );
    }

    /// @notice Decompresses a 48-byte compressed BLS12-381 G1 signature to 96-byte uncompressed form.
    /// @dev Intended for offchain eth_call usage so callers can submit uncompressed signatures to save onchain gas.
    /// Reverts for invalid compressed encodings.
    /// @param compressedSig The compressed signature bytes.
    /// @return The uncompressed signature bytes.
    function decompressSignature(bytes calldata compressedSig) external view override returns (bytes memory) {
        return BLS2.g1Marshal(BLS2.g1UnmarshalCompressed(compressedSig));
    }

    /// @notice Verifies a drand quicknet signature for a given round.
    /// @param round The drand round number.
    /// @param sig The current round signature bytes in compressed (48) or uncompressed (96) G1 form.
    /// @return True when the signature is valid for the provided round and quicknet public key.
    function verify(uint64 round, bytes calldata sig) public view override returns (bool) {
        BLS2.PointG1 memory signaturePoint;
        uint256 signatureLength = sig.length;

        if (signatureLength == UNCOMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1Unmarshal(sig);
        } else if (signatureLength == COMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1UnmarshalCompressed(sig);
        } else {
            return false;
        }

        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(bytes(DST), abi.encodePacked(roundMessageHash(round)));

        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(signaturePoint, PUBLIC_KEY(), messagePoint);
        return pairingSuccess && callSuccess;
    }

    /// @notice Safe wrapper around verify that returns false instead of bubbling decode/precompile reverts.
    function safeVerify(uint64 round, bytes memory sig) public view override returns (bool) {
        try this.verify(round, sig) returns (bool verified) {
            return verified;
        } catch {
            return false;
        }
    }

    /// @notice Verifies a raw drand quicknet JSON API response.
    /// @dev Expects a JSON object containing `round` and hex `signature` fields.
    /// @param response The raw drand quicknet JSON API response.
    function verifyAPI(string calldata response) public view override returns (bool) {
        JSONParserLib.Item memory root = response.parse();
        JSONParserLib.Item memory roundItem = root.at('"round"');
        JSONParserLib.Item memory signatureItem = root.at('"signature"');

        if (roundItem.isUndefined() || signatureItem.isUndefined()) return false;
        if (!roundItem.isNumber() || !signatureItem.isString()) return false;

        uint64 round = uint64(JSONParserLib.parseUint(roundItem.value()));
        string memory signatureHex = JSONParserLib.decodeString(signatureItem.value());

        (bool decoded, bytes memory signature) = _tryDecodeHex(signatureHex);
        if (!decoded) return false;

        return safeVerify(round, signature);
    }

    /// @notice Decodes an ASCII hex string into raw bytes.
    /// @dev Returns `(false, "")` when length is odd or any nibble is not `[0-9a-fA-F]`.
    /// The input is expected without a `0x` prefix.
    /// @param hexString Hex string to decode.
    /// @return success Whether decoding succeeded.
    /// @return decoded Decoded bytes when successful, otherwise empty bytes.
    function _tryDecodeHex(string memory hexString) private pure returns (bool, bytes memory) {
        bytes memory chars = bytes(hexString);
        uint256 charsLen = chars.length;
        if (charsLen % 2 != 0) return (false, bytes(""));

        bytes memory out = new bytes(charsLen / 2);
        for (uint256 i = 0; i < charsLen; i += 2) {
            (bool okHi, uint8 hi) = _hexNibble(chars[i]);
            if (!okHi) return (false, bytes(""));
            (bool okLo, uint8 lo) = _hexNibble(chars[i + 1]);
            if (!okLo) return (false, bytes(""));
            out[i / 2] = bytes1((hi << 4) | lo);
        }

        return (true, out);
    }

    /// @notice Converts a single ASCII hex character into its 4-bit value.
    /// @param c ASCII character expected in `[0-9a-fA-F]`.
    /// @return valid Whether `c` is a valid hex character.
    /// @return nibble The parsed nibble value when valid.
    function _hexNibble(bytes1 c) private pure returns (bool, uint8) {
        uint8 v = uint8(c);
        if (v >= 48 && v <= 57) return (true, v - 48);
        if (v >= 65 && v <= 70) return (true, v - 55);
        if (v >= 97 && v <= 102) return (true, v - 87);
        return (false, 0);
    }
}
