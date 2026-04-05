// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";
import {IDrandVerifierQuicknet} from "src/interfaces/IDrandVerifierQuicknet.sol";

/// @title DrandVerifierQuicknet
/// @notice Verifies drand quicknet BLS12-381 signatures using the vendored bls-solidity library.
/// @dev Supports drand signatures encoded either as compressed G1 (48 bytes) or uncompressed G1 (96 bytes).
contract DrandVerifierQuicknet is IDrandVerifierQuicknet {
    /// @notice Domain separation tag used by drand quicknet for hash-to-curve.
    string public constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

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
    function verify(uint64 round, bytes calldata sig) external view override returns (bool) {
        BLS2.PointG1 memory signaturePoint;
        uint256 signatureLength = sig.length;

        if (signatureLength == UNCOMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1Unmarshal(sig);
        } else if (signatureLength == COMPRESSED_G1_SIG_LENGTH) {
            signaturePoint = BLS2.g1UnmarshalCompressed(sig);
        } else {
            return false;
        }

        BLS2.PointG1 memory messagePoint =
            BLS2.hashToPoint(bytes(DST), abi.encodePacked(roundMessageHash(round)));

        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(signaturePoint, PUBLIC_KEY(), messagePoint);
        return pairingSuccess && callSuccess;
    }
}
