// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "../../lib/bls-solidity/src/libraries/BLS2.sol";
import {DrandVerifierQuicknet} from "./DrandVerifierQuicknet.sol";

/// @title DrandVerifierQuicknetLib
/// @notice Linked facade for drand quicknet verification in the consuming contract's context.
/// @dev External library calls use DELEGATECALL, scopedHash stays internal to avoid a linked call for hashing.
library DrandVerifierQuicknetLib {
    function verify(uint64 round, bytes memory sig) external view returns (bool) {
        return DrandVerifierQuicknet.verify(round, sig);
    }

    function verifyCanonical(uint64 round, bytes memory sig) external view returns (bool, bytes32, bytes memory) {
        return DrandVerifierQuicknet.verifyCanonical(round, sig);
    }

    function verifyNormalized(uint64 round, bytes memory sig) external view returns (bool, bytes32, bytes32) {
        return DrandVerifierQuicknet.verifyNormalized(round, sig);
    }

    function scopedHash(bytes32 normalized) internal view returns (bytes32) {
        return DrandVerifierQuicknet.scopedHash(normalized);
    }

    function decompressSignature(bytes memory compressedSig) external view returns (bytes memory) {
        return DrandVerifierQuicknet.decompressSignature(compressedSig);
    }

    function decodeAPIResponse(string memory response) external pure returns (bool, uint64, bytes memory) {
        return DrandVerifierQuicknet.decodeAPIResponse(response);
    }

    function roundMessageHash(uint64 round) external pure returns (bytes32) {
        return DrandVerifierQuicknet.roundMessageHash(round);
    }

    function deriveDrandRequest(uint64 round) external pure returns (string memory) {
        return DrandVerifierQuicknet.deriveDrandRequest(round);
    }

    function PUBLIC_KEY() external pure returns (BLS2.PointG2 memory) {
        return DrandVerifierQuicknet.PUBLIC_KEY();
    }

    function DST() external pure returns (string memory) {
        return DrandVerifierQuicknet.DST;
    }

    function DRAND_API_REQUEST() external pure returns (string memory) {
        return DrandVerifierQuicknet.DRAND_API_REQUEST;
    }

    function PERIOD_SECONDS() external pure returns (uint64) {
        return DrandVerifierQuicknet.PERIOD_SECONDS;
    }

    function GENESIS_TIMESTAMP() external pure returns (uint64) {
        return DrandVerifierQuicknet.GENESIS_TIMESTAMP;
    }

    function COMPRESSED_G1_SIG_LENGTH() external pure returns (uint256) {
        return DrandVerifierQuicknet.COMPRESSED_G1_SIG_LENGTH;
    }

    function UNCOMPRESSED_G1_SIG_LENGTH() external pure returns (uint256) {
        return DrandVerifierQuicknet.UNCOMPRESSED_G1_SIG_LENGTH;
    }
}
