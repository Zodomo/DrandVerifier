// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";

/// @title IDrandVerifier
/// @notice Interface for drand quicknet BLS12-381 verification and decompression.
interface IDrandVerifier {
    function DST() external pure returns (string memory);
    function COMPRESSED_SIG_LENGTH() external pure returns (uint256);
    function UNCOMPRESSED_SIG_LENGTH() external pure returns (uint256);
    function PUBLIC_KEY() external pure returns (BLS2.PointG2 memory);

    function roundMessageHash(uint64 round) external pure returns (bytes32);
    function decompressSignature(bytes calldata compressedSig) external view returns (bytes memory);
    function verify(uint64 round, bytes calldata sig) external view returns (bool);
}
