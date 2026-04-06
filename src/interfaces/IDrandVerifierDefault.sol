// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";

/// @title IDrandVerifierDefault
/// @notice Interface for drand default network (pedersen-bls-chained) BLS12-381 verification and decompression.
interface IDrandVerifierDefault {
    function DST() external pure returns (string memory);
    function COMPRESSED_G2_SIG_LENGTH() external pure returns (uint256);
    function UNCOMPRESSED_G2_SIG_LENGTH() external pure returns (uint256);
    function PERIOD_SECONDS() external pure returns (uint64);
    function GENESIS_TIMESTAMP() external pure returns (uint64);
    function PUBLIC_KEY() external pure returns (BLS2.PointG1 memory);

    function roundMessageHash(uint64 round, bytes calldata previousSignature) external pure returns (bytes32);
    function deriveDrandRequest(uint64 round) external view returns (string memory);
    function decompressSignature(bytes calldata compressedSig) external view returns (bytes memory);

    function verify(uint64 round, bytes calldata previousSignature, bytes calldata signature)
        external
        view
        returns (bool);
    function safeVerify(uint64 round, bytes calldata previousSignature, bytes calldata signature)
        external
        view
        returns (bool);
    function verifyAPI(string calldata response) external view returns (bool);
}
