// SPDX-License-Identifier: VPL
pragma solidity ^0.8.34;

import {BLS2} from "lib/bls-solidity/src/libraries/BLS2.sol";
import {IDrandVerifierDefault} from "src/interfaces/IDrandVerifierDefault.sol";

/// @title DrandVerifierDefault
/// @notice Verifies drand default-network (pedersen-bls-chained) BLS12-381 signatures.
/// @dev drand default network uses signatures on G2, public key on G1, and chained digest:
///      sha256(previous_signature || uint64(round) big-endian).
contract DrandVerifierDefault is IDrandVerifierDefault {
    /// @notice Domain separation tag used by drand default network for hash-to-curve.
    string public constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    /// @notice Expected compressed G2 signature length in bytes.
    uint256 public constant COMPRESSED_G2_SIG_LENGTH = 96;
    
    /// @notice Expected uncompressed G2 signature length in bytes.
    uint256 public constant UNCOMPRESSED_G2_SIG_LENGTH = 192;

    // BLS12-381 field order.
    uint128 private constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // EIP-198 / EIP-2537 precompile addresses.
    uint256 private constant MODEXP_ADDRESS = 5;
    uint256 private constant BLS12_PAIRING_CHECK = 0x0f;
    uint256 private constant BLS12_MAP_FP2_TO_G2 = 0x11;

    // -G1 generator for BLS12-381, represented as (x_hi, x_lo, y_hi, y_lo).
    uint128 private constant NEG_G1_X_HI = 0x17f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant NEG_G1_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint128 private constant NEG_G1_Y_HI = 0x114d1d6855d545a8aa7d76c8cf2e21f2;
    uint256 private constant NEG_G1_Y_LO = 0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca;

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

    /// @notice Verifies a drand default-network signature for a round and previous signature.
    /// @param round The drand round number.
    /// @param previousSignature The previous round signature bytes from drand beacon payload.
    /// @param signature The current round signature bytes in uncompressed G2 form (192 bytes).
    function verify(uint64 round, bytes calldata previousSignature, bytes calldata signature)
        external
        view
        override
        returns (bool)
    {
        if (signature.length != UNCOMPRESSED_G2_SIG_LENGTH) {
            return false;
        }

        BLS2.PointG2 memory signaturePoint = BLS2.g2Unmarshal(signature);
        uint256[8] memory signatureWords = _pointG2ToPairingWords(signaturePoint);

        bytes32 digest = roundMessageHash(round, previousSignature);
        (uint256[8] memory messageWords0, uint256[8] memory messageWords1) =
            _hashToPointG2Parts(bytes(DST), abi.encodePacked(digest));

        (bool pairingSuccess, bool callSuccess) =
            _verifySingleG2(signatureWords, PUBLIC_KEY(), messageWords0, messageWords1);
        return pairingSuccess && callSuccess;
    }

    function _verifySingleG2(
        uint256[8] memory signature,
        BLS2.PointG1 memory pubkey,
        uint256[8] memory messagePart0,
        uint256[8] memory messagePart1
    )
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[36] memory input = [
            uint256(NEG_G1_X_HI),
            NEG_G1_X_LO,
            uint256(NEG_G1_Y_HI),
            NEG_G1_Y_LO,
            signature[0],
            signature[1],
            signature[2],
            signature[3],
            signature[4],
            signature[5],
            signature[6],
            signature[7],
            uint256(pubkey.x_hi),
            pubkey.x_lo,
            uint256(pubkey.y_hi),
            pubkey.y_lo,
            messagePart0[0],
            messagePart0[1],
            messagePart0[2],
            messagePart0[3],
            messagePart0[4],
            messagePart0[5],
            messagePart0[6],
            messagePart0[7],
            uint256(pubkey.x_hi),
            pubkey.x_lo,
            uint256(pubkey.y_hi),
            pubkey.y_lo,
            messagePart1[0],
            messagePart1[1],
            messagePart1[2],
            messagePart1[3],
            messagePart1[4],
            messagePart1[5],
            messagePart1[6],
            messagePart1[7]
        ];

        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(gas(), BLS12_PAIRING_CHECK, input, 1152, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @dev Hash-to-G2 via RFC9380-style expand message and EIP-2537 map_fp2_to_g2 + g2add.
    /// Returned words are in pairing-precompile order:
    /// (x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo).
    function _hashToPointG2Parts(bytes memory dst, bytes memory message)
        internal
        view
        returns (uint256[8] memory out0, uint256[8] memory out1)
    {
        bytes memory uniformBytes = _expandMsg(dst, message, 256);

        for (uint256 i = 0; i < 4; i++) {
            _modPInPlace(uniformBytes, i * 64);
        }

        bool ok;

        assembly {
            ok := staticcall(gas(), BLS12_MAP_FP2_TO_G2, add(uniformBytes, 32), 128, out0, 256)
        }
        require(ok, "map_fp2_to_g2 p0 failed");

        assembly {
            ok := staticcall(gas(), BLS12_MAP_FP2_TO_G2, add(add(uniformBytes, 32), 128), 128, out1, 256)
        }
        require(ok, "map_fp2_to_g2 p1 failed");
    }

    function _pointG2ToPairingWords(BLS2.PointG2 memory point) internal pure returns (uint256[8] memory out) {
        out[0] = uint256(point.x0_hi);
        out[1] = point.x0_lo;
        out[2] = uint256(point.x1_hi);
        out[3] = point.x1_lo;
        out[4] = uint256(point.y0_hi);
        out[5] = point.y0_lo;
        out[6] = uint256(point.y1_hi);
        out[7] = point.y1_lo;
    }

    function _modPInPlace(bytes memory input, uint256 offset) internal view {
        bytes memory buf = new bytes(225);
        bool ok;

        assembly {
            let p := add(buf, 32)
            mstore(p, 64)
            p := add(p, 32)
            mstore(p, 1)
            p := add(p, 32)
            mstore(p, 64)
            p := add(p, 32)

            let src := add(add(input, 32), offset)
            mcopy(p, src, 64)
            p := add(p, 64)

            mstore8(p, 1)
            p := add(p, 1)
            mstore(p, P_HI)
            p := add(p, 32)
            mstore(p, P_LO)

            ok := staticcall(gas(), MODEXP_ADDRESS, add(buf, 32), 225, src, 64)
        }

        require(ok, "modp failed");
    }

    function _expandMsg(bytes memory dst, bytes memory message, uint16 nBytes) internal pure returns (bytes memory) {
        uint256 domainLen = dst.length;
        require(domainLen <= 255, "dst too long");

        bytes memory zpad = new bytes(64);
        bytes32 b0 = sha256(abi.encodePacked(zpad, message, bytes2(nBytes), uint8(0), dst, uint8(domainLen)));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dst, uint8(domainLen)));

        bytes memory out = new bytes(nBytes);
        uint256 ell = (uint256(nBytes) + 31) >> 5;

        for (uint256 i = 1; i < ell; i++) {
            bytes32 tmp = bi;
            assembly {
                let p := add(add(out, 32), mul(32, sub(i, 1)))
                mstore(p, tmp)
            }
            bi = sha256(abi.encodePacked(b0 ^ bi, uint8(1 + i), dst, uint8(domainLen)));
        }

        assembly {
            let p := add(add(out, 32), mul(32, sub(ell, 1)))
            mstore(p, bi)
        }

        return out;
    }
}
