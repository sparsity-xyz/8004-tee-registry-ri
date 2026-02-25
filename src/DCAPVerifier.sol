// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./TEERegistry.sol";
import {IAttestation} from "@automata-network/dcap-attestation/interfaces/IAttestation.sol";

/// @title DCAPVerifier — Intel TDX/SGX attestation via Automata DCAP
/// @notice Wraps Automata's on-chain DCAP verifier. Expects a raw DCAP quote as input.
/// @dev Gas cost: ~4-5M per verification (real on-chain DCAP parsing + cert chain validation).
///
/// Automata output layout (from AutomataDcapV3Attestation._verify):
///   byte  0       : uint8  tcbStatus
///   bytes 1–32    : bytes32 mrEnclave
///   bytes 33–64   : bytes32 mrSigner
///   bytes 65–128  : bytes64 reportData (first 20 bytes = teeWallet by convention)
contract DCAPVerifier is IVerifier {
    IAttestation public immutable automata;

    constructor(address _automata) {
        automata = IAttestation(_automata);
    }

    function verify(bytes calldata attestation) external override returns (bytes32 codeMeasurement, address teeWallet) {
        bytes memory output = automata.verifyAndAttestOnChain(attestation);

        bytes32 mrEnclave;
        bytes32 mrSigner;
        assembly {
            // output is a dynamic bytes: first 32 bytes = length, data starts at offset 32.
            // mrEnclave starts at data byte 1 → memory offset 32 + 1 = 33
            mrEnclave := mload(add(output, 33))
            // mrSigner starts at data byte 33 → memory offset 32 + 33 = 65
            mrSigner := mload(add(output, 65))
            // reportData starts at data byte 65 → memory offset 32 + 65 = 97
            // We need the first 20 bytes as an address (address is right-aligned in 32 bytes).
            // mload gives us 32 bytes; shift right by 96 bits (12 bytes) to get the top 20 bytes.
            teeWallet := shr(96, mload(add(output, 97)))
        }

        codeMeasurement = keccak256(abi.encodePacked(mrEnclave, mrSigner));
    }
}
