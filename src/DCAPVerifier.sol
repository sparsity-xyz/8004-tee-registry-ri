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
///   bytes 65–128  : bytes64 reportData
contract DCAPVerifier is IVerifier {
    IAttestation public immutable automata;

    constructor(address _automata) {
        automata = IAttestation(_automata);
    }

    function verify(bytes calldata attestation) external override returns (bytes32 codeMeasurement) {
        bytes memory output = automata.verifyAndAttestOnChain(attestation);

        bytes32 mrEnclave;
        bytes32 mrSigner;
        assembly {
            mrEnclave := mload(add(output, 33))
            mrSigner := mload(add(output, 65))
        }

        codeMeasurement = keccak256(abi.encodePacked(mrEnclave, mrSigner));
    }
}
