// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./TEERegistry.sol";

/// @title MockNitroVerifier — Stub for AWS Nitro Enclaves
/// @notice Accepts abi.encode(codeMeasurement, teeWallet) as "attestation" and returns the values.
///
/// @dev Real on-chain Nitro verification exists (e.g. base/nitro-validator) but costs ~63M gas,
/// exceeding typical block gas limits. This mock enables full E2E testing of the registry flow.
/// Swap in a real verifier via TEERegistry.setVerifier(NITRO, realAddress) when gas-feasible.
contract MockNitroVerifier is IVerifier {
    error InvalidAttestationLength();

    function verify(bytes calldata attestation) external pure override returns (bytes32 codeMeasurement, address teeWallet) {
        if (attestation.length < 64) revert InvalidAttestationLength();
        (codeMeasurement, teeWallet) = abi.decode(attestation, (bytes32, address));
    }
}
