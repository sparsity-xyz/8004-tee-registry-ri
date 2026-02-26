// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TEERegistry, TEEType} from "../src/TEERegistry.sol";
import {CertManager} from "nitro-validator/CertManager.sol";

/// @title Register — Pre-warm Nitro CA certs then register a TEE instance
/// @notice Must use --skip-simulation --slow flags. Local simulation hangs because
///         forge tries to eth_call all 5 ECDSA-384 verifications (~9.5M gas each)
///         before broadcasting, causing RPC timeouts. --skip-simulation bypasses this;
///         --slow ensures each cert tx confirms before sending the next.
///
/// Usage:
///   forge script script/Register.s.sol --rpc-url base_sepolia --broadcast \
///     --skip-simulation --slow
///
/// Required env vars:
///   CERT_MANAGER   — deployed CertManager address
///   REGISTRY       — deployed TEERegistry address
///
/// Reads from samples/:
///   attestation.bin  — raw COSE_Sign1 attestation
///   cert_0.bin..cert_3.bin — CA certs extracted by extract_certs.py
///   leaf_cert.bin    — leaf cert
contract Register is Script {
    // Root CA cert hash — pre-cached in CertManager constructor
    bytes32 constant ROOT_CA_CERT_HASH = 0x311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185;

    function run() external {
        CertManager certManager = CertManager(vm.envAddress("CERT_MANAGER"));
        TEERegistry registry = TEERegistry(vm.envAddress("REGISTRY"));

        // Load cert files (extracted by extract_certs.py)
        bytes memory cert0 = vm.readFileBinary("samples/cert_0.bin");
        bytes memory cert1 = vm.readFileBinary("samples/cert_1.bin");
        bytes memory cert2 = vm.readFileBinary("samples/cert_2.bin");
        bytes memory cert3 = vm.readFileBinary("samples/cert_3.bin");
        bytes memory leafCert = vm.readFileBinary("samples/leaf_cert.bin");
        bytes memory attestation = vm.readFileBinary("samples/attestation.bin");

        // Compute parent hash chain locally (matches on-chain keccak256)
        bytes32 hash0 = keccak256(cert0);
        bytes32 hash1 = keccak256(cert1);
        bytes32 hash2 = keccak256(cert2);
        bytes32 hash3 = keccak256(cert3);

        console2.log("cert_0 hash:", vm.toString(hash0));
        console2.log("cert_1 hash:", vm.toString(hash1));
        console2.log("cert_2 hash:", vm.toString(hash2));
        console2.log("cert_3 hash:", vm.toString(hash3));
        console2.log("leaf hash:  ", vm.toString(keccak256(leafCert)));

        vm.startBroadcast();

        // Step 1: Pre-warm CA certs (each ~9.5M gas, fits under 25M per-tx)
        // cert_0 is the root — already cached at CertManager deploy, but we
        // still call verifyCACert so the on-chain hash chain is consistent.
        // Parent of cert_0 is ROOT_CA_CERT_HASH (hardcoded in CertManager).
        console2.log("Verifying cert_0 (root re-verify)...");
        certManager.verifyCACert(cert0, ROOT_CA_CERT_HASH);

        console2.log("Verifying cert_1 (intermediate)...");
        certManager.verifyCACert(cert1, hash0);

        console2.log("Verifying cert_2 (regional)...");
        certManager.verifyCACert(cert2, hash1);

        console2.log("Verifying cert_3 (zonal)...");
        certManager.verifyCACert(cert3, hash2);

        // Step 2: Verify leaf/client cert
        console2.log("Verifying leaf cert...");
        certManager.verifyClientCert(leafCert, hash3);

        // Step 3: Register the TEE instance (~18M gas with warm certs)
        console2.log("Registering Nitro TEE instance...");
        uint256 id = registry.register(TEEType.NITRO, attestation);
        console2.log("Registered with ID:", id);

        vm.stopBroadcast();
    }
}
