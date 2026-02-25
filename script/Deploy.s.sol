// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TEERegistry, TEEType} from "../src/TEERegistry.sol";
import {DCAPVerifier} from "../src/DCAPVerifier.sol";
import {NitroVerifier} from "../src/NitroVerifier.sol";
import {NitroValidator} from "nitro-validator/NitroValidator.sol";
import {CertManager} from "nitro-validator/CertManager.sol";
import {ICertManager} from "nitro-validator/ICertManager.sol";

contract Deploy is Script {
    function run() external {
        // AUTOMATA_ATTESTATION: address of Automata's on-chain DCAP verifier.
        // On testnets/local, deploy a test instance. On mainnet, use the real deployment.
        address automataAddr = vm.envAddress("AUTOMATA_ATTESTATION");

        vm.startBroadcast();

        // 1. Deploy verifiers
        DCAPVerifier dcap = new DCAPVerifier(automataAddr);
        CertManager certManager = new CertManager();
        NitroValidator nitroValidator = new NitroValidator(ICertManager(address(certManager)));
        NitroVerifier nitro = new NitroVerifier(nitroValidator);

        // 2. Deploy registry
        TEERegistry registry = new TEERegistry();

        // 3. Wire verifiers
        registry.setVerifier(TEEType.TDX, address(dcap));
        registry.setVerifier(TEEType.NITRO, address(nitro));

        vm.stopBroadcast();

        console2.log("CertManager:", address(certManager));
        console2.log("NitroValidator:", address(nitroValidator));
        console2.log("NitroVerifier:", address(nitro));
        console2.log("DCAPVerifier:", address(dcap));
        console2.log("TEERegistry:", address(registry));
    }
}
