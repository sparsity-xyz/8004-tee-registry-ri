// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TEERegistry, TEEType} from "../src/TEERegistry.sol";
import {NitroVerifier} from "../src/NitroVerifier.sol";
import {NitroValidator} from "nitro-validator/NitroValidator.sol";
import {CertManager} from "nitro-validator/CertManager.sol";
import {ICertManager} from "nitro-validator/ICertManager.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy Nitro verifier stack
        CertManager certManager = new CertManager();
        NitroValidator nitroValidator = new NitroValidator(ICertManager(address(certManager)));
        NitroVerifier nitro = new NitroVerifier(nitroValidator);

        // 2. Deploy registry
        TEERegistry registry = new TEERegistry();

        // 3. Wire Nitro verifier (DCAP/TDX skipped — no Automata deployment on Base Sepolia)
        registry.setVerifier(TEEType.NITRO, address(nitro));

        vm.stopBroadcast();

        console2.log("CertManager:", address(certManager));
        console2.log("NitroValidator:", address(nitroValidator));
        console2.log("NitroVerifier:", address(nitro));
        console2.log("TEERegistry:", address(registry));
    }
}
