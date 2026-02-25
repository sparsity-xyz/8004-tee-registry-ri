// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TEERegistry, TEEType} from "../src/TEERegistry.sol";
import {DCAPVerifier} from "../src/DCAPVerifier.sol";
import {MockNitroVerifier} from "../src/NitroVerifier.sol";

contract Deploy is Script {
    function run() external {
        // AUTOMATA_ATTESTATION: address of Automata's on-chain DCAP verifier.
        // On testnets/local, deploy a mock. On mainnet, use the real deployment.
        address automataAddr = vm.envAddress("AUTOMATA_ATTESTATION");

        vm.startBroadcast();

        // 1. Deploy verifiers
        DCAPVerifier dcap = new DCAPVerifier(automataAddr);
        MockNitroVerifier nitro = new MockNitroVerifier();

        // 2. Deploy registry
        TEERegistry registry = new TEERegistry();

        // 3. Wire verifiers
        registry.setVerifier(TEEType.TDX, address(dcap));
        registry.setVerifier(TEEType.NITRO, address(nitro));

        vm.stopBroadcast();

        console2.log("DCAPVerifier:", address(dcap));
        console2.log("MockNitroVerifier:", address(nitro));
        console2.log("TEERegistry:", address(registry));
    }
}
