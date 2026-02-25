// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {TEERegistry, TEEEntry, TEEType, IVerifier} from "../src/TEERegistry.sol";
import {DCAPVerifier} from "../src/DCAPVerifier.sol";
import {MockNitroVerifier} from "../src/NitroVerifier.sol";
import {IAttestation} from "@automata-network/dcap-attestation/interfaces/IAttestation.sol";

/// @dev Mock Automata attestation that returns configurable output bytes.
/// Output layout: uint8 tcbStatus ++ bytes32 mrEnclave ++ bytes32 mrSigner ++ bytes64 reportData
contract MockAutomataAttestation is IAttestation {
    bytes public outputToReturn;

    function setOutput(bytes memory _output) external {
        outputToReturn = _output;
    }

    function buildOutput(
        uint8 tcbStatus,
        bytes32 mrEnclave,
        bytes32 mrSigner,
        address teeWallet
    ) external {
        // 1 + 32 + 32 + 64 = 129 bytes
        bytes memory out = new bytes(129);
        out[0] = bytes1(tcbStatus);
        assembly {
            // out data starts at out + 32
            mstore(add(add(out, 32), 1), mrEnclave)
            mstore(add(add(out, 32), 33), mrSigner)
            // Store teeWallet as first 20 bytes of reportData (offset 65)
            // Shift left by 96 bits to put address in top 20 bytes
            mstore(add(add(out, 32), 65), shl(96, teeWallet))
        }
        outputToReturn = out;
    }

    function verifyAndAttestOnChain(bytes calldata) external view override returns (bytes memory) {
        require(outputToReturn.length > 0, "MockAutomata: output not set");
        return outputToReturn;
    }

    function verifyAndAttestWithZKProof(bytes calldata, bytes calldata) external view override returns (bytes memory) {
        return outputToReturn;
    }
}

contract TEERegistryTest is Test {
    TEERegistry public registry;
    DCAPVerifier public dcapVerifier;
    MockNitroVerifier public nitroVerifier;
    MockAutomataAttestation public mockAutomata;

    bytes32 constant MR_ENCLAVE = keccak256("test-enclave-code-v1");
    bytes32 constant MR_SIGNER = keccak256("test-signer-key");
    address constant TEE_WALLET = address(0xBEEF);

    address admin = address(this);
    address user1 = address(0x1);
    address user2 = address(0x2);

    function setUp() public {
        // Deploy contracts
        registry = new TEERegistry();
        mockAutomata = new MockAutomataAttestation();
        dcapVerifier = new DCAPVerifier(address(mockAutomata));
        nitroVerifier = new MockNitroVerifier();

        // Wire verifiers
        registry.setVerifier(TEEType.TDX, address(dcapVerifier));
        registry.setVerifier(TEEType.NITRO, address(nitroVerifier));
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    function _setupMockDCAP(bytes32 mrEnclave, bytes32 mrSigner, address wallet) internal {
        mockAutomata.buildOutput(0, mrEnclave, mrSigner, wallet);
    }

    function _nitroAttestation(bytes32 measurement, address wallet) internal pure returns (bytes memory) {
        return abi.encode(measurement, wallet);
    }

    // ── Registration: TDX ───────────────────────────────────────────────

    function test_RegisterTDX() public {
        _setupMockDCAP(MR_ENCLAVE, MR_SIGNER, TEE_WALLET);

        vm.prank(user1);
        uint256 id = registry.register(TEEType.TDX, hex"deadbeef");

        assertEq(id, 1);

        TEEEntry memory entry = registry.getEntry(id);
        assertEq(entry.owner, user1);
        assertTrue(entry.teeType == TEEType.TDX);
        assertEq(entry.codeMeasurement, keccak256(abi.encodePacked(MR_ENCLAVE, MR_SIGNER)));
        assertEq(entry.teeWallet, TEE_WALLET);
        assertTrue(entry.active);
        assertEq(entry.attestedAt, block.timestamp);
    }

    // ── Registration: Nitro ─────────────────────────────────────────────

    function test_RegisterNitro() public {
        bytes32 measurement = keccak256("nitro-code-hash");
        address wallet = address(0xCAFE);

        vm.prank(user1);
        uint256 id = registry.register(TEEType.NITRO, _nitroAttestation(measurement, wallet));

        assertEq(id, 1);

        TEEEntry memory entry = registry.getEntry(id);
        assertEq(entry.owner, user1);
        assertTrue(entry.teeType == TEEType.NITRO);
        assertEq(entry.codeMeasurement, measurement);
        assertEq(entry.teeWallet, wallet);
        assertTrue(entry.active);
    }

    // ── Reverse Lookups ─────────────────────────────────────────────────

    function test_LookupByWallet() public {
        bytes32 measurement = keccak256("lookup-test");
        address wallet = address(0xFACE);

        vm.prank(user1);
        uint256 expectedId = registry.register(TEEType.NITRO, _nitroAttestation(measurement, wallet));

        (uint256 id, TEEEntry memory entry) = registry.getByWallet(wallet);
        assertEq(id, expectedId);
        assertEq(entry.teeWallet, wallet);
        assertEq(entry.codeMeasurement, measurement);
    }

    function test_LookupByMeasurement() public {
        bytes32 measurement = keccak256("measurement-lookup");
        address wallet = address(0xDAD);

        vm.prank(user1);
        uint256 expectedId = registry.register(TEEType.NITRO, _nitroAttestation(measurement, wallet));

        (uint256 id, TEEEntry memory entry) = registry.getByMeasurement(measurement);
        assertEq(id, expectedId);
        assertEq(entry.codeMeasurement, measurement);
        assertEq(entry.teeWallet, wallet);
    }

    // ── Revocation ──────────────────────────────────────────────────────

    function test_RevokeBySelf() public {
        vm.prank(user1);
        uint256 id = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("revoke-self"), address(0xA1)));

        assertTrue(registry.isActive(id));

        vm.prank(user1);
        registry.revoke(id, "compromised");

        assertFalse(registry.isActive(id));
    }

    function test_RevokeByAdmin() public {
        vm.prank(user1);
        uint256 id = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("revoke-admin"), address(0xA2)));

        // Admin (this contract) revokes
        registry.revoke(id, "admin override");

        assertFalse(registry.isActive(id));
    }

    // ── Error Paths ─────────────────────────────────────────────────────

    function test_RevertDuplicateWallet() public {
        bytes32 m1 = keccak256("first");
        bytes32 m2 = keccak256("second");
        address wallet = address(0xDEAD);

        vm.prank(user1);
        registry.register(TEEType.NITRO, _nitroAttestation(m1, wallet));

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(TEERegistry.WalletAlreadyRegistered.selector, wallet));
        registry.register(TEEType.NITRO, _nitroAttestation(m2, wallet));
    }

    function test_RevertDuplicateMeasurement() public {
        bytes32 measurement = keccak256("same-code");
        address w1 = address(0xAA);
        address w2 = address(0xBB);

        vm.prank(user1);
        registry.register(TEEType.NITRO, _nitroAttestation(measurement, w1));

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(TEERegistry.MeasurementAlreadyRegistered.selector, measurement));
        registry.register(TEEType.NITRO, _nitroAttestation(measurement, w2));
    }

    function test_RevertUnconfiguredVerifier() public {
        // Deploy a fresh registry with no verifiers set
        TEERegistry freshRegistry = new TEERegistry();

        vm.expectRevert(abi.encodeWithSelector(TEERegistry.VerifierNotConfigured.selector, TEEType.TDX));
        freshRegistry.register(TEEType.TDX, hex"aabb");
    }

    function test_SetVerifierOnlyOwner() public {
        vm.prank(user1);
        vm.expectRevert();
        registry.setVerifier(TEEType.TDX, address(0x999));
    }

    function test_RevertRevokeByStranger() public {
        vm.prank(user1);
        uint256 id = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("stranger"), address(0xCC)));

        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(TEERegistry.NotEntryOwnerOrAdmin.selector, id));
        registry.revoke(id, "unauthorized");
    }

    function test_RevertRevokeInactive() public {
        vm.prank(user1);
        uint256 id = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("inactive"), address(0xDD)));

        registry.revoke(id, "first revoke");

        vm.expectRevert(abi.encodeWithSelector(TEERegistry.EntryNotActive.selector, id));
        registry.revoke(id, "double revoke");
    }

    // ── Multiple Registrations ──────────────────────────────────────────

    function test_MultipleRegistrations() public {
        vm.prank(user1);
        uint256 id1 = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("code-1"), address(0x10)));

        vm.prank(user2);
        uint256 id2 = registry.register(TEEType.NITRO, _nitroAttestation(keccak256("code-2"), address(0x20)));

        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(registry.nextId(), 3);

        assertTrue(registry.isActive(id1));
        assertTrue(registry.isActive(id2));
    }
}
