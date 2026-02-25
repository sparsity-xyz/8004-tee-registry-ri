# EIP-8004 TEE Registry — Reference Implementation

## What This Is
Minimal on-chain TEE attestation registry for the EIP-8004 spec. Supports Intel TDX (via Automata DCAP) and AWS Nitro (mock). Three source files, ~260 lines of Solidity. No proxies, no governance, no ZK.

## Architecture
```
TEERegistry.sol    — Main registry. Stores TEE entries, calls platform-specific verifiers.
DCAPVerifier.sol   — Intel TDX/SGX verifier. Wraps Automata's on-chain DCAP verification.
NitroVerifier.sol  — Mock Nitro verifier. Decodes abi.encode(measurement, wallet).
```

All verifiers implement `IVerifier.verify(bytes attestation) → (bytes32 codeMeasurement, address teeWallet)`.

## Commands
```bash
forge build          # Compile
forge test -vvv      # Run tests with verbose output
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast  # Deploy
```

## Key Files
- `src/TEERegistry.sol` — Registry contract + IVerifier interface
- `src/DCAPVerifier.sol` — DCAP verifier (real Automata integration)
- `src/NitroVerifier.sol` — Mock Nitro verifier
- `test/TEERegistry.t.sol` — Full test suite
- `script/Deploy.s.sol` — Deployment script

## Dependencies
- forge-std (testing)
- openzeppelin-contracts (Ownable)
- automata-dcap-v3-attestation (Intel DCAP verification)

## Solidity Version
0.8.24, Cancun EVM, optimizer on (200 runs)
