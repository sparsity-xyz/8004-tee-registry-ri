# EIP-8004 TEE Registry — Reference Implementation

## What This Is
Minimal on-chain TEE attestation registry for the EIP-8004 spec. Supports Intel TDX (via Automata DCAP) and AWS Nitro (via base/nitro-validator). Three source files. No proxies, no governance, no ZK.

## Architecture
```
TEERegistry.sol    — Main registry. Stores TEE entries, calls platform-specific verifiers.
DCAPVerifier.sol   — Intel TDX/SGX verifier. Wraps Automata's on-chain DCAP verification.
NitroVerifier.sol  — AWS Nitro verifier. Wraps base/nitro-validator (CBOR + X.509 + ECDSA-384).
```

All verifiers implement `IVerifier.verify(bytes attestation) → bytes32 codeMeasurement`.

## Commands
```bash
forge build          # Compile
forge test -vvv      # Run tests with verbose output
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast  # Deploy
```

## Key Files
- `src/TEERegistry.sol` — Registry contract + IVerifier interface
- `src/DCAPVerifier.sol` — DCAP verifier (real Automata integration)
- `src/NitroVerifier.sol` — Nitro verifier (real on-chain COSE_Sign1 validation)
- `test/TEERegistry.t.sol` — Full test suite (real Nitro attestation data)
- `script/Deploy.s.sol` — Deployment script

## Dependencies
- forge-std (testing)
- openzeppelin-contracts (Ownable)
- automata-dcap-v3-attestation (Intel DCAP verification)
- nitro-validator (AWS Nitro attestation: CBOR parsing, ASN.1 certs, ECDSA-384)

## Gas
- DCAP verification: ~4-5M gas
- Nitro verification: ~63M gas
- gas_limit set to 150M (Base L2 block limit)

## Solidity Version
0.8.24, Cancun EVM, optimizer on (200 runs)
