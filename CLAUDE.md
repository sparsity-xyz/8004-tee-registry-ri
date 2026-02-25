# EIP-8004 TEE Registry — Reference Implementation

## What This Is
Minimal on-chain TEE attestation registry for the EIP-8004 spec. Supports Intel TDX (via Automata DCAP) and AWS Nitro (via base/nitro-validator). Three source files. No proxies, no governance, no ZK.

## Architecture
```
TEERegistry.sol    — Main registry. Stores TEE entries, calls platform-specific verifiers.
DCAPVerifier.sol   — Intel TDX/SGX verifier. Wraps Automata's on-chain DCAP verification.
NitroVerifier.sol  — AWS Nitro verifier. Wraps base/nitro-validator (CBOR + X.509 + ECDSA-384).
```

All verifiers implement `IVerifier.verify(bytes attestation) → (bytes32 codeMeasurement, bytes pubKey, bytes userData)`.

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
- Nitro verification (cold, no cached certs): ~56M gas
- Nitro verification (warm, certs pre-verified): ~18M gas

### Nitro Cert-Splitting Strategy
The ~56M cold cost comes from verifying 4 CA certs + 1 client cert via ECDSA-384. Each costs ~9.5M gas individually. Pre-verify certs in separate transactions by calling `CertManager.verifyCACert` for each cert in the cabundle, then the final `validateAttestation` call uses cached certs and fits under 25M.

```
CA cert 0 (root):        ~9K gas     (cached at CertManager deploy)
CA cert 1 (intermediate): ~9.5M gas  (ECDSA-384)
CA cert 2 (regional):     ~9.8M gas  (ECDSA-384)
CA cert 3 (zonal):        ~9.5M gas  (ECDSA-384)
Client cert (leaf):       ~9.5M gas  (ECDSA-384)
Final validateAttestation: ~18M gas  (warm — all certs cached)
```

## L2 Deployment Compatibility
- **Base**: block 375M, per-tx 25M — split certs across transactions, each fits under 25M
- **Arbitrum One**: block 32M, per-tx same — same splitting strategy
- **OP Mainnet**: block 30M — same splitting strategy
- **zkSync Era**: per-tx 80M — cold verification fits in a single transaction
- **Scroll**: block 10M — individual cert verification (~9.5M) barely fits, no headroom
- **Linea**: block 61M — cold verification fits, planned increase to 200M in 2026

## Solidity Version
0.8.24, Cancun EVM, optimizer on (200 runs)
