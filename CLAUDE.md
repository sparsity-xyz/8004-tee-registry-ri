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

Note: DCAP verifier is not deployed on Base Sepolia (no Automata DCAP deployment on that chain). Only Nitro is live there.

## Commands
```bash
forge build          # Compile
forge test -vvv      # Run tests with verbose output
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast  # Deploy

# Register a Nitro TEE instance (pre-warm certs + register):
#   1. Extract certs from attestation:
python3 script/extract_certs.py samples/attestation.bin samples/
#   2. Run register script (--skip-simulation required, see Register.s.sol):
forge script script/Register.s.sol --rpc-url base_sepolia --broadcast --skip-simulation --slow
```

## Key Files
- `src/TEERegistry.sol` — Registry contract + IVerifier interface
- `src/DCAPVerifier.sol` — DCAP verifier (real Automata integration)
- `src/NitroVerifier.sol` — Nitro verifier (real on-chain COSE_Sign1 validation)
- `test/TEERegistry.t.sol` — Full test suite (real Nitro attestation data)
- `script/Deploy.s.sol` — Deployment script
- `script/Register.s.sol` — Pre-warm CA certs + register TEE instance
- `script/extract_certs.py` — Extract cert chain from COSE_Sign1 attestation (requires `cbor2`, `pycryptodome`)
- `samples/deployment.json` — Base Sepolia deployed addresses
- `samples/pcr_values.json` — PCR values and code measurement for test attestation

## Dependencies
- forge-std (testing)
- openzeppelin-contracts (Ownable)
- automata-dcap-v3-attestation (Intel DCAP verification)
- nitro-validator (AWS Nitro attestation: CBOR parsing, ASN.1 certs, ECDSA-384)

## CBOR Fix (nitro-validator patch)
Real AWS Nitro attestation documents use **indefinite-length CBOR maps** (`0xBF` major type 5, additional info 31), which the upstream `nitro-validator` library did not support. Two files were patched in `lib/nitro-validator/src/`:

- **`CborDecode.sol`**: Added handling for `ai == 31` (indefinite-length) — returns element with count 0 and advances past the marker byte.
- **`NitroValidator.sol`**: Added break-marker detection (`0xFF`) in the attestation map parsing loop to terminate indefinite-length map iteration.

Without this fix, real Nitro attestations revert with "unsupported type" during CBOR decoding.

## Gas
- DCAP verification: ~4-5M gas
- Nitro verification (cold, no cached certs): ~56M gas
- Nitro verification (warm, all certs pre-verified): ~18.6M gas

### Nitro Cert-Splitting Strategy
The ~56M cold cost comes from verifying 3 CA certs + 1 leaf cert via ECDSA-384 (root is pre-cached at CertManager deploy). Each ECDSA-384 verification costs ~9.5M gas individually. Pre-verify certs in separate transactions by calling `CertManager.verifyCACert` / `verifyClientCert` for each cert, then the final `validateAttestation` call uses cached certs and fits under 25M.

All 5 certs must be pre-warmed (including re-verifying cert_0 to establish the on-chain hash chain):

```
CA cert 0 (root re-verify):  ~9K gas     (already cached, but needed for hash chain)
CA cert 1 (intermediate):    ~9.5M gas   (ECDSA-384)
CA cert 2 (regional):        ~9.8M gas   (ECDSA-384)
CA cert 3 (zonal):           ~9.5M gas   (ECDSA-384)
Leaf cert (client):          ~9.5M gas   (ECDSA-384)
Final validateAttestation:   ~18.6M gas  (warm — all certs cached)
```

**Important:** `--skip-simulation` is required when running `Register.s.sol` via `forge script`. Local simulation hangs because forge tries to `eth_call` all ECDSA-384 verifications before broadcasting, causing RPC timeouts.

## Base Sepolia Deployment
```
CertManager:    0xE5578D3c9006CC13A4D728017B9f0CC2C72027bD
NitroValidator: 0xa43F92EFC31A1be47D7B4D14d93e21c7BC2780AF
NitroVerifier:  0x3ba859a2592C585b010d9647c193F06755E8Cc18
TEERegistry:    0xf08d07b09C33535dcc4C3Bae04ccC5466e9297EE
```

Attestation endpoint: `https://317.fxrmas.sparsity.cloud/.well-known/attestation`

Registered entry ID 1, code measurement: `0xe770a284...93100545` ([tx](https://sepolia.basescan.org/tx/0x887adc15bda6b6fb8856d5f036a49690d6beb72871f52d171da9deb737c296fa))

## L2 Deployment Compatibility
- **Base**: block 375M, per-tx 25M — split certs across transactions, each fits under 25M
- **Arbitrum One**: block 32M, per-tx same — same splitting strategy
- **OP Mainnet**: block 30M — same splitting strategy
- **zkSync Era**: per-tx 80M — cold verification fits in a single transaction
- **Scroll**: block 10M — individual cert verification (~9.5M) barely fits, no headroom
- **Linea**: block 61M — cold verification fits, planned increase to 200M in 2026

## Solidity Version
0.8.24, Cancun EVM, optimizer on (200 runs)
