# EIP-8004 TEE Registry — Reference Implementation

Minimal on-chain registry for TEE attestation verification. Three contracts, real on-chain verification for both Intel TDX and AWS Nitro.

## Architecture

```
                    ┌──────────────────┐
                    │   TEERegistry    │
                    │                  │
                    │  register()      │
                    │  revoke()        │
                    │  getEntry()      │
                    │  getByMeasure()  │
                    └──────┬───────────┘
                           │
              ┌────────────┼────────────┐
              │                         │
     ┌────────▼─────────┐    ┌─────────▼──────────┐
     │  DCAPVerifier     │    │  NitroVerifier      │
     │  (Intel TDX/SGX)  │    │  (AWS Nitro)        │
     └────────┬──────────┘    └────────┬────────────┘
              │                        │
     ┌────────▼──────────┐    ┌────────▼────────────┐
     │  Automata DCAP    │    │  NitroValidator      │
     │  (on-chain)       │    │  + CertManager       │
     └───────────────────┘    └─────────────────────┘
```

**TEERegistry** stores TEE identities and delegates attestation verification to platform-specific verifiers via the `IVerifier` interface.

**DCAPVerifier** wraps [Automata's on-chain DCAP verifier](https://github.com/automata-network/automata-dcap-v3-attestation) for Intel TDX/SGX attestation. Gas cost: ~4-5M per verification.

**NitroVerifier** wraps [base/nitro-validator](https://github.com/base/nitro-validator) for AWS Nitro Enclaves. Full on-chain COSE_Sign1 parsing, X.509 cert chain validation, and ECDSA-384 signature verification. Gas cost: ~63M per verification (fits within Base L2 block gas limit of 150M).

## Build & Test

```bash
# Install dependencies
forge install

# Build
forge build

# Test (uses real Nitro attestation data)
forge test -vvv
```

## Deploy

```bash
# Set the Automata DCAP verifier address
export AUTOMATA_ATTESTATION=0x...

forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast
```

## E2E Demo Walkthrough

1. **Deploy** the registry + verifiers (via `Deploy.s.sol`)
2. **Register a TDX enclave**: call `registry.register(TEEType.TDX, rawDCAPQuote)` — the DCAP verifier parses the quote, extracts `mrEnclave`/`mrSigner`, and stores keccak256(mrEnclave || mrSigner) as the code measurement
3. **Register a Nitro enclave**: call `registry.register(TEEType.NITRO, rawCOSE_Sign1)` — the Nitro verifier validates the full attestation, extracts PCR0/1/2, and stores keccak256(pcr0 || pcr1 || pcr2)
4. **Look up by measurement**: `registry.getByMeasurement(codeMeasurement)` returns the full entry
5. **Revoke**: owner or admin calls `registry.revoke(id, "reason")`

## IVerifier Interface

```solidity
interface IVerifier {
    function verify(bytes calldata attestation)
        external
        returns (bytes32 codeMeasurement);
}
```

Any TEE platform can be supported by implementing this interface and calling `registry.setVerifier(teeType, verifierAddress)`.

## Relationship to EIP-8004

This is the reference implementation for the EIP-8004 TEE Registry specification. It demonstrates the minimal viable on-chain attestation verification flow without proxies, governance, ZK proofs, or upgradability — per the spec committee's requirements.

## License

MIT
