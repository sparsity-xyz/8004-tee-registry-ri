# EIP-8004 TEE Registry — Reference Implementation

Minimal on-chain registry for TEE attestation verification. Three contracts, ~260 lines of Solidity.

## Architecture

```
                    ┌──────────────────┐
                    │   TEERegistry    │
                    │                  │
                    │  register()      │
                    │  revoke()        │
                    │  getEntry()      │
                    │  getByWallet()   │
                    │  getByMeasure()  │
                    └──────┬───────────┘
                           │
              ┌────────────┼────────────┐
              │                         │
     ┌────────▼─────────┐    ┌─────────▼──────────┐
     │  DCAPVerifier     │    │  MockNitroVerifier  │
     │  (Intel TDX/SGX)  │    │  (AWS Nitro stub)   │
     └────────┬──────────┘    └────────────────────┘
              │
     ┌────────▼──────────┐
     │  Automata DCAP    │
     │  (on-chain)       │
     └───────────────────┘
```

**TEERegistry** stores TEE identities and delegates attestation verification to platform-specific verifiers via the `IVerifier` interface.

**DCAPVerifier** wraps [Automata's on-chain DCAP verifier](https://github.com/automata-network/automata-dcap-v3-attestation) for Intel TDX/SGX attestation. Gas cost: ~4-5M per verification.

**MockNitroVerifier** is a stub for AWS Nitro Enclaves. Real on-chain Nitro verification exists but costs ~63M gas (exceeds block limits). Swap in a real verifier when gas-feasible.

## Build & Test

```bash
# Install dependencies (if not already)
forge install

# Build
forge build

# Test
forge test -vvv
```

## Deploy

```bash
# Set the Automata DCAP verifier address (deploy a mock for testnets)
export AUTOMATA_ATTESTATION=0x...

forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast
```

## E2E Demo Walkthrough

1. **Deploy** the registry + verifiers (via `Deploy.s.sol`)
2. **Register a TDX enclave**: call `registry.register(TEEType.TDX, rawDCAPQuote)` — the DCAP verifier parses the quote, extracts `mrEnclave`/`mrSigner`/`teeWallet`, and stores the entry
3. **Register a Nitro enclave**: call `registry.register(TEEType.NITRO, abi.encode(measurement, wallet))`
4. **Look up by wallet**: `registry.getByWallet(teeWallet)` returns the full entry
5. **Revoke**: owner or admin calls `registry.revoke(id, "reason")`

## IVerifier Interface

```solidity
interface IVerifier {
    function verify(bytes calldata attestation)
        external
        returns (bytes32 codeMeasurement, address teeWallet);
}
```

Any TEE platform can be supported by implementing this interface and calling `registry.setVerifier(teeType, verifierAddress)`.

## Relationship to EIP-8004

This is the reference implementation for the EIP-8004 TEE Registry specification. It demonstrates the minimal viable on-chain attestation verification flow without proxies, governance, ZK proofs, or upgradability — per the spec committee's requirements.

## License

MIT
