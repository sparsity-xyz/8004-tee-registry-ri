#!/usr/bin/env python3
"""Extract CA certificate chain from a Nitro COSE_Sign1 attestation document.

Usage: python3 extract_certs.py <attestation.bin> <output_dir>

Outputs:
  cert_0.bin  — root CA cert (already cached in CertManager constructor)
  cert_1.bin  — intermediate CA cert
  cert_2.bin  — regional CA cert
  cert_3.bin  — zonal CA cert
  leaf_cert.bin — client/leaf cert
"""

import sys
import os

import cbor2
from Crypto.Hash import keccak


def keccak256(data: bytes) -> str:
    """Compute Keccak-256 (Ethereum-compatible, NOT FIPS SHA3-256)."""
    k = keccak.new(digest_bits=256)
    k.update(data)
    return "0x" + k.hexdigest()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <attestation.bin> <output_dir>")
        sys.exit(1)

    attestation_path = sys.argv[1]
    output_dir = sys.argv[2]

    with open(attestation_path, "rb") as f:
        raw = f.read()

    # COSE_Sign1 = CBOR tag 18 wrapping [protected, unprotected, payload, signature]
    cose = cbor2.loads(raw)
    if hasattr(cose, "tag") and cose.tag == 18:
        cose_array = cose.value
    elif isinstance(cose, list) and len(cose) == 4:
        cose_array = cose
    else:
        print("Error: not a valid COSE_Sign1 structure")
        sys.exit(1)

    payload = cbor2.loads(cose_array[2])

    cabundle = payload["cabundle"]
    leaf_cert = payload["certificate"]

    print(f"Found {len(cabundle)} CA certs + 1 leaf cert")

    os.makedirs(output_dir, exist_ok=True)

    # Write CA certs
    for i, cert_bytes in enumerate(cabundle):
        out_path = os.path.join(output_dir, f"cert_{i}.bin")
        with open(out_path, "wb") as f:
            f.write(cert_bytes)
        cert_hash = keccak256(cert_bytes)
        print(f"  cert_{i}.bin  ({len(cert_bytes)} bytes)  keccak256={cert_hash}")

    # Write leaf cert
    leaf_path = os.path.join(output_dir, "leaf_cert.bin")
    with open(leaf_path, "wb") as f:
        f.write(leaf_cert)
    leaf_hash = keccak256(leaf_cert)
    print(f"  leaf_cert.bin ({len(leaf_cert)} bytes)  keccak256={leaf_hash}")

    # Print PCR values if present
    pcrs = payload.get("pcrs", {})
    for idx in sorted(pcrs.keys()):
        print(f"  PCR{idx}: {pcrs[idx].hex()}")


if __name__ == "__main__":
    main()
