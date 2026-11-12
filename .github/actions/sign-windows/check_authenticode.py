#!/usr/bin/env python3
"""Fail unless a PE file carries a timestamped Authenticode signature.

Usage: check_authenticode.py <file.exe> [<signature.der>]

Reads the PE certificate table (data directory 4). Exits 1 when it is empty,
when it does not hold a PKCS#7 SignedData, or when the signature has no
timestamp counter-signature. With a second argument, writes the PKCS#7 blob
there so `openssl pkcs7 -inform DER -print_certs` can show the signer.
"""
import struct
import sys

WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

# DER-encoded OIDs of the timestamp counter-signatures Authenticode uses.
TIMESTAMP_OIDS = {
    "RFC 3161 (1.3.6.1.4.1.311.3.3.1)": bytes.fromhex("060a2b060104018237030301"),
    "RFC 3161 token (1.2.840.113549.1.9.16.2.14)": bytes.fromhex("060b2a864886f70d010910020e"),
    "PKCS#9 countersignature (1.2.840.113549.1.9.6)": bytes.fromhex("06092a864886f70d010906"),
}


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def main():
    if len(sys.argv) not in (2, 3):
        fail("usage: check_authenticode.py <file.exe> [<signature.der>]")
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        fail(f"{path}: not a PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        fail(f"{path}: not a PE file")
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    data_dirs = pe + 24 + (112 if magic == 0x20B else 96)
    offset, size = struct.unpack_from("<II", data, data_dirs + 8 * 4)

    if size == 0:
        fail(f"{path}: no Authenticode signature (empty certificate table)")
    if offset + size > len(data) or size < 8:
        fail(f"{path}: certificate table out of bounds")
    length, _revision, cert_type = struct.unpack_from("<IHH", data, offset)
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        fail(f"{path}: certificate table entry is type {cert_type:#x}, not PKCS#7 SignedData")
    blob = data[offset + 8:offset + length]

    found = [name for name, oid in TIMESTAMP_OIDS.items() if oid in blob]
    if not found:
        fail(f"{path}: Authenticode signature has no timestamp")

    if len(sys.argv) == 3:
        with open(sys.argv[2], "wb") as f:
            f.write(blob)
    print(f"{path}: signed, {len(blob)} byte signature, timestamp: {', '.join(found)}")


if __name__ == "__main__":
    main()
