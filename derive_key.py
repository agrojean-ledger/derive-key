"""
Derives an ED25519 key from a seed via BIP32/SLIP-10 and computes the Canton party ID.

Usage:
    python derive_key.py --seed <hex_seed> --path "m/44'/919'/0'/0'/0'"
"""

import argparse
import hashlib

from bip_utils import Bip32Slip10Ed25519
from typing import Tuple

PURPOSE_PUBLIC_KEY_FINGERPRINT = 12
PARTY_PREFIX = "participant1"


def canton_hash(purpose: int, content: bytes) -> bytes:
    prefix = purpose.to_bytes(4, byteorder="big")
    digest = hashlib.sha256(prefix + content).digest()
    return bytes([0x12, 0x20]) + digest


def derive(seed_hex: str, path: str) -> Tuple[bytes, bytes]:
    seed = bytes.fromhex(seed_hex)
    derived = Bip32Slip10Ed25519.FromSeed(seed).DerivePath(path)
    private_key = derived.PrivateKey().Raw().ToBytes()
    public_key = derived.PublicKey().RawCompressed().ToBytes()[1:]  # strip 0x00 prefix → 32 bytes
    return private_key, public_key


def party_id(public_key: bytes) -> str:
    fingerprint = canton_hash(PURPOSE_PUBLIC_KEY_FINGERPRINT, public_key).hex()
    return f"{PARTY_PREFIX}::{fingerprint}"


def main():
    parser = argparse.ArgumentParser(description="Derive ED25519 key and compute Canton party ID")
    parser.add_argument("--seed", required=True, help="Hex-encoded seed")
    parser.add_argument("--path", required=True, help="BIP32 derivation path, e.g. m/44'/919'/0'/0'/0'")
    args = parser.parse_args()

    private_key, public_key = derive(args.seed, args.path)
    pid = party_id(public_key)

    print(f"private_key : {private_key.hex()}")
    print(f"party_id    : {pid}")


if __name__ == "__main__":
    main()
