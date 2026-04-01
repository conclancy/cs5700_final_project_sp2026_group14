"""
PSK Security Module

This module implements:
1. HMAC authentication for handshake messages
2. Key derivation using HKDF-SHA256
3. Random nonce generation

Used during the secure session establishment phase.
"""

import os
import hmac
import hashlib
from config import PSK


def generate_nonce(length: int) -> bytes:
    """
    Generate cryptographically secure random nonce.

    Args:
        length: number of random bytes

    Returns:
        random byte string
    """
    return os.urandom(length)


def compute_hmac(data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 using the pre-shared key.

    Used to authenticate handshake messages between client and server.

    Args:
        data: message bytes

    Returns:
        32-byte HMAC digest
    """
    return hmac.new(PSK, data, hashlib.sha256).digest()


def verify_hmac(data: bytes, received_hmac: bytes) -> bool:
    """
    Verify HMAC of received message using constant-time comparison.

    Args:
        data: original message data
        received_hmac: HMAC attached to the message

    Returns:
        True if valid, False otherwise
    """
    expected = compute_hmac(data)
    return hmac.compare_digest(expected, received_hmac)


def hkdf_extract_expand(client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """
    Derive session encryption keys using HKDF-SHA256.

    Produces two independent 32-byte keys from the PSK and handshake nonces:
      - enc_key:  used for AEAD encryption/decryption of DATA and ACK packets
      - ack_key:  used to authenticate ACK-only packets (optional but prepared)

    Both sides run this independently with the same inputs and get the same keys.

    Args:
        client_nonce: 16-byte random value from client
        server_nonce: 16-byte random value from server

    Returns:
        (enc_key, ack_key) — each 32 bytes
    """
    # Input key material: combine both nonces
    ikm = client_nonce + server_nonce

    # Extract step: PRK = HMAC-SHA256(salt=PSK, ikm=nonces)
    prk = hmac.new(PSK, ikm, hashlib.sha256).digest()

    # Expand step for enc_key (counter = 0x01)
    enc_info = b"SRFT enc key"
    enc_key = hmac.new(prk, enc_info + b"\x01", hashlib.sha256).digest()[:32]

    # Expand step for ack_key (counter = 0x02, different info string)
    ack_info = b"SRFT ack key"
    ack_key = hmac.new(prk, ack_info + b"\x02", hashlib.sha256).digest()[:32]

    return enc_key, ack_key