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

    This is used to authenticate handshake messages
    between the client and the server.

    Args:
        data: message bytes

    Returns:
        HMAC digest
    """

    return hmac.new(PSK, data, hashlib.sha256).digest()


def verify_hmac(data: bytes, received_hmac: bytes) -> bool:
    """
    Verify HMAC of received message.

    Args:
        data: original message data
        received_hmac: HMAC attached to the message

    Returns:
        True if valid, False otherwise
    """

    expected = compute_hmac(data)

    return hmac.compare_digest(expected, received_hmac)


def hkdf_extract_expand(client_nonce: bytes, server_nonce: bytes) -> bytes:
    """
    Derive a session encryption key using HKDF-SHA256.

    HKDF is used to derive a fresh session key from the
    long-term PSK and the handshake nonces.

    Args:
        client_nonce: random value from client
        server_nonce: random value from server

    Returns:
        32-byte encryption key
    """

    # Combine nonces as input key material
    ikm = client_nonce + server_nonce

    # Extract step
    prk = hmac.new(PSK, ikm, hashlib.sha256).digest()

    # Expand step
    info = b"SRFT session key"
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    # Return 32-byte encryption key
    return okm[:32]