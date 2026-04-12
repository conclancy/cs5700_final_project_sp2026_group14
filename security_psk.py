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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


def hkdf_extract_expand(client_nonce: bytes, server_nonce: bytes) -> tuple:
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
    enc_key = hmac.new(prk, b"SRFT enc key" + b"\x01", hashlib.sha256).digest()[:32]
    ack_key = hmac.new(prk, b"SRFT ack key" + b"\x02", hashlib.sha256).digest()[:32]

    return enc_key, ack_key


# Key must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256).
# This expects a pre-derived key (bytes), not a password.

def _build_associated_data(
    session_id: bytes,
    seq_num: int,
    flags: int,
    ack_num: int = 0,
) -> bytes:
    """
    Encode the fields that are authenticated but not encrypted.

    Layout: session_id (N bytes) | seq_num (4B) | ack_num (4B) | flags (1B)

    Args:
        session_id:  Unique identifier for this session (bytes).
        seq_num:     SRFT sequence number.
        flags:       SRFT flags byte (FLAG_DATA, FLAG_ACK, etc.).
        ack_num:     SRFT ack number (0 if not present).

    Returns:
        Packed bytes suitable for use as GCM associated_data.
    """
    import struct
    return session_id + struct.pack("!IIB", seq_num, ack_num, flags)


def encrypt(
    data: bytes,
    key: bytes,
    session_id: bytes,
    seq_num: int,
    flags: int,
    ack_num: int = 0,
) -> bytes:
    """
    Encrypt and authenticate `data` using AES-256-GCM.

    The session_id, seq_num, ack_num, and flags are included as GCM
    associated data — they are authenticated by the tag but not encrypted,
    so the receiver can verify none of these fields were tampered with.

    Args:
        data:        Plaintext payload bytes.
        key:         32-byte session key from hkdf_extract_expand().
        session_id:  Unique session identifier bytes.
        seq_num:     SRFT sequence number for this packet.
        flags:       SRFT flags byte for this packet.
        ack_num:     SRFT ack number (default 0 if not present).

    Returns:
        nonce (12 B) || ciphertext || GCM tag (16 B)
    """
    nonce = os.urandom(12)
    ad    = _build_associated_data(session_id, seq_num, flags, ack_num)
    ciphertext = AESGCM(key).encrypt(nonce, data, associated_data=ad)
    return nonce + ciphertext


def decrypt(
    blob: bytes,
    key: bytes,
    session_id: bytes,
    seq_num: int,
    flags: int,
    ack_num: int = 0,
) -> bytes:
    """
    Verify and decrypt a blob produced by encrypt().

    The same associated data fields must be provided — if any of them
    differ from what was used during encryption, the GCM tag check will
    fail and InvalidTag is raised.

    Args:
        blob:        nonce (12 B) || ciphertext || GCM tag (16 B)
        key:         32-byte session key from hkdf_extract_expand().
        session_id:  Unique session identifier bytes.
        seq_num:     SRFT sequence number for this packet.
        flags:       SRFT flags byte for this packet.
        ack_num:     SRFT ack number (default 0 if not present).

    Returns:
        Plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if the key, associated data,
        or ciphertext has been tampered with.
    """
    nonce      = blob[:12]
    ciphertext = blob[12:]
    ad         = _build_associated_data(session_id, seq_num, flags, ack_num)
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=ad)


# --- Example usage ---
if __name__ == "__main__":
    from config import FLAG_DATA

    client_nonce = generate_nonce(32)
    server_nonce = generate_nonce(32)
    enc_key, ack_key = hkdf_extract_expand(client_nonce, server_nonce)

    session_id   = generate_nonce(16)

    seq_num   = 42
    ack_num   = 10
    flags     = FLAG_DATA
    plaintext = b"secret message"

    blob = encrypt(plaintext, enc_key, session_id, seq_num, flags, ack_num)
    print("Encrypted:", blob.hex())

    recovered = decrypt(blob, enc_key, session_id, seq_num, flags, ack_num)
    print("Decrypted:", recovered)
