import struct
import os
from security_psk import verify_hmac, compute_hmac, hkdf_extract_expand


def process_client_hello(packet: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Process ClientHello and build ServerHello response.

    Expected ClientHello layout:
        version (1B) | cipher (1B) | client_nonce (16B) | HMAC (32B)

    Steps:
      1. Split payload and MAC
      2. Verify HMAC with PSK — reject if invalid
      3. Parse version, cipher, client_nonce
      4. Generate server_nonce and session_id
      5. Build ServerHello response with its own HMAC
      6. Derive session keys (same KDF as client side)

    Args:
        packet: raw ClientHello bytes received from client

    Returns:
        (response_packet, enc_key, ack_key, session_id, client_nonce)

        response_packet: bytes to send back as ServerHello
        enc_key:         32-byte key for AEAD encryption
        ack_key:         32-byte key for ACK authentication
        session_id:      8-byte unique session identifier
        client_nonce:    parsed from ClientHello (kept for caller use)

    Raises:
        Exception if HMAC verification fails (client not authenticated)
    """
    # Split payload and HMAC (last 32 bytes)
    payload = packet[:-32]
    received_mac = packet[-32:]

    # Step 1: authenticate the client
    if not verify_hmac(payload, received_mac):
        raise Exception("ClientHello authentication failed: HMAC mismatch")

    # Step 2: parse fields
    version, cipher, client_nonce = struct.unpack("!BB16s", payload)

    # Step 3: generate fresh server-side values
    server_nonce = os.urandom(16)
    session_id = os.urandom(8)

    # Step 4: build ServerHello payload and sign it
    response_payload = struct.pack("!16s8s", server_nonce, session_id)
    mac = compute_hmac(response_payload)
    response_packet = response_payload + mac

    # Step 5: derive session keys — same KDF as client, same inputs, same outputs
    enc_key, ack_key = hkdf_extract_expand(client_nonce, server_nonce)

    return response_packet, enc_key, ack_key, session_id, client_nonce