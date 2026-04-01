import struct
from security_psk import generate_nonce, compute_hmac, verify_hmac, hkdf_extract_expand


def build_client_hello() -> tuple[bytes, bytes]:
    """
    Build ClientHello handshake message.

    The HMAC covers the entire payload so the server can verify
    that this message was sent by someone who knows the PSK.

    Returns:
        (packet_bytes, client_nonce)
    """
    version = 1
    cipher = 1  # 1 = AES-256-GCM

    client_nonce = generate_nonce(16)

    # Build payload that HMAC covers
    payload = struct.pack("!BB16s", version, cipher, client_nonce)

    mac = compute_hmac(payload)

    return payload + mac, client_nonce


def process_server_hello(packet: bytes, client_nonce: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Validate ServerHello and derive session keys.

    Expected packet layout:
        server_nonce (16B) | session_id (8B) | HMAC (32B)

    Steps:
      1. Split packet into payload and MAC
      2. Verify HMAC with PSK — reject if invalid
      3. Parse server_nonce and session_id from payload
      4. Run HKDF with both nonces to derive (enc_key, ack_key)

    Args:
        packet:       raw ServerHello bytes received from server
        client_nonce: the nonce this client generated in build_client_hello()

    Returns:
        (enc_key, ack_key, session_id)

    Raises:
        Exception if HMAC verification fails (server not authenticated)
    """
    # Split payload and HMAC (last 32 bytes)
    payload = packet[:-32]
    received_mac = packet[-32:]

    # Step 1: authenticate the server
    if not verify_hmac(payload, received_mac):
        raise Exception("ServerHello authentication failed: HMAC mismatch")

    # Step 2: parse fields
    server_nonce, session_id = struct.unpack("!16s8s", payload)

    # Step 3: derive session keys — same inputs as server side, same outputs
    enc_key, ack_key = hkdf_extract_expand(client_nonce, server_nonce)

    return enc_key, ack_key, session_id