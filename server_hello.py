import struct
import os
from security_psk import verify_hmac, compute_hmac

def process_client_hello(packet: bytes):
    """
    Process ClientHello message.
    """

    payload = packet[:-32]
    received_mac = packet[-32:]

    if not verify_hmac(payload, received_mac):
        raise Exception("Handshake authentication failed")

    version, cipher, client_nonce = struct.unpack("!B B 16s", payload)

    server_nonce = os.urandom(16)
    session_id = os.urandom(8)

    response_payload = struct.pack(
        "!16s8s",
        server_nonce,
        session_id
    )

    mac = compute_hmac(response_payload)

    return response_payload + mac, client_nonce, server_nonce, session_id