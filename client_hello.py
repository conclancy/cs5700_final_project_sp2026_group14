import struct
from security_psk import generate_nonce, compute_hmac
from security_psk import verify_hmac, hkdf_extract_expand

def build_client_hello():
    """
    Build ClientHello handshake message.
    """

    version = 1
    cipher = 1

    client_nonce = generate_nonce(16)

    payload = struct.pack("!B B 16s", version, cipher, client_nonce)

    mac = compute_hmac(payload)

    return payload + mac, client_nonce


def process_server_hello(packet, client_nonce):
    """
    Validate ServerHello and derive session key
    """

    payload = packet[:-32]
    received_mac = packet[-32:]

    if not verify_hmac(payload, received_mac):
        raise Exception("Server authentication failed")

    server_nonce, session_id = struct.unpack("!16s8s", payload)

    enc_key = hkdf_extract_expand(client_nonce, server_nonce)

    return enc_key, session_id