"""
SRFT Packet Utilities

Shared functions for building, parsing, and validating SRFT packets and IPv4
headers. Used by both srft_udpserver.py and srft_udpclient.py.
"""

from __future__ import annotations

import struct

from config import SRFT_HEADER_FORMAT, SRFT_HEADER_SIZE


def compute_payload_checksum(data: bytes) -> int:
    """
    Compute a simple checksum for the SRFT layer.

    Uses a 32-bit modular sum over the SRFT header (without checksum field)
    and payload to detect corruption in the SRFT layer.

    Args:
        data: The bytes over which to compute the checksum
    Returns:
        A 32-bit integer checksum value
    """
    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFFFFFFFF
    return checksum


def build_srft_packet(flags: int, seq_num: int, ack_num: int, payload: bytes) -> bytes:
    """
    Build the SRFT payload carried inside the UDP segment.

    Args:
        flags: The SRFT flags byte (e.g. FLAG_SYN, FLAG_ACK, etc.)
        seq_num: The sequence number for this packet
        ack_num: The cumulative acknowledgement number for this packet
        payload: The file data or control message to include in the packet
    Returns:
        The complete SRFT header and payload bytes to be included in the UDP segment
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes-like")
    payload = bytes(payload)

    header_without_checksum = struct.pack(
        SRFT_HEADER_FORMAT, flags, seq_num, ack_num, len(payload), 0
    )
    checksum = compute_payload_checksum(header_without_checksum[:-4] + payload)
    return (
        struct.pack(SRFT_HEADER_FORMAT, flags, seq_num, ack_num, len(payload), checksum)
        + payload
    )


def parse_srft_packet(payload_bytes: bytes) -> dict[str, int | bytes]:
    """
    Parse the SRFT header and payload from UDP payload bytes.

    Args:
        payload_bytes: The raw bytes from the UDP payload
    Returns:
        Dictionary with parsed SRFT fields: flags, seq_num, ack_num,
        payload_len, checksum, and payload
    Raises:
        ValueError: If the data is too short or the payload length mismatches
    """
    if len(payload_bytes) < SRFT_HEADER_SIZE:
        raise ValueError("payload is too short for SRFT header")

    flags, seq_num, ack_num, payload_len, checksum = struct.unpack(
        SRFT_HEADER_FORMAT, payload_bytes[:SRFT_HEADER_SIZE]
    )
    payload = payload_bytes[SRFT_HEADER_SIZE: SRFT_HEADER_SIZE + payload_len]

    if len(payload) != payload_len:
        raise ValueError("payload length does not match SRFT header")

    return {
        "flags": flags,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "payload_len": payload_len,
        "checksum": checksum,
        "payload": payload,
    }


def is_corrupt(packet_dict: dict[str, int | bytes]) -> bool:
    """
    Validate the SRFT checksum carried in the packet.

    Args:
        packet_dict: Parsed SRFT packet dict (as returned by parse_srft_packet)
    Returns:
        True if the packet is corrupt, False if valid
    Raises:
        TypeError: If the payload field is not bytes
    """
    payload = packet_dict["payload"]
    if not isinstance(payload, bytes):
        raise TypeError("packet payload must be bytes")

    header_without_checksum = struct.pack(
        SRFT_HEADER_FORMAT,
        int(packet_dict["flags"]),
        int(packet_dict["seq_num"]),
        int(packet_dict["ack_num"]),
        int(packet_dict["payload_len"]),
        0,
    )
    expected = compute_payload_checksum(header_without_checksum[:-4] + payload)
    return expected != int(packet_dict["checksum"])


def ip_checksum(data: bytes) -> int:
    """
    Compute the IPv4 header checksum (one's complement of 16-bit word sum).

    Args:
        data: The bytes of the IPv4 header with the checksum field set to 0
    Returns:
        The 16-bit checksum value to be included in the IPv4 header
    """
    if len(data) % 2 != 0:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
