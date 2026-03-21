"""
Header Construction & Parsing

Build a header to pack binary data into the exact byte layout required by 
UDP protocols for header files

This module provides functions to:
  1. Build a UDP header with fields (source port, dest port, length, checksum)
  2. Combine header with a datagram into a full sendable packet
  3. Compute the checksum for error detection
"""

def compute_checksum(data: bytes) -> int:
    """
    Compute the Internet Checksum (RFC 1071 style).

    This function calculates the 16-bit one's complement checksum.
    It is used for detecting a bit corruption in transmitted packets.

    Steps:
    1. If total length is odd, pad one zero byte.
    2. Split into 16-bit words.
    3. Sum all words using 32-bit accumulator.
    4. Add carry bits back into lower 16 bits.
    5. Take one's complement.

    Args:
        data: bytes over which checksum is computed

    Returns:
        16-bit checksum as integer
    """

    # If the total length is odd, pad with one zero byte
    if len(data) % 2 != 0:
        data += b'\x00'

    checksum = 0

    # Process every 2 bytes (16 bits)
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

        # Add carry if overflow beyond 16 bits
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement (invert bits)
    checksum = ~checksum & 0xFFFF

    return checksum

def verify_checksum(segment: bytes) -> bool:
    """
    Verify checksum of received UDP segment.

    The segment must include:
        UDP header (8 bytes)
        Payload

    If the computed checksum over entire segment equals 0,
    then the packet is valid.

    #  compute_checksum() should resolve in a hex value

    Args:
        segment: full UDP segment (header + payload)

    Returns:
        True if valid, False if corrupted
    """

    result = compute_checksum(segment)

    return result == 0








