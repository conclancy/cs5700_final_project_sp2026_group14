"""
Header Construction & Parsing

Build a header to pack binary data into the exact byte layout required by 
UDP protocols for header files

This module provides functions to:
  1. Build a UDP header with fields (source port, dest port, length, checksum)
  2. Combine header with a datagram into a full sendable packet
  3. Compute the checksum for error detection
"""

from dataclasses import dataclass
import ipaddress
import struct
from config import MAX_UDP_LENGTH, UDP_HEADER_SIZE, UDP_PROTOCOL_NUMBER


@dataclass
class UDPHeader:
    """
    Data object for an 8 byte UDP header with fields:
    - src_port: 16 bits
    - dst_port: 16 bits
    - length:   16 bits (header + payload)
    - checksum: 16 bits (computed over header + payload)
    """

    src_port: int
    dst_port: int
    length: int = UDP_HEADER_SIZE
    checksum: int = 0

    # Validation to ensure fields are within valid ranges
    def __post_init__(self) -> None:
        if not (0 <= self.src_port <= 0xFFFF and 0 <= self.dst_port <= 0xFFFF):
            raise ValueError("UDP ports must be in range 0-65535")
        
        if not (UDP_HEADER_SIZE <= self.length <= MAX_UDP_LENGTH):
            raise ValueError("UDP length must be in range 8-65535")
        
        if not (0 <= self.checksum <= 0xFFFF):
            raise ValueError("UDP checksum must be in range 0-65535")

    # Serialize header fields into bytes
    def to_bytes(self) -> bytes:
        return struct.pack("!HHHH", self.src_port, self.dst_port, self.length, self.checksum)

    @classmethod
    def from_bytes(cls, header_bytes: bytes) -> "UDPHeader":
        """
        Parse an 8-byte UDP header from bytes and return a UDPHeader instance

        Args:
            header_bytes: 8 bytes representing the UDP header
        
        Returns:
            UDPHeader instance with fields populated from the byte data
        """

        # Validate input length
        if len(header_bytes) != UDP_HEADER_SIZE:
            raise ValueError("UDP header must be exactly 8 bytes")
        
        # Unpack the header fields from bytes
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", header_bytes)

        return cls(src_port=src_port, dst_port=dst_port, length=length, checksum=checksum)

    def to_bytes_with_checksum(self, payload: bytes, src_ip: str, dst_ip: str) -> bytes:
        """
        Serialize the UDP header with a computed checksum based on the payload and IPs

        Args:
            payload: bytes of the UDP payload
            src_ip: source IP address as string (e.g. "192.168.1.1")
            dst_ip: destination IP address as string (e.g. "10.0.0.1")
        
        Returns:
            bytes: the 8-byte UDP header with checksum field correctly set
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes-like")

        # Compute the total length of the UDP packet (header + payload)
        udp_length = UDP_HEADER_SIZE + len(payload)

        # Validate that the total length does not exceed the maximum allowed for UDP
        if udp_length > MAX_UDP_LENGTH:
            raise ValueError("UDP segment too large (max 65535 bytes including header)")

        # Placeholder checksum for checksum computation
        self.length = udp_length
        self.checksum = 0
        header_without_checksum = self.to_bytes()
        pseudo_header = _build_udp_pseudo_header(src_ip, dst_ip, udp_length)
        checksum = compute_checksum(pseudo_header + header_without_checksum + payload)

        # For IPv4, a computed zero checksum is sent as 0xFFFF.
        self.checksum = 0xFFFF if checksum == 0 else checksum
        return self.to_bytes()


def compute_checksum(data: bytes) -> int:
    """
    Compute the Checksum for UDP packets

    Calculates the 16-bit one's complement checksum.

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


def _build_udp_pseudo_header(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    """
    Build the IP pseudo-header used in UDP checksum calculation.

    The pseudo-header includes:
    - Source IP (4 bytes)
    - Destination IP (4 bytes)
    - Zero (1 byte)
    - Protocol (1 byte, 17 for UDP)
    - UDP Length (2 bytes)
    """
    src = ipaddress.ip_address(src_ip)
    dst = ipaddress.ip_address(dst_ip)

    # Validate that both IPs are IPv4 addresses
    if src.version != 4 or dst.version != 4:
        raise ValueError("Source and destination IPs must be IPv4 addresses")

    # IPv4 pseudo-header: src(4), dst(4), zero(1), protocol(1), length(2)
    return struct.pack("!4s4sBBH", src.packed, dst.packed, 0, UDP_PROTOCOL_NUMBER, udp_length)


def build_udp_header(src_port: int, dst_port: int, datagram: bytes,
                     src_ip: str, dst_ip: str) -> bytes:
    """
    Construct an 8-byte UDP header with checksum

    The UDP checksum is computed over a by concatenating the UDP header and payload.
   
    Args:
        src_port:   Source port number
        dst_port:   Destination port number
        datagram:   The datagram (as bytes) to be sent in the UDP packet
        src_ip:     Source IP 
        dst_ip:     Destination IP

    Returns:
        struct: An 8-byte bytes object representing the UDP header
    """
    header = UDPHeader(src_port=src_port, dst_port=dst_port)
    return header.to_bytes_with_checksum(datagram, src_ip, dst_ip)

def verify_checksum(segment: bytes, src_ip: str | None = None, dst_ip: str | None = None) -> bool:
    """
    Verify checksum of received UDP segment.

    The segment must include:
        UDP header (8 bytes)
        Payload

    If the computed checksum over entire segment equals 0,
    then the packet is valid.

    Args:
        segment: full UDP segment (header + payload)

    Returns:
        True if valid, False if corrupted
    """

    if src_ip is not None and dst_ip is not None:
        udp_length = len(segment)
        pseudo_header = _build_udp_pseudo_header(src_ip, dst_ip, udp_length)
        result = compute_checksum(pseudo_header + segment)
        return result == 0

    # Backward-compatible fallback if IPs are not available.
    result = compute_checksum(segment)

    return result == 0
