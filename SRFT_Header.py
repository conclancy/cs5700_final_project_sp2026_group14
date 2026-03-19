"""
Header Construction & Parsing

Build a header to pack binary data into the exact byte layout required by 
UDP protocols for header files

This module provides functions to:
  1. Build a UDP header with fields (source port, dest port, length, checksum)
  2. Combine header with a datagram into a full sendable packet
  3. Compute the checksum for error detection
"""

# Constands for header field sizes
import struct
from checksum import *
from config import UDP_HEADER_SIZE, SRFT_HEADER_SIZE

#TODO: I don't think we need this function, unless its started in the
# instructions that we need to manually build the UPD packet.
# If not, then we just need a function for building out application header
# If we do need to construct the packets manually, then we will need to use scapy library
class Header:
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, message_type: str,
                 sequence_num: int, additional_messages: bool) -> None:
        self.src_port = src_port
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.dst_ip = dst_ip
        self.message_type = ""
        self.header_length = SRFT_HEADER_SIZE
        self.sequence_num = 0
        self.additional_messages = False
        self.checksum = bytes(0000)


def valididateHeader(header: Header):
    #TODO: We might want to expand this to do more specific validation of each field in the header
    return (header.src_port != "" and
            header.src_ip != "" and
            header.dst_port != "" and
            header.dst_ip != "" and
            header.checksum != 0 and
            header.header_length != 0 and
            header.sequence_num != 0)

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

    # Set initial values for length and checksum
    udp_length = UDP_HEADER_SIZE + len(datagram)   # total UDP segment length
    checksum = 0                              # placeholder

    # Build header with placeholder checksum to get length for checksum calculation
    header = struct.pack("!HHHH", src_port, dst_port, udp_length, checksum)

    # Checksum is computed over: header + datagram
    checksum = compute_checksum(header + datagram) #TODO by other team member, placeholder for now

    # Repack with the real checksum
    header = struct.pack("!HHHH", src_port, dst_port, udp_length, checksum)
    return header