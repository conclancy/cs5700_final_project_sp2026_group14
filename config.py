"""
Shared Configuration and Constants

This module centralizes parameters and constants used across the SRFT project. 
To change a global setting, edit it here once and it will propagate everywhere 
automatically.
"""

import struct
# ---------------------------------------------------------------------------
# Feild Length Constants
# ---------------------------------------------------------------------------
UDP_HEADER_SIZE = 8  # Total header size in bytes (source port + dest port + length + checksum)
MAX_UDP_LENGTH = 0xFFFF  # Maximum UDP segment size (header + payload)
UDP_PROTOCOL_NUMBER = 17  # IP protocol number for UDP

# ---------------------------------------------------------------------------
# Packet Flags
# ---------------------------------------------------------------------------
# Single-byte header flag constants to indicate the type/purpose of each packet

FLAG_DATA = 0x01    # Packet carries a chunk of file data
FLAG_ACK  = 0x02    # Packet is a cumulative acknowledgement
FLAG_FIN  = 0x04    # Packet signals end-of-file (no more data)
FLAG_SYN  = 0x08    # Packet initiates a connection
FLAG_ERR  = 0x10    # Packet signals an error condition

# ---------------------------------------------------------------------------
# Header format strings and derived sizes
# ---------------------------------------------------------------------------
# Used by both server and client for packing/unpacking IP and SRFT headers 
IP_HEADER_FORMAT = "!BBHHHBBH4s4s"
SRFT_HEADER_FORMAT = "!BIIHI"

# precompute sizes so callers don't need to call struct.calcsize each time
IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)
SRFT_HEADER_SIZE = struct.calcsize(SRFT_HEADER_FORMAT)

# ---------------------------------------------------------------------------
# Miscellaneous defaults
# ---------------------------------------------------------------------------
# File path where the server writes its transfer report.  This location can be
# overridden by setting a different value before initializing the server.
REPORT_PATH = "transfer_report.txt"


# Pre-shared key used by both client and server
# Must be >= 32 bytes for strong security
PSK = b"SRFT_demo_pre_shared_key_32_bytes_long!!"

# protocol parameters
CLIENT_NONCE_SIZE = 16
SERVER_NONCE_SIZE = 16
SESSION_ID_SIZE = 8