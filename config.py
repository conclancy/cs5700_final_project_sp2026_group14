"""
Shared Configuration and Constants

This module centralizes parameters and constants used across the SRFT project.
To change a global setting, edit it here once, and it will propagate everywhere
automatically.
"""
# ---------------------------------------------------------------------------
# Field Length Constants
# ---------------------------------------------------------------------------
IP_HEADER_SIZE   = 20               # IPv4 header size in bytes (no options)
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'  # struct format for IPv4 header
UDP_HEADER_SIZE  = 8                # UDP header size in bytes
MAX_UDP_LENGTH   = 65300
UDP_PROTOCOL_NUMBER = 17
SRFT_PORT = 12345

# ---------------------------------------------------------------------------
# SRFT Packet Header (used by srft_udpserver.py and srft_udpclient.py)
#
# Format: flags(1B) | seq_num(4B) | ack_num(4B) | payload_len(4B) | checksum(4B)
# ---------------------------------------------------------------------------
SRFT_HEADER_FORMAT = "!BIIII"
SRFT_HEADER_SIZE = 17  # 1 + 4 + 4 + 4 + 4 bytes

# Path where the server writes its transfer report
REPORT_PATH = "transfer_report.txt"


# ---------------------------------------------------------------------------
# Packet Flags
# ---------------------------------------------------------------------------
# Single-byte header flag constants to indicate the type/purpose of each packet

FLAG_DATA = 0x01    # Packet carries a chunk of file data
FLAG_ACK  = 0x02    # Packet is a cumulative acknowledgement
FLAG_FIN  = 0x04    # Packet signals end-of-file (no more data)
FLAG_SYN  = 0x08    # Packet initiates a connection
FLAG_ERR  = 0x10    # Packet signals an error condition

# Pre-shared key used by both client and server
# Must be >= 32 bytes for strong security
PSK = b"SRFT_demo_pre_shared_key_32_bytes_long!!"

# protocol parameters
CLIENT_NONCE_SIZE = 16
SERVER_NONCE_SIZE = 16
SESSION_ID_SIZE = 8