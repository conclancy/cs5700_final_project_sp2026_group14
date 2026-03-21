"""
Shared Configuration and Constants

This module centralizes parameters and constants used across the SRFT project. 
To change a global setting, edit it here once, and it will propagate everywhere
automatically.
"""
# ---------------------------------------------------------------------------
# Field Length Constants
# ---------------------------------------------------------------------------
IP_HEADER_LENGTH = 20
IP_HEADER_STRUCT = '!BBHHHBBH4s4s'
UDP_HEADER_LENGTH = 8  # Total header size in bytes (source port + dest port + length + checksum)
MAX_UDP_LENGTH = 65300
UDP_HEADER_STRUCT = "!HHHH"
UDP_PROTOCOL_NUMBER = 17
SRFT_HEADER_LENGTH = 25
SRFT_PORT = 12345
SRFT_HEADER_STRUCT = "!H4sH4s4sHH?H"
#                     H  = src_port       (2 bytes)
#                     4s = src_ip         (4 bytes)
#                     H  = dst_port       (2 bytes)
#                     4s = dst_ip         (4 bytes)
#                     4s = message_type   (4 bytes)
#                     H  = header_length  (2 bytes)
#                     H  = sequence_num   (2 bytes)
#                     ?  = additional_msgs(1 byte)
#                     H  = checksum       (2 bytes)




# ---------------------------------------------------------------------------
# Packet Flags
# ---------------------------------------------------------------------------
# Single-byte header flag constants to indicate the type/purpose of each packet

FLAG_DAT  = 0x01    # Packet carries a chunk of file data
FLAG_ACK  = 0x02    # Packet is a cumulative acknowledgement
FLAG_FIN  = 0x04    # Packet signals end-of-file (no more data)
FLAG_SYN  = 0x08    # Packet initiates a connection
FLAG_ERR  = 0x10    # Packet signals an error condition
