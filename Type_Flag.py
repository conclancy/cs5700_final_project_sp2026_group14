from enum import Enum

class SrftType(Enum):
    DAT = 0x01  # Packet carries a chunk of file data
    ACK = 0x02  # Packet is a cumulative acknowledgement
    FIN = 0x04  # Packet signals end-of-file (no more data)
    SYN = 0x08  # Packet initiates a connection
    REQ = 0x10  # Packet contains a request for a file to be sent
    ERR = 0x20  # Packet signals an error condition
