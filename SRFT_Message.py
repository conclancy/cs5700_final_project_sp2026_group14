"""
Datagram Class

The datagram consists of 2 parts:
1. header: the header object required by the UDP protocols
2. payload: the data that needs to be transferred
"""
import socket
import struct
import checksum
from Condensed.Type_Flag import SrftType
from config import *

class SRFT_Message:

    """
    Construct a SRFT Protocol message with both header and payload
   
    Args:
        header:     a Header object
        payload:    the data that needs to be transferred
    Returns:
        struct: a UDP datagram object
    """


    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, message_type: SrftType,
                 sequence_num: int, additional_messages: bool, payload: bytes) -> None:
        self.src_port = src_port
        self.src_ip = socket.inet_aton(src_ip)
        self.dst_port = dst_port
        self.dst_ip = socket.inet_aton(dst_ip)
        self.message_type = message_type # TODO: should this be an enum?
        self.header_length = SRFT_HEADER_LENGTH
        self.sequence_num = sequence_num
        self.additional_messages = additional_messages
        self.checksum = 0
        if self._is_valid_payload(payload):
            self.payload = payload
        else:
            print("invalid payload")


    def to_bytes(self):
        if self._is_valid_header() and self._is_valid_payload(self.payload):
            msg_type_bytes = self.message_type.name.encode().ljust(4)[:4]
            srft_msg = struct.pack(SRFT_HEADER_STRUCT, self.src_port, self.src_ip, self.dst_port,
                        self.dst_ip, msg_type_bytes, self.header_length,
                        self.sequence_num, self.additional_messages, self.checksum) + self.payload
            self.checksum = checksum.compute_checksum(srft_msg)
            return struct.pack(SRFT_HEADER_STRUCT, self.src_port, self.src_ip, self.dst_port,
                        self.dst_ip, msg_type_bytes, self.header_length,
                        self.sequence_num, self.additional_messages, self.checksum) + self.payload
        else:
            print("invalid header")
            return None

    @classmethod
    def from_bytes(cls, raw: bytes):
        if len(raw) < SRFT_HEADER_LENGTH:
            raise ValueError(f"Too short to be a valid SRFT message: {len(raw)} bytes")

        header_bytes = raw[:SRFT_HEADER_LENGTH]
        payload = raw[SRFT_HEADER_LENGTH:]

        (src_port, src_ip_bytes, dst_port, dst_ip_bytes,
         msg_type_bytes, header_length, sequence_num,
         additional_messages, rcvd_checksum) = struct.unpack(SRFT_HEADER_STRUCT, header_bytes)

        obj = cls.__new__(cls)  # bypass __init__ to avoid re-validating
        obj.src_port = src_port
        obj.src_ip = src_ip_bytes
        obj.dst_port = dst_port
        obj.dst_ip = dst_ip_bytes
        obj.message_type = SrftType[msg_type_bytes.decode().strip()]
        obj.header_length = header_length
        obj.sequence_num = sequence_num
        obj.additional_messages = additional_messages
        obj.checksum = rcvd_checksum
        obj.payload = payload
        return obj


    def _is_valid_header(self):
        # TODO: We might want to expand this to do more specific validation of each field in the header
        return (self.src_port > 0 and
                len(self.src_ip) == 4 and #TODO: Should this be validated?
                self.dst_port > 0 and #TODO: We might want o check that this and src_port are within a certain range?
                len(self.dst_ip) == 4 and #TODO: Maybe we should ping the address to validate it?
                self.header_length != 0 and #TODO: We might want to validate that the actually header matches out declared value
                self.sequence_num != 0)

    """def build_udp_header(src_port: int, dst_port: int, datagram: bytes,
                         src_ip: str, dst_ip: str) -> bytes:
        """ """
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
        """ """

        # Set initial values for length and checksum
        udp_length = UDP_HEADER_SIZE + len(datagram)  # total UDP segment length
        checksum = 0  # placeholder

        # Build header with placeholder checksum to get length for checksum calculation
        header = struct.pack("!HHHH", src_port, dst_port, udp_length, checksum)

        # Checksum is computed over: header + datagram
        checksum = checksum.compute_checksum(header + datagram)  # TODO by other team member, placeholder for now

        # Repack with the real checksum
        header = struct.pack("!HHHH", src_port, dst_port, udp_length, checksum)
        return header"""


    def get_payload_content(self):

        """
        Getter method for datagram's payload

        Returns:
            bytes: UDP payload data in bytes (need to use .decode() if printing the data) 
        """

        return self.payload.decode(errors='replace')
    
    def _is_valid_payload(self, payload):

        """
        'Private' method to check if the payload is valid (empty or NULL)

        Args:
            payload:    the payload of a datagram

        Returns:
            boolean: True or False based on the condition
        """
        
        return isinstance(payload, bytes)


    
    # to string method
    def __str__(self):
        return (f'************************\n'
                f'***** SRFT MESSAGE *****\n'
                f'************************\n'
                f'---------HEADER---------\n'
                f'Source Port:{self.src_port}\n'
                f'Destination Port:{self.dst_port}\n'
                f'Source IP:{socket.inet_ntoa(self.src_ip)}\n'
                f'Destination IP:{socket.inet_ntoa(self.dst_ip)}\n'
                f'Message Type:{self.message_type.value} ({self.message_type.name})\n'
                f'Header Length:{self.header_length}\n'
                f'Sequence Number:{self.sequence_num}\n'
                f'Additional Messages:{self.additional_messages}\n'
                f'Checksum:{self.checksum}\n'
                f'---------PAYLOAD--------\n'
                f"{self.payload.decode(errors='replace')}")
