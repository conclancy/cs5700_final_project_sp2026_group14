"""
Datagram Class

The datagram consists of 2 parts:
1. header: the header object required by the UDP protocols
2. payload: the data that needs to be transferred
"""

from header import UDPHeader

class Datagram:

    """
    Construct a UDP datagram with both header and payload
   
    Args:
        header:     a Header object
        payload:    the data that needs to be transferred
    Returns:
        struct: a UDP datagram object
    """

    def __init__(self, payload: str | bytes, header: UDPHeader | None = None):
        self.header = header if header is not None else UDPHeader(src_port=0, dst_port=0)
        self.payload = self._normalize_payload(payload)

    def set_header(self, header: UDPHeader):
        """
        Setter method for datagram's header.
        """
        self.header = header

    def set_payload(self, payload: str | bytes):

        """
        Setter method for datagram's payload

        Args:
            payload:    the payload of a datagram
        """

        self.payload = self._normalize_payload(payload)

    def get_payload(self):

        """
        Getter method for datagram's payload

        Returns:
            bytes: UDP payload data in bytes (need to use .decode() if printing the data) 
        """

        return self.payload

    def to_bytes(self, src_ip: str, dst_ip: str) -> bytes:
        """
        Serialize datagram as UDP header bytes + payload bytes.
        """
        return self.header.to_bytes_with_checksum(self.payload, src_ip, dst_ip) + self.payload
    
    def _is_valid_payload(self, payload: str | bytes):

        """
        'Private' method to check if the payload is valid (empty or NULL)

        Args:
            payload:    the payload of a datagram

        Returns:
            boolean: True or False based on the condition
        """

        if payload is None:
            return False

        if isinstance(payload, str) and payload == "":
            return False

        if isinstance(payload, (bytes, bytearray)) and len(payload) == 0:
            return False

        return True

    def _normalize_payload(self, payload: str | bytes) -> bytes:
        """
        Method to normalize the payload into bytes format for datagram construction

        Args:
            payload: the payload of a datagram

        Returns:
            bytes: the payload in bytes format
        """

        # Check if the payload is valid (not empty or NULL)
        if not self._is_valid_payload(payload):
            raise ValueError("invalid payload")
        
        # Normalize the payload to bytes
        if isinstance(payload, str):
            return payload.encode()
        
        # If it's already bytes-like, return as is
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        
        # If it's neither str nor bytes-like, raise an error
        raise TypeError("payload must be str or bytes-like")
    
    # to string method
    def __str__(self):

        return f"Datagram\nHeader: {self.header}\nPayload: {self.payload.decode(errors='replace')}"
