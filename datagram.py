"""
Datagram Class

The datagram consists of 2 parts:
1. header: the header object required by the UDP protocols
2. payload: the data that needs to be transferred
"""

# import Header class here

class Datagram:

    """
    Construct a UDP datagram with both header and payload
   
    Args:
        header:     a Header object
        payload:    the data that needs to be transferred
    Returns:
        struct: a UDP datagram object
    """

    def __init__(self, payload: str, header='header'):

        # Header currently has a filler to test if the other components in the programs work
        # TODO: change the header to the appropriate header object when header is finished
        self.header = header
        if self._is_valid_payload(payload) is True:
            self.payload = payload.encode()
        else:
            print("invalid payload")

    def set_payload(self, payload: str):

        """
        Setter method for datagram's payload

        Args:
            payload:    the payload of a datagram
        """

        if self._is_valid_payload(payload) is True:
            self.payload = payload.encode()
        else:
            print("invalid payload")

    def get_payload(self):

        """
        Getter method for datagram's payload

        Returns:
            bytes: UDP payload data in bytes (need to use .decode() if printing the data) 
        """

        return self.payload
    
    def _is_valid_payload(self, payload: str):

        """
        'Private' method to check if the payload is valid (empty or NULL)

        Args:
            payload:    the payload of a datagram

        Returns:
            boolean: True or False based on the condition
        """

        if payload is None or payload == "":
            return False
        
        return True
    
    # to string method
    def __str__(self):

        return f'Datagram\nHeader:{self.header}\nPayload: {self.payload.decode()}'