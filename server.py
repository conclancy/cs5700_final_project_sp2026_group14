class Server:

    def __init__(self):

        '''
        The structure of the payload_memo after sort_payload() should look like this:

        self.payload_memo = {
            'length': number_of_datagrams_received,
            seq_num: payload,
            seq_num: payload,
            seq_num: payload,
        }
        '''
        
        self.payload_memo = {}

    def sort_payload(self, datagrams: list):

        '''
        Method for sorting the payload message before assembling because the packets may not necessarily 
        arrive in order.

        Args:
            datagrams:  the list of datagrams sent by client (or after the server processed everything and 
                        ready for assemble)
        '''

        if not datagrams:
            return

        datagram_nums = len(datagrams)
        self.payload_memo['length'] = datagram_nums

        for datagram in datagrams:
            self.payload_memo[datagram[0]] = datagram[1].decode()

    def assemble_payload(self):

        '''
        Method for assembling the payload message based on server's payload_memo

        Return:
            A string object that contains the decoded message from payload
        '''

        if 'length' not in self.payload_memo:
            print("No payload exists")
            return

        nums_of_payload = self.payload_memo['length']
        msg = ""

        for i in range(1, nums_of_payload + 1):
            msg += self.payload_memo[i]
        
        return msg

    def generate_output(self, filename: str, size: int):

        '''
        Method for generating the ouput string for writting to the txt file.

        Args:
            filename:   the name of the file
            size:       the size of the filename
        
        Return:
            the output string to write to the output txt file
        '''
        
        return f"- Name of the transferred file: {filename}\n" + \
               f"- Size of the transferred file: {size}\n" + \
               f"- The number of packets sent from the server:\n" + \
               f"- The number of retransmitted packets from the server:\n" + \
               f"- The number of packets received from the client:\n" + \
               f"- The time duration of the file transfer (hh:min:ss):"
    
    def write_file(self, filename: str, output: str):

        '''
        Method for writing the output txt file

        Args:
            filename:   the name of the output txt file
            output:     the output string from generate_ouput() method
        
        Return:
            an output txt file
        '''

        if filename is None or filename == "": # check valid input
            return None

        with open(filename, 'w') as out_file:
            out_file.write(output)