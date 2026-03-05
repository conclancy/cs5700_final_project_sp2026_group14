from datagram import Datagram

class Client:

    def __init__(self):
        pass

    # read the file
    def read_file(self, file: str):

        if file is None or file == "": # check valid input
            return None
        
        with open(file, 'r') as in_file:
            data = in_file.read()
        
        return data
    
    # split data into chunks to suit UDP's payload
    def split_data(self, data: str, chunk_size: int):

        # check invalid input
        if data is None or data == "":
            print("invalid data input")
            return None
        
        if chunk_size is None or chunk_size <= 0:
            print("invalid chunk_size input")
            return None

        # spliting data into fragments
        start = 0
        split_data = []

        while True:
            end = start + chunk_size
            if end < len(data):
                substring = data[start:end]
                split_data.append(substring)
                start = end
            else: # last chunk of data
                substring = data[start:len(data)]
                split_data.append(substring)
                break

        return split_data
    
    # making datagrams for sending info to the server
    def make_datagrams(self, data: list):

        if data is None or len(data) == 0: # if data list is NULL or empty
            return []

        datagrams = []

        for payload in data:
            datagram = Datagram(payload)
            datagrams.append(datagram)

        return datagrams