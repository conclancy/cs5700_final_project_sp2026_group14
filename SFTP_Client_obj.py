import socket
import os
import time


class Client():


    def __init__(self, args, globalBuf):
        self.globalBuf = globalBuf
        self.sent_msgs = []
        self.args = args

    def sendPacket(self, packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.sendto(packet, (dst_ip, 0))

        self.sent_msgs.append({"packet":UDP_packet, "timestamp":time.time(), "attempts": 1})

    def checkForACK(self):
        ACK_list = globalBuf["ACK"]
        if len(ACK_list) > 0:
            for msg in self.sent_msgs:
                for ack in ACK_list:
                    if msg["packet"].header.sequence_number == ack.header.sequence_number:
                        ACK_list.remove(ack)

    def read_file(self, file: str):

        if file is None or file == "":  # check valid input
            return None

        with open(file, 'r') as in_file:
            data = in_file.read()

        # have a memo of filename and the file_size for server writing output file
        self.memo['filename'] = file
        self.memo['file_size'] = len(data.encode())
        print(self.memo)

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

        start = 0
        split_data = []

        # the first datagram info should be the file name and the file size
        split_data.append(f"{self.memo['filename']},{self.memo['file_size']}")

        while True:  # spliting data into fragments
            end = start + chunk_size
            if end < len(data):
                substring = data[start:end]
                split_data.append(substring)
                start = end
            else:  # last chunk of data
                substring = data[start:len(data)]
                split_data.append(substring)
                break

        return split_data

    # making datagrams for sending info to the server
    def make_datagrams(self, data: list):

        if data is None or len(data) == 0:  # if data list is NULL or empty
            return []

        datagrams = []

        for payload in data:
            datagram = Datagram(payload)
            datagrams.append(datagram)

        return datagrams

