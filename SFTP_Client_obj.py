import random
import socket

from Condensed.Type_Flag import SrftType
from SRFT_Message import SRFT_Message
from UDP_Packet import UDP_Packet
from IP_Datagram import Datagram
from config import SRFT_PORT


class Client:


    def __init__(self, kwargs, global_buf):
        self.file_name = kwargs["filename"]
        self.file_size = None
        self.src_ip = self.get_local_ip()
        self.src_port = SRFT_PORT
        self.dest_port = int(kwargs["dest_port"])
        self.dest_ip = kwargs["dest_ip"]
        self.global_buf = global_buf
        self.rcvd_msgs = dict(ACK=[], SYN=[], FIN=[], REQ=[], ERR=[], DAT=[])
        self.sent_msgs = []

    def send_packet(self, packet):
        # NOTE: Caller is responsible for appending to sent_msgs
        # to avoid double-tracking during resends

        packet_bytes = packet.to_bytes()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.sendto(packet_bytes, (self.dest_ip, self.dest_port))

    def process_rcvd_msgs(self):
        while self.global_buf:
            datagram = self.global_buf.pop(0)
            datagram_obj = Datagram.from_bytes(datagram)
            assert isinstance(datagram_obj, Datagram)
            match datagram_obj.ip_payload.udp_payload.message_type:
                case SrftType.ACK:
                    self.rcvd_msgs["ACK"].append(datagram_obj)
                case SrftType.SYN:
                    self.rcvd_msgs["SYN"].append(datagram_obj)
                case SrftType.FIN:
                    self.rcvd_msgs["FIN"].append(datagram_obj)
                case SrftType.REQ:
                    self.rcvd_msgs["REQ"].append(datagram_obj)
                case SrftType.ERR:
                    self.rcvd_msgs["ERR"].append(datagram_obj)


    def check_for_ack(self):
        if len(self.rcvd_msgs['ACK']) > 0:
            for msg in list(self.sent_msgs):
                for ack in list(self.rcvd_msgs['ACK']):
                    if msg['packet'].ip_payload.udp_payload.sequence_num == ack.ip_payload.udp_payload.sequence_num:
                        self.rcvd_msgs['ACK'].remove(ack)
                        self.sent_msgs.remove(msg)

    def read_file(self):
        if self.file_name is None or self.file_name == "":  # check valid input
            return None

        with open(self.file_name, 'rb') as in_file:
            data = in_file.read()

        self.file_size = len(data)

        return data

    # split data into chunks to suit UDP's payload
    def split_data(self, data: bytes, chunk_size: int):

        # check invalid input
        if data is None or data == "":
            print("invalid data input")
            return None

        if chunk_size is None or chunk_size <= 0:
            print("invalid chunk_size input")
            return None

        start = 0
        split_data = [f'{self.file_name},{self.file_size}'.encode()]

        # the first datagram info should be the file name and the file size

        while True:  # splitting data into fragments
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
        sequence_number = self.get_seq_num()

        for payload in data:
            message = SRFT_Message(self.src_ip, self.src_port, self.dest_ip, self.dest_port, SrftType.DAT, sequence_number, True, payload)
            packet = UDP_Packet(message)
            datagram = Datagram(packet)
            datagrams.append(datagram)
            sequence_number += 1
        message = SRFT_Message(self.src_ip, self.src_port, self.dest_ip, self.dest_port, SrftType.FIN, sequence_number, False,
                               b"")
        packet = UDP_Packet(message)
        datagram = Datagram(packet)
        datagrams.append(datagram)
        sequence_number += 1


        return datagrams

    @staticmethod
    def get_local_ip():
        try:
            # Create a temporary socket to determine the local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Connect to a public DNS server (Google's 8.8.8.8) on port 80
                # This doesn't actually send data, just determines the route
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return None

    @staticmethod
    def get_seq_num():
        return random.randint(0,90000)


