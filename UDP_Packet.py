import struct
import checksum
from SRFT_Message import SRFT_Message
from config import *


class UDP_Packet:

    def __init__(self, message:SRFT_Message):
        self.src_port = message.src_port
        self.dst_port = message.dst_port
        msg_bytes = message.to_bytes()
        if msg_bytes is not None:
            self.udp_len = 8 + len(msg_bytes)
            self.udp_payload = message
        else:
            print('SRFT message build error while initializing UDP packet layer')
            self.udp_len = 8 #TODO: Maybe we should exit instead? Otherwise, we'll need way to resolve any errors
            self.udp_payload = None
        self.udp_check = 0

    def to_bytes(self):
        payload_bytes = self.udp_payload.to_bytes()
        udp_packet = struct.pack('!HHHH', self.src_port, self.dst_port, self.udp_len, self.udp_check) + payload_bytes
        self.udp_check = checksum.compute_checksum(udp_packet)
        return struct.pack('!HHHH', self.src_port, self.dst_port, self.udp_len, self.udp_check) + payload_bytes

    @classmethod
    def from_bytes(cls, raw: bytes):
        # UDP header is always 8 bytes
        udp_header = raw[:8]
        src_port, dst_port, udp_len, udp_check = struct.unpack(UDP_HEADER_STRUCT, udp_header)
        srft_bytes = raw[8:]  # everything after UDP header

        # Reconstruct a UDP_Packet from the parsed message
        obj = cls.__new__(cls)
        obj.src_port = src_port
        obj.dst_port = dst_port
        obj.udp_len = udp_len
        obj.udp_check = udp_check
        obj.udp_payload = SRFT_Message.from_bytes(srft_bytes)
        return obj

    # to string method
    def __str__(self):
        return (f'************************\n'
                f'****** UDP PACKET ******\n'
                f'************************\n'
                f'---------HEADER---------\n'
                f'Source Port:{self.src_port}\n'
                f'Destination Port:{self.dst_port}\n'
                f'UDP Packet Length:{self.udp_len}\n'
                f'UDP Packet Check Sum:{self.udp_check}\n'
                f'---------PAYLOAD--------\n'
                f'{self.udp_payload}')


"""def create_udp_packet(msg, src_ip, dst_ip, src_port, dst_port, payload):
    """ """Build a raw UDP packet with IPv4 header.""" """
    # IPv4 header fields
    ip_ver_ihl = (4 << 4) + 5  # Version=4, IHL=5 (no options)
    ip_tos = 0
    ip_tot_len = 20 + 8 + len(payload)  # IP header + UDP header + payload
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0  # Initially zero for checksum calculation
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    # Pack IP header without checksum
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_tot_len, ip_id,
                            ip_frag_off, ip_ttl, ip_proto, ip_check,
                            ip_saddr, ip_daddr)

    # Calculate IP checksum
    ip_check = checksum.compute_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_tot_len, ip_id,
                            ip_frag_off, ip_ttl, ip_proto, ip_check,
                            ip_saddr, ip_daddr)

    # UDP header
    udp_len = 8 + len(payload)
    udp_check = 0  # Will calculate later
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    # Pseudo-header for UDP checksum
    pseudo_header = ip_saddr + ip_daddr + struct.pack('!BBH', 0, ip_proto, udp_len)
    udp_check = checksum.compute_checksum(pseudo_header + udp_header + payload)

    # Final UDP header with checksum
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    return ip_header + udp_header + payload"""
