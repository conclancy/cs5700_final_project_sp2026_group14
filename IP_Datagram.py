import socket
import struct
import checksum
from Condensed.config import IP_HEADER_LENGTH, IP_HEADER_STRUCT
from Condensed.UDP_Packet import UDP_Packet


class Datagram:

    def __init__(self, payload:UDP_Packet):
        # IPv4 header fields
        self.ip_ver_ihl = (4 << 4) + 5  # Version=4, IHL=5 (no options)
        self.ip_tos = 0
        payload_len = len(payload.to_bytes())
        if payload_len is not None:
            self.ip_tot_len = 20 + payload_len # IP header + UDP header + payload
        else:
            self.ip_tot_len = 20
        self.ip_id = 54321
        self.ip_frag_off = 0
        self.ip_ttl = 64
        self.ip_proto = socket.IPPROTO_UDP
        self.ip_check = 0  # Initially zero for checksum calculation
        self.ip_saddr = payload.udp_payload.src_ip
        self.ip_daddr = payload.udp_payload.dst_ip
        self.ip_payload = payload

    def to_bytes(self):
        udp_build = self.ip_payload.to_bytes()
        ip_header_no_check = struct.pack(IP_HEADER_STRUCT,
                                         self.ip_ver_ihl, self.ip_tos, self.ip_tot_len, self.ip_id,
                                         self.ip_frag_off, self.ip_ttl, self.ip_proto, 0,
                                         self.ip_saddr, self.ip_daddr)
        self.ip_check = checksum.compute_checksum(ip_header_no_check)
        return struct.pack(IP_HEADER_STRUCT,
                           self.ip_ver_ihl, self.ip_tos, self.ip_tot_len, self.ip_id,
                           self.ip_frag_off, self.ip_ttl, self.ip_proto, self.ip_check,
                           self.ip_saddr, self.ip_daddr) + udp_build

    @classmethod
    def from_bytes(cls, raw: bytes):
        # IP header is always 20 bytes (assuming no options, IHL=5)
        #ihl = (raw[0] & 0x0F) * 4  # extract actual header length

        ip_header = raw[0:IP_HEADER_LENGTH]
        remaining = raw[IP_HEADER_LENGTH:]  # everything after IP header

        (ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
         ip_proto, ip_check, ip_saddr, ip_daddr) = struct.unpack(IP_HEADER_STRUCT, ip_header)

        obj = cls.__new__(cls)
        obj.ip_ver_ihl = ip_ver_ihl
        obj.ip_tos = ip_tos
        obj.ip_tot_len = ip_tot_len
        obj.ip_id = ip_id
        obj.ip_frag_off = ip_frag_off
        obj.ip_ttl = ip_ttl
        obj.ip_proto = ip_proto
        obj.ip_check = ip_check
        obj.ip_saddr = ip_saddr
        obj.ip_daddr = ip_daddr
        obj.ip_payload = UDP_Packet.from_bytes(remaining)
        return obj

    # to string method
    def __str__(self):
        return (f'************************\n'
                f'****** IP  PACKET ******\n'
                f'************************\n'
                f'---------HEADER---------\n'
                f'IP Version:{self.ip_ver_ihl}\n'
                f'Type of Service (TOS): {self.ip_tos}\n'
                f'Datagram Total Length:{self.ip_tot_len}\n'
                f'Datagram ID: {self.ip_id}\n'
                f'Datagram Fragment Off: {self.ip_frag_off}\n'
                f'Datagram TTL: {self.ip_ttl}\n'
                f'Datagram Protocol: {self.ip_proto}\n'
                f'Datagram Check: {self.ip_check}\n'
                f'Datagram Saddr: {self.ip_saddr}\n'
                f'Datagram Daddr: {self.ip_daddr}\n'
                f'---------PAYLOAD--------\n'
                f'{self.ip_payload}')



