import scapy.all as scapy
import pickle



def make_udp_packet(msg):
    # Create an IP layer
    ip_layer = IP(dst="192.168.1.10", src="192.168.1.100")

    # Create a UDP layer
    udp_layer = UDP(sport=12345, dport=80)

    # Add a payload (data)
    payload = b"Hello from Scapy!"

    # Stack the layers together
    packet = ip_layer / udp_layer / payload

    # Display packet details
    packet.show()

    # Send the packet (requires root/admin privileges)
    # send(packet)

def create_udp_packet(msg, src_ip, dst_ip, src_port, dst_port, payload):
    """Build a raw UDP packet with IPv4 header."""
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
    ip_check = checksum(ip_header)
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
    udp_check = checksum(pseudo_header + udp_header + payload)

    # Final UDP header with checksum
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    return ip_header + udp_header + payload