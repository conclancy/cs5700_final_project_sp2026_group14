"""
SRFT UDP Client - Phase 1 Implementation

Requests a file from the SRFT server by sending a SYN packet containing the
filename, then receives the file in numbered DATA packets using the Go-Back-N
receiver protocol, sends cumulative ACKs, and writes the received file to disk.

Usage:
    sudo python srft_udpclient.py filename=<name> [dest_ip=<ip>] [dest_port=<port>] [src_port=<port>]

Example (both client and server on same machine):
    Terminal 1: sudo python srft_udpserver.py
    Terminal 2: sudo python srft_udpclient.py filename=sample.txt dest_ip=<your-local-ip> dest_port=9000
"""

from __future__ import annotations

import hashlib
import os
import select
import socket
import struct
import sys
import platform
import time
from datetime import timedelta
from pathlib import Path

from config import (
    FLAG_ACK,
    FLAG_DATA,
    FLAG_ERR,
    FLAG_FIN,
    FLAG_SYN,
    IP_HEADER_FORMAT,
    IP_HEADER_SIZE,
    SRFT_PORT,
    UDP_HEADER_SIZE,
)
from header import UDPHeader
from srft_packet import build_srft_packet, ip_checksum, is_corrupt, parse_srft_packet



# ---------------------------------------------------------------------------
# SRFT UDP Client
# ---------------------------------------------------------------------------

class SRFTUDPClient:
    """
    Go-Back-N receiver side of the SRFT file transfer protocol.

    The client:
    1. Sends a SYN packet carrying the filename to the server.
    2. Receives DATA packets, delivers them in order, buffers out-of-order ones.
    3. Sends cumulative ACKs (batched — not one ACK per packet).
    4. Receives a FIN packet, sends a final ACK, then writes the file to disk.

    Attributes:
        src_ip:      Local IP address used as the packet source.
        src_port:    Local UDP port used as the packet source.
        server_ip:   Server IP address to send SYN/ACK packets to.
        server_port: Server UDP port.
        timeout:     Seconds to wait for a packet before triggering timeout logic.
        output_dir:  Directory where the received file will be written.
    """

    # Send a cumulative ACK after this many consecutive in-order packets
    ACK_BATCH_SIZE = 16

    # Also send ACK if this many seconds have passed since the last one (delayed ACK)
    ACK_DELAY = 0.005

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        server_ip: str,
        server_port: int,
        timeout: float = 2.0,
        output_dir: str = ".",
    ) -> None:
        self.src_ip = src_ip
        self.src_port = src_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.timeout = timeout
        self.output_dir = Path(output_dir)

        # Raw socket used exclusively for SENDING — allows the configuration of custom IP+UDP headers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Regular UDP socket used exclusively for RECEIVING.
        # On macOS, raw sockets do not receive packets sent from processes on the same machine.
        # A SOCK_DGRAM socket is registered with the kernel's UDP demultiplexer and reliably
        # receives any properly-addressed UDP packet, including those injected by raw sockets.
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind((self.src_ip, self.src_port))

        # Receiver state
        self.next_expected: int = 0               # Next in-order seq num expected
        self.recv_buf: dict[int, bytes] = {}      # Out-of-order packet buffer
        self.chunks: dict[int, bytes] = {}        # In-order delivered chunks
        self.fin_seq: int = -1
        self.ip_pkt_id: int = 0

        # Counters for transfer report
        self.pkts_received: int = 0
        self.acks_sent: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_file(self, filename: str) -> None:
        """
        Send a SYN for the given filename, receive the file, and write it to disk.

        Args:
            filename: The name of the file to request from the server.
        """
        print(f"Requesting '{filename}' from {self.server_ip}:{self.server_port}")
        self.start_time = time.time()

        self._send_syn(filename)
        syn_sent_at = self.start_time
        got_data = False
        last_ack_time = self.start_time
        since_last_ack = 0

        while True:
            pkt = self._recv_packet(self.timeout)

            if pkt is None:
                # Timeout — either resend SYN or send a duplicate ACK
                if not got_data:
                    if time.time() - syn_sent_at >= self.timeout:
                        print("No response from server, resending SYN...")
                        self._send_syn(filename)
                        syn_sent_at = time.time()
                else:
                    # Mid-transfer: duplicate ACK signals the server to retransmit
                    self._send_ack(self.next_expected)
                    last_ack_time = time.time()
                    since_last_ack = 0
                continue

            # Ignore packets not from the server
            if pkt["src_ip"] != self.server_ip or pkt["src_port"] != self.server_port:
                continue

            flags = pkt["srft"]["flags"]
            seq = pkt["srft"]["seq_num"]
            payload = pkt["srft"]["payload"]
            self.pkts_received += 1
            got_data = True

            if flags & FLAG_DATA:
                if seq == self.next_expected:
                    # In-order: deliver immediately
                    self.chunks[seq] = payload
                    self.next_expected += 1
                    since_last_ack += 1

                    # Deliver any contiguous buffered out-of-order packets
                    while self.next_expected in self.recv_buf:
                        self.chunks[self.next_expected] = self.recv_buf.pop(self.next_expected)
                        self.next_expected += 1
                        since_last_ack += 1

                    # Send a batched cumulative ACK
                    now = time.time()
                    if since_last_ack >= self.ACK_BATCH_SIZE or (now - last_ack_time) >= self.ACK_DELAY:
                        self._send_ack(self.next_expected)
                        last_ack_time = now
                        since_last_ack = 0

                elif seq > self.next_expected:
                    # Out-of-order: buffer and send a duplicate ACK
                    if seq not in self.recv_buf and seq not in self.chunks:
                        self.recv_buf[seq] = payload
                    self._send_ack(self.next_expected)
                    last_ack_time = time.time()
                    since_last_ack = 0

                else:
                    # Duplicate: re-ACK so the server can advance its window
                    self._send_ack(self.next_expected)

            elif flags & FLAG_FIN:
                # Flush any pending data ACK first, then ACK the FIN
                if since_last_ack > 0:
                    self._send_ack(self.next_expected)
                self.fin_seq = seq
                self._send_ack(seq + 1)
                print(f"FIN received (seq={seq}), transfer complete.")
                break

            elif flags & FLAG_ERR:
                print(f"Server error: {payload.decode(errors='replace')}")
                return

        # Send a few extra FIN ACKs to handle server retransmits of FIN
        for _ in range(3):
            self._send_ack(self.fin_seq + 1)
            time.sleep(0.05)

        self.end_time = time.time()
        self._write_file(filename)
        self._write_report(filename)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_file(self, filename: str) -> None:
        """Assemble received chunks in sequence order and write to disk."""
        if not self.chunks:
            print("Warning: no data received.")
            return

        max_seq = max(self.chunks.keys())
        file_data = b"".join(
            self.chunks[i] for i in range(max_seq + 1) if i in self.chunks
        )

        out_path = self.output_dir / f"received_{Path(filename).name}"
        out_path.write_bytes(file_data)

        md5 = hashlib.md5(file_data).hexdigest()
        print(f"File written : {out_path}  ({len(file_data)} bytes)")
        print(f"MD5          : {md5}")

    def _write_report(self, filename: str) -> None:
        """Write the client-side transfer report."""
        duration = str(timedelta(seconds=max(0, int(self.end_time - self.start_time))))
        lines = [
            f"Name of the transferred file: {filename}",
            f"The number of packets received from the server: {self.pkts_received}",
            f"The number of ACKs sent to the server: {self.acks_sent}",
            f"The time duration of the file transfer (hh:min:ss): {duration}",
        ]
        report_path = self.output_dir / "client_transfer_report.txt"
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Report       : {report_path}")

    def _send_syn(self, filename: str) -> None:
        """Send a SYN packet with the filename as payload."""
        srft_payload = build_srft_packet(FLAG_SYN, 0, 0, filename.encode())
        self.sock.sendto(self._build_packet(srft_payload), (self.server_ip, self.server_port))

    def _send_ack(self, ack_num: int) -> None:
        """Send a cumulative ACK packet with SACK blocks for any buffered out-of-order data."""
        srft_payload = build_srft_packet(FLAG_ACK, 0, ack_num, self._build_sack_payload())
        self.sock.sendto(self._build_packet(srft_payload), (self.server_ip, self.server_port))
        self.acks_sent += 1

    def _build_sack_payload(self) -> bytes:
        """
        Encode out-of-order buffered sequence numbers as SACK blocks.

        Each block is a [start(4B)][end(4B)] pair representing a contiguous range
        [start, end) of sequence numbers already received out-of-order. The server
        uses these to skip retransmitting packets it doesn't need to resend.
        Capped at 8 blocks to keep ACK packets small.
        """
        if not self.recv_buf:
            return b""
        seqs = sorted(self.recv_buf.keys())
        ranges: list[tuple[int, int]] = []
        start = seqs[0]
        end = seqs[0]
        for s in seqs[1:]:
            if s == end + 1:
                end = s
            else:
                ranges.append((start, end + 1))
                start = s
                end = s
        ranges.append((start, end + 1))
        result = b""
        for s, e in ranges[:8]:
            result += struct.pack("!II", s, e)
        return result

    def _recv_packet(self, timeout: float) -> dict | None:
        """
        Wait up to `timeout` seconds for a valid SRFT packet via the DGRAM receive socket.

        The DGRAM socket delivers only the UDP payload (the SRFT data), with the IP and
        UDP headers already stripped by the kernel.  The kernel also validates the UDP
        checksum before delivery, so no manual checksum check is needed here.

        Returns a dict with src_ip, src_port, and srft fields, or None on timeout or
        any parse/validation failure.
        """
        readable, _, _ = select.select([self.recv_sock], [], [], timeout)
        if not readable:
            return None

        # recvfrom on a DGRAM socket returns (udp_payload, (src_ip, src_port))
        payload, addr = self.recv_sock.recvfrom(65535)
        src_ip, src_port = addr

        if not isinstance(payload, bytes):
            return None

        try:
            srft = parse_srft_packet(payload)
        except ValueError:
            return None

        if is_corrupt(srft):
            return None

        return {
            "src_ip": src_ip,
            "src_port": src_port,
            "srft": srft,
        }

    def _build_packet(self, srft_payload: bytes) -> bytes:
        """Build a complete IPv4 + UDP + SRFT byte string."""
        udp_hdr = UDPHeader(src_port=self.src_port, dst_port=self.server_port)
        udp_bytes = udp_hdr.to_bytes_with_checksum(srft_payload, self.src_ip, self.server_ip)
        udp_pkt = udp_bytes + srft_payload
        ip_hdr = self._build_ip_header(IP_HEADER_SIZE + len(udp_pkt))
        return ip_hdr + udp_pkt

    def _build_ip_header(self, total_len: int) -> bytes:
        """
        Construct an IPv4 header with the correct checksum.

        On macOS/BSD with IP_HDRINCL, the kernel requires ip_len and ip_off to
        be in host byte order rather than network byte order.  All other fields
        remain in network (big-endian) byte order.
        """
        version_ihl = (4 << 4) + 5
        pkt_id = self.ip_pkt_id & 0xFFFF
        self.ip_pkt_id += 1
        src = socket.inet_aton(self.src_ip)
        dst = socket.inet_aton(self.server_ip)

        if platform.system() == "Darwin":
            # ip_len and ip_off must be in host byte order on macOS
            hdr_no_chk = (
                struct.pack("!BB", version_ihl, 0) +       # version_ihl, tos
                struct.pack("=H", total_len) +             # ip_len:  host byte order
                struct.pack("!H", pkt_id) +                # ip_id:   network byte order
                struct.pack("=H", 0) +                     # ip_off:  host byte order
                struct.pack("!BBH4s4s", 64, socket.IPPROTO_UDP, 0, src, dst)
            )
            chk = ip_checksum(hdr_no_chk)
            return (
                struct.pack("!BB", version_ihl, 0) +
                struct.pack("=H", total_len) +
                struct.pack("!H", pkt_id) +
                struct.pack("=H", 0) +
                struct.pack("!BBH4s4s", 64, socket.IPPROTO_UDP, chk, src, dst)
            )
        else:
            hdr_no_chk = struct.pack(
                IP_HEADER_FORMAT,
                version_ihl, 0, total_len, pkt_id, 0, 64, socket.IPPROTO_UDP, 0, src, dst,
            )
            chk = ip_checksum(hdr_no_chk)
            return struct.pack(
                IP_HEADER_FORMAT,
                version_ihl, 0, total_len, pkt_id, 0, 64, socket.IPPROTO_UDP, chk, src, dst,
            )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    """Detect the primary local IP address by routing to a public host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def parse_args(argv: list[str]) -> dict[str, str]:
    kwargs: dict[str, str] = {}
    for arg in argv:
        if "=" in arg:
            key, value = arg.split("=", 1)
            kwargs[key] = value
    return kwargs


def main() -> None:
    if os.geteuid() != 0:
        print("Error: raw sockets require root. Run with sudo.")
        sys.exit(1)

    kw = parse_args(sys.argv[1:])

    filename = kw.get("filename")
    if not filename:
        print(
            "Usage: sudo python srft_udpclient.py filename=<name> "
            "[dest_ip=<ip>] [dest_port=<port>] [src_port=<port>] [timeout=<sec>]"
        )
        sys.exit(1)

    server_ip   = kw.get("dest_ip", get_local_ip())
    server_port = int(kw.get("dest_port", "9000"))
    src_port    = int(kw.get("src_port", str(SRFT_PORT)))
    src_ip      = kw.get("src_ip", get_local_ip())
    timeout     = float(kw.get("timeout", "2.0"))

    client = SRFTUDPClient(
        src_ip=src_ip,
        src_port=src_port,
        server_ip=server_ip,
        server_port=server_port,
        timeout=timeout,
    )
    client.request_file(filename)


if __name__ == "__main__":
    main()
