"""
SRFT UDP Server Implementation.

This module implements a server to send UDP Data on top of raw UDP sockets. 
The server expects a client request packet containing a file name, then sends 
the file in numbered data packets and handles ACKs and retransmissions.
"""

from __future__ import annotations

import hashlib
import os
import platform
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    FLAG_ACK,
    FLAG_DATA,
    FLAG_ERR,
    FLAG_FIN,
    FLAG_SYN,
    UDP_HEADER_SIZE,
    IP_HEADER_FORMAT,
    IP_HEADER_SIZE,
    SRFT_HEADER_SIZE,
    REPORT_PATH,
    format_bytes,
)
from header import UDPHeader
from security_psk import encrypt
from server_hello import process_client_hello
from srft_packet import build_srft_packet, ip_checksum, is_corrupt, parse_srft_packet
from verification import encrypt_file

# Set default chunk size based on the default MTU minus the sizes of the IPv4, UDP, and SRFT headers
DEFAULT_MTU = 1400
DEFAULT_CHUNK_SIZE = DEFAULT_MTU - IP_HEADER_SIZE - UDP_HEADER_SIZE - SRFT_HEADER_SIZE
MAX_IP_PACKET_ID = 0xFFFF


@dataclass
class SentPacket:
    """
    Data class to store information about sent packets for retransmission and ACK tracking

    Attributes:
        seq_num: The sequence number of the packet
        payload: The file data or control message contained in the packet
        packet_bytes: The complete bytes of the packet ready to be sent on the socket
        sent_at: The timestamp of when the packet was last sent (used for timeout tracking)
        acked: A boolean flag indicating whether this packet has been acknowledged by the client
    """
    seq_num: int
    payload: bytes
    packet_bytes: bytes
    sent_at: float = 0.0
    acked: bool = False


class SRFTUDPServer:
    """
    Sender-side SRFT server implementing Go-Back-N over raw UDP

    Attributes:
        bind_ip: The IP address to bind the server socket to
        bind_port: The port number to bind the server socket to
        window_size: The size of the sliding window for Go-Back-N
        timeout_seconds: The timeout duration in seconds for retransmissions
        chunk_size: The size of file chunks to send in each SRFT data packet
        report_path: The file path where the transfer report will be written after each transfer
    """

    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        window_size: int = 64,
        timeout_seconds: float = 0.05,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        report_path: str = REPORT_PATH,
    ) -> None:

        if window_size <= 0:
            raise ValueError("window_size must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.window_size = window_size
        self.timeout_seconds = timeout_seconds
        self.chunk_size = chunk_size
        self.report_path = Path(report_path)

        # Raw socket for SENDING
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # DGRAM socket for RECEIVING
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind((self.bind_ip, self.bind_port))

        # Threading
        self.transfer_lock = threading.Lock()
        self.transfer_complete = threading.Event()
        self.stop_receiver = threading.Event()

        # Per-transfer state (reset each request)
        self.client_ip = ""
        self.client_port = 0
        self.requested_file = ""
        self.file_size = 0
        self.file_chunks: list[bytes] = []
        self.fin_seq_num = 0
        self.fin_acked = False
        self.fin_packet: SentPacket | None = None
        self.ip_packet_id = 0

        # Go-Back-N state
        self.send_base = 0
        self.next_seq_num = 0
        self.unacked_packets: dict[int, SentPacket] = {}

        # Counters
        self.packets_sent_count = 0
        self.retransmissions_count = 0
        self.packets_received_count = 0
        self.transfer_start_time = 0.0
        self.transfer_end_time = 0.0

    def serve_forever(self) -> None:
        """Run the server loop and process one request at a time."""

        print(f"SRFT server listening on {self.bind_ip}:{self.bind_port}")

        while True:
            packet_info = self._receive_srft_packet(timeout=None)
            if packet_info is None:
                continue

            srft_packet = packet_info["srft_packet"]
            flags = int(srft_packet["flags"])

            if not flags & FLAG_SYN:
                continue

            payload = srft_packet["payload"]
            if not isinstance(payload, bytes):
                continue

            # Process ClientHello handshake
            try:
                response_packet, enc_key, ack_key, session_id, client_nonce = process_client_hello(payload)
            except Exception as e:
                print(f"ClientHello failed: {e}")
                continue

            # Set client address before sending ServerHello
            self.client_ip  = str(packet_info["src_ip"])
            self.client_port = int(packet_info["src_port"])

            # Send ServerHello
            self._send_control_packet(
                flags=FLAG_SYN | FLAG_ACK,
                seq_num=0,
                ack_num=0,
                payload=response_packet,
            )

            # Store session crypto state
            self.session_key = enc_key
            self.session_id  = session_id

            # Wait for second SYN carrying the filename
            packet_info = self._receive_srft_packet(timeout=5.0)
            if packet_info is None:
                continue
            if not (int(packet_info["srft_packet"]["flags"]) & FLAG_SYN):
                continue
            filename = packet_info["srft_packet"]["payload"].decode(errors="replace").strip()

            self.handle_request(
                filename=filename,
                client_ip=str(packet_info["src_ip"]),
                client_port=int(packet_info["src_port"]),
            )

    def handle_request(self, filename: str, client_ip: str, client_port: int) -> None:
        """Handle a file transfer request from a client."""

        self._reset_transfer_state()

        self.client_ip = client_ip
        self.client_port = client_port
        self.requested_file = filename

        file_path = Path(filename)
        if not file_path.exists() or not file_path.is_file():
            self._send_control_packet(
                flags=FLAG_ERR,
                seq_num=0,
                ack_num=0,
                payload=f"file not found: {filename}".encode(),
            )
            return

        with file_path.open("rb") as fh:
            file_bytes = fh.read()

        self.file_size = len(file_bytes)
        self.file_chunks = self._segment_file(file_bytes)
        self.fin_seq_num = len(self.file_chunks)
        self.transfer_start_time = time.time()

        receiver_thread = threading.Thread(target=self._ack_receiver_loop, daemon=True)
        sender_thread   = threading.Thread(target=self._sender_loop, daemon=True)

        receiver_thread.start()
        sender_thread.start()
        sender_thread.join()

        self.stop_receiver.set()
        receiver_thread.join(timeout=1.0)

        self.transfer_end_time = time.time()
        self.write_report()

    def send_window(self) -> None:
        """Send new packets while the sliding window has available space."""

        with self.transfer_lock:
            while (
                self.next_seq_num < len(self.file_chunks)
                and self.next_seq_num < self.send_base + self.window_size
            ):
                seq_num = self.next_seq_num
                payload = self.file_chunks[seq_num]

                # Encrypt the chunk before wrapping in SRFT header
                encrypted_payload = encrypt(
                    payload, self.session_key, self.session_id,
                    seq_num, FLAG_DATA, self.send_base,
                )
                srft_payload = build_srft_packet(
                    flags=FLAG_DATA,
                    seq_num=seq_num,
                    ack_num=self.send_base,
                    payload=encrypted_payload,
                )
                packet_bytes = self._build_full_packet(srft_payload)
                sent_packet = SentPacket(
                    seq_num=seq_num,
                    payload=payload,
                    packet_bytes=packet_bytes,
                )
                self.unacked_packets[seq_num] = sent_packet
                self.next_seq_num += 1
                self._send_stored_packet(sent_packet)

    def retransmit_from_base(self) -> None:
        """Retransmit every unacked packet currently in the sender window."""

        with self.transfer_lock:
            for seq_num in range(self.send_base, self.next_seq_num):
                pkt = self.unacked_packets.get(seq_num)
                if pkt is None or pkt.acked:
                    continue
                self._send_stored_packet(pkt, is_retransmission=True)

    def process_ack(self, ack_num: int, sack_payload: bytes = b"") -> None:
        """
        Process a cumulative ACK from the client.

        Args:
            ack_num:      Cumulative ACK number.
            sack_payload: Optional SACK blocks ([start(4B)][end(4B)] pairs).
        """
        with self.transfer_lock:
            if ack_num <= self.send_base:
                self._apply_sack(sack_payload)
                return

            upper_bound = min(ack_num, self.fin_seq_num + 1)
            for seq_num in list(self.unacked_packets):
                if seq_num < upper_bound:
                    self.unacked_packets[seq_num].acked = True
                    del self.unacked_packets[seq_num]

            if ack_num > self.send_base:
                self.send_base = ack_num

            self._apply_sack(sack_payload)

            if ack_num > self.fin_seq_num:
                self.fin_acked = True
                self.transfer_complete.set()

            if self.send_base >= self.fin_seq_num and self.fin_acked:
                self.transfer_complete.set()

    def _apply_sack(self, sack_payload: bytes) -> None:
        """Mark out-of-order packets already received by the client as acknowledged."""
        if not sack_payload or len(sack_payload) % 8 != 0:
            return
        for i in range(len(sack_payload) // 8):
            start, end = struct.unpack("!II", sack_payload[i * 8:(i + 1) * 8])
            for seq in range(start, end):
                pkt = self.unacked_packets.get(seq)
                if pkt is not None:
                    pkt.acked = True
                    del self.unacked_packets[seq]

    def write_report(self) -> None:
        """Write the transfer report to disk."""
        duration_seconds = max(0, int(self.transfer_end_time - self.transfer_start_time))
        duration_text = str(timedelta(seconds=duration_seconds))
        lines = [
            f"Name of the transferred file: {self.requested_file}",
            f"Size of the transferred file: {self.file_size}",
            f"The number of packets sent from the server: {self.packets_sent_count}",
            f"The number of retransmitted packets from the server: {self.retransmissions_count}",
            f"The number of packets received from the client: {self.packets_received_count}",
            f"The time duration of the file transfer (hh:min:ss): {duration_text}",
        ]
        session_suffix = self.session_id.hex() if hasattr(self, "session_id") else "unknown"
        report_path = self.report_path.with_stem(f"{self.report_path.stem}_{session_suffix}")
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _print_progress(self, last_time: float, last_base: int) -> tuple[float, int]:
        """Render a progress bar in terminal for the current transfer."""
        now = time.time()
        current_base = self.send_base
        total_chunks = len(self.file_chunks)

        if total_chunks == 0:
            return now, current_base

        pct = min(current_base / total_chunks, 1.0)
        acked_bytes = min(current_base * self.chunk_size, self.file_size)
        elapsed = now - self.transfer_start_time

        delta_t = now - last_time
        delta_chunks = current_base - last_base
        if delta_t > 0 and delta_chunks > 0:
            speed = (delta_chunks * self.chunk_size) / delta_t
        elif elapsed > 0:
            speed = acked_bytes / elapsed
        else:
            speed = 0.0

        remaining = self.file_size - acked_bytes
        eta_str = str(timedelta(seconds=int(remaining / speed))) if speed > 0 else "--:--"

        bar_width = 28
        filled = int(bar_width * pct)
        bar = "█" * filled + "░" * (bar_width - filled)

        print(
            f"\r[{bar}] {pct * 100:5.1f}% | "
            f"{format_bytes(acked_bytes)}/{format_bytes(self.file_size)} | "
            f"{format_bytes(speed)}/s | ETA {eta_str}   ",
            end="",
            flush=True,
        )
        return now, current_base

    def _sender_loop(self) -> None:
        """Main sender loop for file data and FIN handling."""
        fin_sent = False
        _PROGRESS_INTERVAL = 0.5
        last_progress_time = time.time()
        last_progress_base = 0

        while not self.transfer_complete.is_set():
            self.send_window()

            # Build and send FIN once all data is acknowledged
            if self.send_base >= len(self.file_chunks) and not fin_sent:
                file_digest = encrypt_file(
                    b"".join(self.file_chunks),
                    AESGCM(self.session_key),
                    b"\x00" * 12,
                )
                self.fin_packet = self._build_control_packet(
                    flags=FLAG_FIN,
                    seq_num=self.fin_seq_num,
                    ack_num=self.send_base,
                    payload=file_digest,
                )
                self._send_stored_packet(self.fin_packet)
                fin_sent = True

            if fin_sent and self.fin_acked:
                self.transfer_complete.set()
                break

            with self.transfer_lock:
                oldest_packet = self.unacked_packets.get(self.send_base)

            if oldest_packet is not None:
                if time.time() - oldest_packet.sent_at >= self.timeout_seconds:
                    self.retransmit_from_base()
            elif fin_sent and self.fin_packet is not None and not self.fin_acked:
                if time.time() - self.fin_packet.sent_at >= self.timeout_seconds:
                    self._send_stored_packet(self.fin_packet, is_retransmission=True)

            now = time.time()
            if now - last_progress_time >= _PROGRESS_INTERVAL:
                last_progress_time, last_progress_base = self._print_progress(
                    last_progress_time, last_progress_base
                )

            time.sleep(0.001)

        self._print_progress(last_progress_time, last_progress_base)
        print()

    def _ack_receiver_loop(self) -> None:
        """Background loop that processes ACK packets from the client."""
        while not self.stop_receiver.is_set():
            packet_info = self._receive_srft_packet(timeout=0.1)
            if packet_info is None:
                continue
            if packet_info["src_ip"] != self.client_ip or packet_info["src_port"] != self.client_port:
                continue

            srft_packet = packet_info["srft_packet"]
            flags = int(srft_packet["flags"])

            if flags & FLAG_ACK:
                sack_payload = srft_packet.get("payload", b"")
                if not isinstance(sack_payload, bytes):
                    sack_payload = b""
                self.process_ack(int(srft_packet["ack_num"]), sack_payload)

    def _receive_srft_packet(self, timeout: float | None) -> dict[str, object] | None:
        """Receive and validate one SRFT packet via the DGRAM receive socket."""
        if timeout is None:
            readable, _, _ = select.select([self.recv_sock], [], [])
        else:
            readable, _, _ = select.select([self.recv_sock], [], [], timeout)

        if not readable:
            return None

        payload, addr = self.recv_sock.recvfrom(65535)
        src_ip, src_port = addr

        if not isinstance(payload, bytes):
            return None

        try:
            srft_packet = parse_srft_packet(payload)
        except ValueError:
            return None

        if is_corrupt(srft_packet):
            return None

        self.packets_received_count += 1

        return {
            "src_ip": src_ip,
            "dst_ip": self.bind_ip,
            "src_port": src_port,
            "dst_port": self.bind_port,
            "srft_packet": srft_packet,
        }

    def _segment_file(self, file_bytes: bytes) -> list[bytes]:
        """Split the file into fixed-size chunks."""
        if not file_bytes:
            return [b""]
        return [
            file_bytes[i:i + self.chunk_size]
            for i in range(0, len(file_bytes), self.chunk_size)
        ]

    def _build_control_packet(self, flags: int, seq_num: int, ack_num: int, payload: bytes) -> SentPacket:
        """Build a control packet that can be sent or retransmitted."""
        srft_payload = build_srft_packet(flags=flags, seq_num=seq_num, ack_num=ack_num, payload=payload)
        packet_bytes = self._build_full_packet(srft_payload)
        return SentPacket(seq_num=seq_num, payload=payload, packet_bytes=packet_bytes)

    def _send_control_packet(self, flags: int, seq_num: int, ack_num: int, payload: bytes) -> None:
        """Build and immediately send a control packet."""
        self._send_stored_packet(self._build_control_packet(flags, seq_num, ack_num, payload))

    def _send_stored_packet(self, sent_packet: SentPacket, is_retransmission: bool = False) -> None:
        """Send a previously constructed packet and update counters/timestamps."""
        self.sock.sendto(sent_packet.packet_bytes, (self.client_ip, self.client_port))
        sent_packet.sent_at = time.time()
        self.packets_sent_count += 1
        if is_retransmission:
            self.retransmissions_count += 1

    def _build_full_packet(self, srft_payload: bytes) -> bytes:
        """Build a complete IPv4 + UDP + SRFT packet."""
        udp_header = UDPHeader(src_port=self.bind_port, dst_port=self.client_port)
        udp_bytes  = udp_header.to_bytes_with_checksum(srft_payload, self.bind_ip, self.client_ip)
        udp_packet = udp_bytes + srft_payload
        ip_header  = self._build_ip_header(IP_HEADER_SIZE + len(udp_packet))
        return ip_header + udp_packet

    def _build_ip_header(self, total_length: int) -> bytes:
        """Construct an IPv4 header with the correct checksum."""
        version_ihl          = (4 << 4) + 5
        tos                  = 0
        packet_id            = self.ip_packet_id & MAX_IP_PACKET_ID
        self.ip_packet_id   += 1
        flags_fragment_offset = 0
        ttl                  = 64
        protocol             = socket.IPPROTO_UDP
        src_ip               = socket.inet_aton(self.bind_ip)
        dst_ip               = socket.inet_aton(self.client_ip)

        if platform.system() == "Darwin":
            hdr_no_chk = (
                struct.pack("!BB", version_ihl, tos) +
                struct.pack("=H", total_length) +
                struct.pack("!H", packet_id) +
                struct.pack("=H", flags_fragment_offset) +
                struct.pack("!BBH4s4s", ttl, protocol, 0, src_ip, dst_ip)
            )
            checksum = ip_checksum(hdr_no_chk)
            return (
                struct.pack("!BB", version_ihl, tos) +
                struct.pack("=H", total_length) +
                struct.pack("!H", packet_id) +
                struct.pack("=H", flags_fragment_offset) +
                struct.pack("!BBH4s4s", ttl, protocol, checksum, src_ip, dst_ip)
            )
        else:
            hdr_no_chk = struct.pack(
                IP_HEADER_FORMAT,
                version_ihl, tos, total_length, packet_id,
                flags_fragment_offset, ttl, protocol, 0, src_ip, dst_ip,
            )
            checksum = ip_checksum(hdr_no_chk)
            return struct.pack(
                IP_HEADER_FORMAT,
                version_ihl, tos, total_length, packet_id,
                flags_fragment_offset, ttl, protocol, checksum, src_ip, dst_ip,
            )

    def _reset_transfer_state(self) -> None:
        """Reset transfer state, preserving session crypto keys."""
        saved_key = getattr(self, "session_key", None)
        saved_id  = getattr(self, "session_id", None)

        self.transfer_complete.clear()
        self.stop_receiver.clear()

        with self.transfer_lock:
            self.send_base = 0
            self.next_seq_num = 0
            self.unacked_packets = {}

        self.requested_file = ""
        self.file_size = 0
        self.file_chunks = []
        self.fin_seq_num = 0
        self.fin_acked = False
        self.fin_packet = None
        self.packets_sent_count = 0
        self.retransmissions_count = 0
        self.packets_received_count = 0
        self.transfer_start_time = 0.0
        self.transfer_end_time = 0.0

        if saved_key is not None:
            self.session_key = saved_key
            self.session_id  = saved_id


def main() -> None:
    bind_ip          = os.environ.get("SRFT_SERVER_IP", "127.0.0.1")
    bind_port        = int(os.environ.get("SRFT_SERVER_PORT", "9000"))
    window_size      = int(os.environ.get("SRFT_WINDOW_SIZE", "64"))
    timeout_seconds  = float(os.environ.get("SRFT_TIMEOUT_SECONDS", "0.05"))

    server = SRFTUDPServer(
        bind_ip=bind_ip,
        bind_port=bind_port,
        window_size=window_size,
        timeout_seconds=timeout_seconds,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()