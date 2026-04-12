"""
SRFT UDP Client

Performs the PSK handshake, then receives the file in numbered DATA packets
using the Go-Back-N receiver protocol with SACK, sends cumulative ACKs,
verifies the file digest carried in the FIN, and writes the file to disk.

Usage:
    sudo python srft_udpclient.py filename=<name> [dest_ip=<ip>] [dest_port=<port>] [src_port=<port>]
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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_hello import build_client_hello, process_server_hello
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
    format_bytes,
)
from header import UDPHeader
from security_psk import decrypt
from srft_packet import build_srft_packet, ip_checksum, is_corrupt, parse_srft_packet
from verification import verify_transfer


class SRFTUDPClient:
    """
    Go-Back-N receiver side of the SRFT file transfer protocol.

    1. Performs PSK handshake (ClientHello / ServerHello).
    2. Sends a second SYN carrying the filename.
    3. Receives encrypted DATA packets, delivers them in order, buffers
       out-of-order ones, and sends cumulative ACKs with SACK blocks.
    4. On FIN, verifies the SHA-256 digest and writes the file to disk.
    """

    ACK_BATCH_SIZE = 16       # send ACK after this many in-order packets
    ACK_DELAY      = 0.005    # or after this many seconds (delayed ACK)

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        server_ip: str,
        server_port: int,
        timeout: float = 2.0,
        output_dir: str = ".",
    ) -> None:
        self.src_ip     = src_ip
        self.src_port   = src_port
        self.server_ip  = server_ip
        self.server_port = server_port
        self.timeout    = timeout
        self.output_dir = Path(output_dir)

        # Raw socket for SENDING
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # DGRAM socket for RECEIVING
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind((self.src_ip, self.src_port))

        # Receiver state
        self.next_expected: int          = 0
        self.recv_buf: dict[int, bytes]  = {}
        self.chunks:   dict[int, bytes]  = {}
        self.fin_seq:  int               = -1
        self.ip_pkt_id: int              = 0

        # Counters
        self.pkts_received: int  = 0
        self.acks_sent:     int  = 0
        self.bytes_received: int = 0
        self.start_time: float   = 0.0
        self.end_time:   float   = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_file(self, filename: str) -> None:
        """Handshake, receive, verify, and write the requested file."""
        print(f"Requesting '{filename}' from {self.server_ip}:{self.server_port}")
        self.start_time = time.time()

        # ── Step 1: ClientHello ──────────────────────────────────────
        hello_msg, client_nonce = build_client_hello()
        srft_payload = build_srft_packet(FLAG_SYN, 0, 0, hello_msg)
        self.sock.sendto(self._build_packet(srft_payload), (self.server_ip, self.server_port))

        # ── Step 2: ServerHello ──────────────────────────────────────
        pkt = self._recv_packet(self.timeout)
        if pkt is None or not (pkt["srft"]["flags"] & FLAG_SYN):
            raise RuntimeError("No ServerHello received")

        enc_key, ack_key, session_id = process_server_hello(
            pkt["srft"]["payload"], client_nonce
        )
        self.session_key = enc_key
        self.session_id  = session_id

        # ── Step 3: request the file ─────────────────────────────────
        self._send_syn(filename)
        syn_sent_at     = time.time()
        got_data        = False
        last_ack_time   = self.start_time
        since_last_ack  = 0
        fin_payload: bytes = b""

        _PROGRESS_INTERVAL = 0.5
        last_progress_time  = self.start_time
        last_progress_bytes = 0

        while True:
            pkt = self._recv_packet(self.timeout)

            if pkt is None:
                if not got_data:
                    if time.time() - syn_sent_at >= self.timeout:
                        print("No response from server, resending SYN...")
                        self._send_syn(filename)
                        syn_sent_at = time.time()
                else:
                    self._send_ack(self.next_expected)
                    last_ack_time  = time.time()
                    since_last_ack = 0
                continue

            if pkt["src_ip"] != self.server_ip or pkt["src_port"] != self.server_port:
                continue

            flags   = pkt["srft"]["flags"]
            seq     = pkt["srft"]["seq_num"]
            payload = pkt["srft"]["payload"]
            self.pkts_received += 1
            got_data = True

            if flags & FLAG_DATA:
                if seq == self.next_expected:
                    self.chunks[seq] = payload
                    self.bytes_received += len(payload)
                    self.next_expected  += 1
                    since_last_ack      += 1

                    while self.next_expected in self.recv_buf:
                        chunk = self.recv_buf.pop(self.next_expected)
                        self.chunks[self.next_expected] = chunk
                        self.bytes_received += len(chunk)
                        self.next_expected  += 1
                        since_last_ack      += 1

                    now = time.time()
                    if since_last_ack >= self.ACK_BATCH_SIZE or (now - last_ack_time) >= self.ACK_DELAY:
                        self._send_ack(self.next_expected)
                        last_ack_time  = now
                        since_last_ack = 0

                    if now - last_progress_time >= _PROGRESS_INTERVAL:
                        last_progress_time, last_progress_bytes = self._print_progress(
                            last_progress_time, last_progress_bytes
                        )

                elif seq > self.next_expected:
                    if seq not in self.recv_buf and seq not in self.chunks:
                        self.recv_buf[seq] = payload
                    self._send_ack(self.next_expected)
                    last_ack_time  = time.time()
                    since_last_ack = 0

                else:
                    self._send_ack(self.next_expected)

            elif flags & FLAG_FIN:
                if since_last_ack > 0:
                    self._send_ack(self.next_expected)
                self.fin_seq  = seq
                fin_payload   = payload
                self._send_ack(seq + 1)
                self._print_progress(last_progress_time, last_progress_bytes)
                print()
                print(f"FIN received (seq={seq}), transfer complete.")
                break

            elif flags & FLAG_ERR:
                print(f"Server error: {payload.decode(errors='replace')}")
                return

        for _ in range(3):
            self._send_ack(self.fin_seq + 1)
            time.sleep(0.05)

        self.end_time = time.time()
        self._write_file(filename, fin_payload)
        self._write_report(filename)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_file(self, filename: str, fin_payload: bytes) -> None:
        """Verify the file digest, then write to disk."""
        if not self.chunks:
            print("Warning: no data received.")
            return

        max_seq   = max(self.chunks.keys())
        file_data = b"".join(
            self.chunks[i] for i in range(max_seq + 1) if i in self.chunks
        )

        verified = verify_transfer(
            fin_payload,
            file_data,
            AESGCM(self.session_key),
            b"\x00" * 12,
        )
        if not verified:
            print("WARNING: File integrity check FAILED — received file may be corrupt!")
        else:
            print("Integrity check: PASS")

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
        session_suffix = self.session_id.hex() if hasattr(self, "session_id") else "unknown"
        report_path = (self.output_dir / f"client_transfer_report_{session_suffix}.txt")
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Report       : {report_path}")

    def _send_syn(self, filename: str) -> None:
        """Send a SYN packet carrying the filename."""
        srft_payload = build_srft_packet(FLAG_SYN, 0, 0, filename.encode())
        self.sock.sendto(self._build_packet(srft_payload), (self.server_ip, self.server_port))

    def _send_ack(self, ack_num: int) -> None:
        """Send a cumulative ACK with SACK blocks for any buffered out-of-order data."""
        srft_payload = build_srft_packet(FLAG_ACK, 0, ack_num, self._build_sack_payload())
        self.sock.sendto(self._build_packet(srft_payload), (self.server_ip, self.server_port))
        self.acks_sent += 1

    def _build_sack_payload(self) -> bytes:
        """Encode buffered out-of-order sequence numbers as SACK blocks (max 8)."""
        if not self.recv_buf:
            return b""
        seqs   = sorted(self.recv_buf.keys())
        ranges: list[tuple[int, int]] = []
        start = end = seqs[0]
        for s in seqs[1:]:
            if s == end + 1:
                end = s
            else:
                ranges.append((start, end + 1))
                start = end = s
        ranges.append((start, end + 1))
        result = b""
        for s, e in ranges[:8]:
            result += struct.pack("!II", s, e)
        return result

    def _print_progress(self, last_time: float, last_bytes: int) -> tuple[float, int]:
        """Print a throughput/elapsed progress line (no total size known on client)."""
        now           = time.time()
        current_bytes = self.bytes_received
        elapsed       = now - self.start_time

        delta_t     = now - last_time
        delta_bytes = current_bytes - last_bytes
        if delta_t > 0 and delta_bytes > 0:
            speed = delta_bytes / delta_t
        elif elapsed > 0:
            speed = current_bytes / elapsed
        else:
            speed = 0.0

        elapsed_str = str(timedelta(seconds=int(elapsed)))
        print(
            f"\rReceived {format_bytes(current_bytes)} | "
            f"{format_bytes(speed)}/s | Elapsed {elapsed_str}   ",
            end="",
            flush=True,
        )
        return now, current_bytes

    def _recv_packet(self, timeout: float) -> dict | None:
        """
        Wait up to `timeout` seconds for a valid SRFT packet.

        Decrypts DATA payloads after the handshake is complete.
        SYN and FIN packets are never decrypted (they are not encrypted).
        """
        readable, _, _ = select.select([self.recv_sock], [], [], timeout)
        if not readable:
            return None

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

        # Only DATA packets are encrypted — never SYN, FIN, ACK, or ERR
        if hasattr(self, "session_key") and (srft["flags"] & FLAG_DATA):
            try:
                srft["payload"] = decrypt(
                    srft["payload"],
                    self.session_key,
                    self.session_id,
                    srft["seq_num"],
                    srft["flags"],
                    srft["ack_num"],
                )
            except InvalidTag:
                return None

        return {"src_ip": src_ip, "src_port": src_port, "srft": srft}

    def _build_packet(self, srft_payload: bytes) -> bytes:
        """Build a complete IPv4 + UDP + SRFT packet."""
        udp_hdr   = UDPHeader(src_port=self.src_port, dst_port=self.server_port)
        udp_bytes = udp_hdr.to_bytes_with_checksum(srft_payload, self.src_ip, self.server_ip)
        udp_pkt   = udp_bytes + srft_payload
        ip_hdr    = self._build_ip_header(IP_HEADER_SIZE + len(udp_pkt))
        return ip_hdr + udp_pkt

    def _build_ip_header(self, total_len: int) -> bytes:
        """Construct an IPv4 header with correct checksum (handles macOS byte-order quirk)."""
        version_ihl = (4 << 4) + 5
        pkt_id      = self.ip_pkt_id & 0xFFFF
        self.ip_pkt_id += 1
        src = socket.inet_aton(self.src_ip)
        dst = socket.inet_aton(self.server_ip)

        if platform.system() == "Darwin":
            hdr_no_chk = (
                struct.pack("!BB", version_ihl, 0) +
                struct.pack("=H", total_len) +
                struct.pack("!H", pkt_id) +
                struct.pack("=H", 0) +
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def main() -> None:
    if os.geteuid() != 0:
        print("Error: raw sockets require root. Run with sudo.")
        sys.exit(1)

    kw: dict[str, str] = {}
    for arg in sys.argv[1:]:
        if "=" in arg:
            k, v = arg.split("=", 1)
            kw[k] = v

    filename = kw.get("filename")
    if not filename:
        print(
            "Usage: sudo python srft_udpclient.py filename=<name> "
            "[dest_ip=<ip>] [dest_port=<port>] [src_port=<port>] [timeout=<sec>]"
        )
        sys.exit(1)

    client = SRFTUDPClient(
        src_ip      = kw.get("src_ip", get_local_ip()),
        src_port    = int(kw.get("src_port", str(SRFT_PORT))),
        server_ip   = kw.get("dest_ip", get_local_ip()),
        server_port = int(kw.get("dest_port", "9000")),
        timeout     = float(kw.get("timeout", "2.0")),
    )
    client.request_file(filename)


if __name__ == "__main__":
    main()