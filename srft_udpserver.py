"""
SRFT UDP Server Implementation.

This module implements a server to send UDP Data on top of raw UDP sockets. 
The server expects a client request packet containing a file name, then sends 
the file in numbered data packets and handles ACKs and retransmissions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import os
import platform
import select
import socket
import struct
import threading
import time
from pathlib import Path

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
from srft_packet import build_srft_packet, ip_checksum, is_corrupt, parse_srft_packet

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
            Note this can be overridden by passing a different path to the constructor
            but defaults to the global REPORT_PATH constant.
    """

    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        window_size: int = 64,
        timeout_seconds: float = 0.05,

        # Allow chun_size and report_path to be overridden by constructor parameters
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        report_path: str = REPORT_PATH,
    ) -> None:
        
        # Validate constructor parameters to ensure they are within expected ranges and types
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

        # Raw socket used exclusively for SENDING — allows us to build custom IP+UDP headers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Regular UDP socket used exclusively for RECEIVING.
        # On macOS, raw sockets do not receive packets sent from processes on the same machine
        # because the kernel routes same-machine traffic through an internal loopback path that
        # bypasses raw socket delivery.  A SOCK_DGRAM socket is registered with the kernel's UDP
        # demultiplexer and reliably receives any properly-addressed UDP packet, including those
        # injected by raw sockets on the same host.
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind((self.bind_ip, self.bind_port))

        # Initialize threading and synchronization variables for managing the file transfer
        self.transfer_lock = threading.Lock()
        self.transfer_complete = threading.Event()
        self.stop_receiver = threading.Event()

        # Initialize per-transfer state variables that will be reset for each new client request
        self.client_ip = ""
        self.client_port = 0
        self.requested_file = ""
        self.file_size = 0
        self.file_chunks: list[bytes] = []
        self.fin_seq_num = 0
        self.fin_acked = False
        self.fin_packet: SentPacket | None = None
        self.ip_packet_id = 0

        # Initialize Go-Back-N sender state variables for tracking the sliding window and unacknowledged packets
        self.send_base = 0
        self.next_seq_num = 0
        self.unacked_packets: dict[int, SentPacket] = {}

        # Initialize counters and timestamps for the transfer report
        self.packets_sent_count = 0
        self.retransmissions_count = 0
        self.packets_received_count = 0
        self.transfer_start_time = 0.0
        self.transfer_end_time = 0.0

    def serve_forever(self) -> None:
        """
        Run the server loop and process one request at a time
        """

        print(f"SRFT server listening on {self.bind_ip}:{self.bind_port}")

        # Run the server indefinitely waiting for client requests
        while True:
            
            #####################################################
            # Waiting and validating client requests
            #####################################################

            # Wait for a SYN packet from a client to initiate a file transfer request
            packet_info = self._receive_srft_packet(timeout=None)

            # If the received packet is None (due to timeout or parsing error), ignore and continue waiting
            if packet_info is None:
                continue

            # Validate that the packet is a SYN packet and contains a valid filename in the payload
            srft_packet = packet_info["srft_packet"]

            # Extract the flags from the SRFT packet and check if the SYN flag is set
            flags = int(srft_packet["flags"])

            # If the SYN flag is not set, this packet is not a valid file transfer request
            if not flags & FLAG_SYN:
                continue

            # Extract the payload from the SRFT packet, which should contain the requested filename
            payload = srft_packet["payload"]

            # Validate that the payload is bytes and can be decoded into a string filename
            if not isinstance(payload, bytes):
                continue

            # Decode the filename from the payload, stripping any whitespace to prevent errors
            filename = payload.decode(errors="replace").strip()

            #####################################################
            # Handle the valid file transfer requests
            #####################################################
            self.handle_request(
                filename=filename,
                client_ip=str(packet_info["src_ip"]),
                client_port=int(packet_info["src_port"]),
            )

    def handle_request(self, filename: str, client_ip: str, client_port: int) -> None:
        """
        Handle a file transfer request from a client by sending the requested file in SRFT 
        data packets and managing ACKs

        Args:
            filename: The name of the file requested by the client
            client_ip: The IP address of the client making the request
            client_port: The port number of the client making the request
        """

        # Reset all per-transfer state before starting to handle the new request
        self._reset_transfer_state()

        # Store the client information and requested filename for use in the transfer
        self.client_ip = client_ip
        self.client_port = client_port
        self.requested_file = filename

        # Validate that the requested file exists and is a regular file before attempting to read it
        file_path = Path(filename)

        # If the file does not exist or is not a regular file, send an error packet back to the client
        if not file_path.exists() or not file_path.is_file():
            self._send_control_packet(
                flags=FLAG_ERR,
                seq_num=0,
                ack_num=0,
                payload=f"file not found: {filename}".encode(),
            )
            return

        # Read the entire file into memory and split it into chunks for sending in SRFT data packets
        with file_path.open("rb") as file_handle:
            file_bytes = file_handle.read()

        # Store the file size and the list of file chunks that will be sent in the data packets
        self.file_size = len(file_bytes)
        self.file_chunks = self._segment_file(file_bytes)

        # The FIN packet will have a sequence number one greater than the last data packet
        # Precompute this value for use in the sender loop
        self.fin_seq_num = len(self.file_chunks)
        self.transfer_start_time = time.time()

        # Start the sender and receiver threads for this file transfer
        # The receiver thread will run in the background to process ACKs
        receiver_thread = threading.Thread(target=self._ack_receiver_loop, daemon=True)

        # The sender thread will run the main loop for sending data packets and handling exceptions
        sender_thread = threading.Thread(target=self._sender_loop, daemon=True)

        # Start the threads
        receiver_thread.start()
        sender_thread.start()

        # Join the sender thread to wait for it to complete the file transfer
        sender_thread.join()

        # Once the sender thread has completed, signal the receiver thread to stop
        self.stop_receiver.set()

        # Join the receiver thread with a timeout to ensure it does not block indefinitely
        receiver_thread.join(timeout=1.0)

        # Record the end time of the transfer and write the transfer report
        self.transfer_end_time = time.time()
        self.write_report()

    def send_window(self) -> None:
        """
        Send new packets while the sliding window has available space.
        """

        with self.transfer_lock:
            while (
                self.next_seq_num < len(self.file_chunks)
                and self.next_seq_num < self.send_base + self.window_size
            ):
                seq_num = self.next_seq_num
                payload = self.file_chunks[seq_num]
                srft_payload = build_srft_packet(
                    flags=FLAG_DATA,
                    seq_num=seq_num,
                    ack_num=self.send_base,
                    payload=payload,
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
        """
        Retransmit every unacked packet currently in the sender window.
        """

        with self.transfer_lock:
            for seq_num in range(self.send_base, self.next_seq_num):
                sent_packet = self.unacked_packets.get(seq_num)
                if sent_packet is None or sent_packet.acked:
                    continue

                self._send_stored_packet(sent_packet, is_retransmission=True)

    def process_ack(self, ack_num: int, sack_payload: bytes = b"") -> None:
        """
        Process a cumulative acknowledgement number from the client.

        Args:
            ack_num: The cumulative ACK number received from the client, indicating that all packets
            with sequence numbers less than ack_num have been received successfully. This method will
            mark packets as acknowledged and slide the window accordingly.
            sack_payload: Optional SACK block bytes from the ACK payload encoding out-of-order
            received ranges as [start(4B)][end(4B)] pairs. Used to skip already-received packets
            during Go-Back-N retransmission.
        """

        # Called by the ACK receiver thread when an ACK packet is received from the client
        with self.transfer_lock:

            # If the ACK number is less than or equal to the current send_base it is a duplicate,
            # but still apply any SACK info to avoid redundant retransmissions
            if ack_num <= self.send_base:
                self._apply_sack(sack_payload)
                return

            # Mark all packets with sequence numbers less than the ACK number as acknowledged and remove
            # them from the unacked_packets dictionary
            upper_bound = min(ack_num, self.fin_seq_num + 1)
            for seq_num in list(self.unacked_packets):
                if seq_num < upper_bound:
                    self.unacked_packets[seq_num].acked = True
                    del self.unacked_packets[seq_num]

            # If the ACK number is greater than the current send_base, slide the window forward by updating
            # the send_base to the ACK number. This allows new packets to be sent in the next iteration of the sender loop.
            if ack_num > self.send_base:
                self.send_base = ack_num

            # Apply SACK blocks to mark any out-of-order packets already received by the client
            self._apply_sack(sack_payload)

            # If the ACK number acknowledges the FIN packet, mark the FIN as acknowledged and check if the transfer is complete
            if ack_num > self.fin_seq_num:
                self.fin_acked = True
                self.transfer_complete.set()

            # If the send_base has advanced past the last data packet and the FIN has been acknowledged, the transfer is complete
            if self.send_base >= self.fin_seq_num and self.fin_acked:
                self.transfer_complete.set()

    def _apply_sack(self, sack_payload: bytes) -> None:
        """
        Mark out-of-order packets already received by the client as acknowledged.

        Called with self.transfer_lock held. Parses SACK blocks encoded as
        [start_seq(4B)][end_seq(4B)] pairs and removes the corresponding packets
        from unacked_packets so retransmit_from_base skips them.

        Args:
            sack_payload: Raw SACK bytes from the ACK packet payload.
        """
        if not sack_payload or len(sack_payload) % 8 != 0:
            return
        n_blocks = len(sack_payload) // 8
        for i in range(n_blocks):
            start, end = struct.unpack("!II", sack_payload[i * 8 : (i + 1) * 8])
            for seq in range(start, end):
                pkt = self.unacked_packets.get(seq)
                if pkt is not None:
                    pkt.acked = True
                    del self.unacked_packets[seq]

    def write_report(self) -> None:
        """
        Write the required Phase 1 transfer report to disk.
        """

        # Compute the duration of the transfer in seconds and format it as hh:mm:ss for the report
        duration_seconds = max(0, int(self.transfer_end_time - self.transfer_start_time))
        duration_text = str(timedelta(seconds=duration_seconds))

        # Generate report lines about the transfer and write them to the specified report file path
        lines = [
            f"Name of the transferred file: {self.requested_file}",
            f"Size of the transferred file: {self.file_size}",
            f"The number of packets sent from the server: {self.packets_sent_count}",
            f"The number of retransmitted packets from the server: {self.retransmissions_count}",
            f"The number of packets received from the client: {self.packets_received_count}",
            f"The time duration of the file transfer (hh:min:ss): {duration_text}",
        ]

        self.report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _print_progress(self, last_time: float, last_base: int) -> tuple[float, int]:
        """
        Render a progress bar in terminal for the current transfer.

        Args:
            last_time: Timestamp of the previous progress print (used to compute throughput).
            last_base: send_base value at the previous progress print.
        Returns:
            (now, current_base) to pass back as last_time/last_base on the next call.
        """
        now = time.time()
        current_base = self.send_base
        total_chunks = len(self.file_chunks)

        if total_chunks == 0:
            return now, current_base

        pct = min(current_base / total_chunks, 1.0)
        acked_bytes = min(current_base * self.chunk_size, self.file_size)
        elapsed = now - self.transfer_start_time

        # Throughput over the last interval
        delta_t = now - last_time
        delta_chunks = current_base - last_base
        if delta_t > 0 and delta_chunks > 0:
            speed = (delta_chunks * self.chunk_size) / delta_t
        elif elapsed > 0:
            speed = acked_bytes / elapsed
        else:
            speed = 0.0

        # ETA
        remaining = self.file_size - acked_bytes
        if speed > 0:
            eta_str = str(timedelta(seconds=int(remaining / speed)))
        else:
            eta_str = "--:--"

        # Build the bar
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
        """
        Main sender loop for file data and FIN handling.
        """

        # This loop runs in the sender thread and is responsible for sending new data packets while the window allows,
        # handling timeouts and retransmissions, and sending the FIN packet when all data has been sent. It also checks
        # for the completion of the transfer when the FIN is acknowledged.
        fin_sent = False
        _PROGRESS_INTERVAL = 0.5  # seconds between progress bar updates
        last_progress_time = time.time()
        last_progress_base = 0

        while not self.transfer_complete.is_set():
            self.send_window()
            
            # Send the FIN packet if all data packets have been sent and the FIN has not been sent yet
            if self.send_base >= len(self.file_chunks) and not fin_sent:
                self.fin_packet = self._build_control_packet(
                    flags=FLAG_FIN,
                    seq_num=self.fin_seq_num,
                    ack_num=self.send_base,
                    payload=b"",
                )
                self._send_stored_packet(self.fin_packet)
                fin_sent = True

            # If the FIN has been sent and acknowledged, the transfer is complete and we can exit the loop
            if fin_sent and self.fin_acked:
                self.transfer_complete.set()
                break

            # Check for timeouts on the oldest unacknowledged packet in the window and retransmit if necessary.
            # Also check for FIN timeout if the FIN has been sent but not acknowledged.
            with self.transfer_lock:
                oldest_packet = self.unacked_packets.get(self.send_base)

            # If there is an oldest unacked packet, check if it has timed out and retransmit if necessary
            if oldest_packet is not None:
                elapsed = time.time() - oldest_packet.sent_at
                if elapsed >= self.timeout_seconds:
                    self.retransmit_from_base()
            # Check for FIN timeout if the FIN has been sent but not acknowledged and retransmit if necessary
            elif fin_sent and self.fin_packet is not None and not self.fin_acked:
                elapsed = time.time() - self.fin_packet.sent_at
                if elapsed >= self.timeout_seconds:
                    self._send_stored_packet(self.fin_packet, is_retransmission=True)

            # Print progress bar every 0.5 seconds
            now = time.time()
            if now - last_progress_time >= _PROGRESS_INTERVAL:
                last_progress_time, last_progress_base = self._print_progress(
                    last_progress_time, last_progress_base
                )

            # Restart loop every 1ms to check for new ACKs and timeouts
            time.sleep(0.001)

        # Final progress update then move to a new line
        self._print_progress(last_progress_time, last_progress_base)
        print()

    def _ack_receiver_loop(self) -> None:
        """
        Background receiver loop that waits for ACK packets from the client.
        """

        # Run a receiver thread that is continuously listening for packets from the client 
        while not self.stop_receiver.is_set():

            # Wait for a packet from the client with a short timeout to allow checking the stop_receiver event
            packet_info = self._receive_srft_packet(timeout=0.1)

            # If the received packet is None (due to timeout or parsing error), ignore and continue waiting
            if packet_info is None:
                continue
            
            # Validate that the packet is from the expected client IP and port before processing it as an ACK
            if packet_info["src_ip"] != self.client_ip or packet_info["src_port"] != self.client_port:
                continue

            # Extract the received packet and flag ID type
            srft_packet = packet_info["srft_packet"]
            flags = int(srft_packet["flags"])

            # If the packet has the ACK flag, process it and update the sender state.
            # Also extract any SACK payload for selective retransmission.
            if flags & FLAG_ACK:
                sack_payload = srft_packet.get("payload", b"")
                if not isinstance(sack_payload, bytes):
                    sack_payload = b""
                self.process_ack(int(srft_packet["ack_num"]), sack_payload)

    def _receive_srft_packet(self, timeout: float | None) -> dict[str, object] | None:
        """
        Receive and validate one SRFT packet via the DGRAM receive socket.

        The DGRAM socket delivers only the UDP payload (the SRFT data), with the IP
        and UDP headers already stripped by the kernel.  The kernel also validates the
        UDP checksum before delivery, so no manual checksum check is needed here.

        Args:
            timeout: Seconds to wait for a packet; None blocks indefinitely.
        Returns:
            A dict with src_ip, src_port, and the parsed srft_packet, or None on
            timeout or any validation failure.
        """

        # Wait for a packet on the DGRAM receive socket
        if timeout is None:
            readable, _, _ = select.select([self.recv_sock], [], [])
        else:
            readable, _, _ = select.select([self.recv_sock], [], [], timeout)

        if not readable:
            return None

        # recvfrom on a DGRAM socket returns (udp_payload, (src_ip, src_port))
        payload, addr = self.recv_sock.recvfrom(65535)
        src_ip, src_port = addr

        if not isinstance(payload, bytes):
            return None

        # Parse and validate the SRFT layer
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
        """
        Split the file into fixed-size chunks for SRFT data packets.

        Args:
            file_bytes: The complete bytes of the file to be transferred
        Returns:
            A list of byte strings, where each byte string is a chunk of the file with a maximum 
            size of self.chunk_size. If the file is empty, returns a list containing a single empty 
            byte string to ensure that at least one data packet is sent with an empty payload.
        """

        # Check if the file is empty and return a list with one empty byte string to ensure we send 
        # a data packet for an empty file
        if not file_bytes:
            return [b""]

        # Split the file bytes into chunks of size self.chunk_size and return the list of chunks
        return [
            file_bytes[index:index + self.chunk_size]
            for index in range(0, len(file_bytes), self.chunk_size)
        ]

    def _build_control_packet(self, flags: int, seq_num: int, ack_num: int, payload: bytes) -> SentPacket:
        """
        Build a control packet that can be sent or retransmitted.

        Args:
            flags: The SRFT flags byte (e.g. FLAG_SYN, FLAG_ACK, etc.)
            seq_num: The sequence number for this packet
            ack_num: The cumulative acknowledgement number for this packet
            payload: The file data or control message to include in the packet
        Returns:
            A SentPacket object containing the sequence number, payload, and complete packet bytes
        """

        # Build the payload using the flags, sequence number, acknowledgement number, and payload data
        srft_payload = build_srft_packet(flags=flags, seq_num=seq_num, ack_num=ack_num, payload=payload)
        
        # Construct the full packet bytes
        packet_bytes = self._build_full_packet(srft_payload)

        # Return a SentPacket object that can be stored for retransmission and sent immediately
        return SentPacket(seq_num=seq_num, payload=payload, packet_bytes=packet_bytes)

    def _send_control_packet(self, flags: int, seq_num: int, ack_num: int, payload: bytes) -> None:
        """
        Build and send a control packet immediately

        Args:
            flags: The SRFT flags byte (e.g. FLAG_SYN, FLAG_ACK, etc.)
            seq_num: The sequence number for this packet
            ack_num: The cumulative acknowledgement number for this packet
            payload: The file data or control message to include in the packet
        """

        # Build the control packet 
        sent_packet = self._build_control_packet(flags=flags, seq_num=seq_num, ack_num=ack_num, payload=payload)

        # Call the send method to send the packet
        self._send_stored_packet(sent_packet)

    def _send_stored_packet(self, sent_packet: SentPacket, is_retransmission: bool = False) -> None:
        """
        Send a previously constructed packet and update counters/timestamps.

        Args:
            sent_packet: SentPacket object containing the sequence number, payload, and complete packet bytes to be sent
            is_retransmission: Boolean flag indicating whether this packet is being sent as a retransmission
        """

        # Send the packet bytes to the client IP and port using the raw socket
        self.sock.sendto(sent_packet.packet_bytes, (self.client_ip, self.client_port))

        # Update the sent_at timestamp of the packet for timeout tracking 
        sent_packet.sent_at = time.time()

        # Increment the count of packets sent
        self.packets_sent_count += 1

        # If this packet is being sent as a retransmission, increment the retransmissions count
        if is_retransmission:
            self.retransmissions_count += 1

    def _build_full_packet(self, srft_payload: bytes) -> bytes:
        """
        Build a complete packet with IPv4 + UDP + SRFT payload

        Args:
            srft_payload: The bytes of the SRFT header and payload to be included in the UDP segment
        Returns:
            The complete bytes of the IPv4 packet containing the UDP segment with the SRFT payload
        """

        # Contruct the UDP header 
        udp_header = UDPHeader(src_port=self.bind_port, dst_port=self.client_port)

        # Compute the UDP checksum over the UDP header and SRFT payload
        udp_bytes = udp_header.to_bytes_with_checksum(srft_payload, self.bind_ip, self.client_ip)

        # Create the UDP packet with the bytes and payload
        udp_packet = udp_bytes + srft_payload

        # Compute the total length of the IPv4 packet for the header 
        total_length = IP_HEADER_SIZE + len(udp_packet)

        # Build the IPv4 header with the total length and return the complete packet bytes
        ip_header = self._build_ip_header(total_length)

        # Return the full header and packet bytes to be sent on the socket
        return ip_header + udp_packet

    def _build_ip_header(self, total_length: int) -> bytes:
        """
        Construct an IPv4 header for a raw UDP packet.

        On macOS/BSD with IP_HDRINCL, the kernel requires ip_len and ip_off to
        be in host byte order rather than network byte order.  All other fields
        remain in network (big-endian) byte order.

        Args:
            total_length: The total length of the IPv4 packet including the header and UDP segment
        Returns:
            The bytes of the IPv4 header with the correct fields set and the checksum computed
        """

        version_ihl = (4 << 4) + 5
        tos = 0
        packet_id = self.ip_packet_id & MAX_IP_PACKET_ID
        self.ip_packet_id += 1
        flags_fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_UDP
        src_ip = socket.inet_aton(self.bind_ip)
        dst_ip = socket.inet_aton(self.client_ip)

        if platform.system() == "Darwin":
            # ip_len and ip_off must be in host byte order on macOS
            hdr_no_chk = (
                struct.pack("!BB", version_ihl, tos) +
                struct.pack("=H", total_length) +                  # ip_len:  host byte order
                struct.pack("!H", packet_id) +                     # ip_id:   network byte order
                struct.pack("=H", flags_fragment_offset) +         # ip_off:  host byte order
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
        """
        Reset transfer state before handling a new request.
        """

        # Clear the transfer complete and stop receiver events
        self.transfer_complete.clear()
        self.stop_receiver.clear()

        # Reset all transfer-state variables
        with self.transfer_lock:
            self.send_base = 0
            self.next_seq_num = 0
            self.unacked_packets = {}

        # Reset client information and file transfer state
        self.requested_file = ""
        self.file_size = 0
        self.file_chunks = []
        self.fin_seq_num = 0
        self.fin_acked = False
        self.fin_packet = None

        # Reset counters and timestamps for the transfer report
        self.packets_sent_count = 0
        self.retransmissions_count = 0
        self.packets_received_count = 0
        self.transfer_start_time = 0.0
        self.transfer_end_time = 0.0


def main() -> None:
    # Read configuration parameters from environment variables with defaults for local testing
    bind_ip = os.environ.get("SRFT_SERVER_IP", "127.0.0.1")
    bind_port = int(os.environ.get("SRFT_SERVER_PORT", "9000"))
    window_size = int(os.environ.get("SRFT_WINDOW_SIZE", "64"))
    timeout_seconds = float(os.environ.get("SRFT_TIMEOUT_SECONDS", "0.05"))

    # Create and start the SRFT UDP server with the specified configuration parameters
    server = SRFTUDPServer(
        bind_ip=bind_ip,
        bind_port=bind_port,
        window_size=window_size,
        timeout_seconds=timeout_seconds,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
