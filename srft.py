"""
SRFT CLI

Single entry point for starting the SRFT server or client.

Usage:
    sudo python3 srft.py server [--ip IP] [--port PORT] [--window N] [--timeout SEC]
                                [--attack {tamper,replay,inject}]
    sudo python3 srft.py client FILENAME [--dest-ip IP] [--dest-port PORT]
                                         [--src-ip IP] [--src-port PORT] [--timeout SEC]

Examples:
    sudo python3 srft.py server --ip 192.168.1.10
    sudo python3 srft.py server --ip 192.168.1.10 --attack tamper
    sudo python3 srft.py client sample.txt --dest-ip 192.168.1.10

Attack modes (security test plan):
    tamper  — flip 2 bytes in one DATA packet payload; tests checksum / AEAD detection
    replay  — re-send one captured DATA packet as a duplicate; tests replay protection
    inject  — inject a forged packet with random bytes; tests authentication failure handling
"""

from __future__ import annotations

import argparse
import os
import socket
import sys

from config import SRFT_PORT
from srft_udpclient import SRFTUDPClient
from srft_udpserver import SRFTUDPServer


def get_local_ip() -> str:
    """Detect the primary local IP address by routing to a public host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def cmd_server(args: argparse.Namespace) -> None:
    ip = args.ip or get_local_ip()
    server = SRFTUDPServer(
        bind_ip=ip,
        bind_port=args.port,
        window_size=args.window,
        timeout_seconds=args.timeout,
        attack=args.attack,
    )
    server.serve_forever()


def cmd_client(args: argparse.Namespace) -> None:
    dest_ip = args.dest_ip or get_local_ip()
    src_ip  = args.src_ip  or get_local_ip()
    client = SRFTUDPClient(
        src_ip=src_ip,
        src_port=args.src_port,
        server_ip=dest_ip,
        server_port=args.dest_port,
        timeout=args.timeout,
    )
    client.request_file(args.filename)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="srft",
        description="Secure Reliable File Transfer over raw UDP",
    )
    parser.add_argument(
        "--version", action="version", version="SRFT Phase 1"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # --- server ---
    sp = sub.add_parser("server", help="start the SRFT server")
    sp.add_argument(
        "--ip",
        default=None,
        metavar="IP",
        help="IP address to bind (default: auto-detected local IP)",
    )
    sp.add_argument(
        "--port",
        type=int,
        default=9000,
        metavar="PORT",
        help="UDP port to listen on (default: 9000)",
    )
    sp.add_argument(
        "--window",
        type=int,
        default=64,
        metavar="N",
        help="Go-Back-N window size (default: 64)",
    )
    sp.add_argument(
        "--timeout",
        type=float,
        default=0.05,
        metavar="SEC",
        help="retransmission timeout in seconds (default: 0.05)",
    )
    sp.add_argument(
        "--attack",
        choices=["tamper", "replay", "inject"],
        default=None,
        metavar="MODE",
        help=(
            "built-in attack mode for security testing: "
            "tamper (flip 2 payload bytes), "
            "replay (resend one captured packet), "
            "inject (send a forged packet)"
        ),
    )
    sp.set_defaults(func=cmd_server)

    # --- client ---
    cp = sub.add_parser("client", help="request a file from the SRFT server")
    cp.add_argument("filename", help="name of the file to request from the server")
    cp.add_argument(
        "--dest-ip",
        default=None,
        metavar="IP",
        help="server IP address (default: auto-detected local IP)",
    )
    cp.add_argument(
        "--dest-port",
        type=int,
        default=9000,
        metavar="PORT",
        help="server UDP port (default: 9000)",
    )
    cp.add_argument(
        "--src-ip",
        default=None,
        metavar="IP",
        help="source IP address (default: auto-detected local IP)",
    )
    cp.add_argument(
        "--src-port",
        type=int,
        default=SRFT_PORT,
        metavar="PORT",
        help=f"source UDP port (default: {SRFT_PORT})",
    )
    cp.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        metavar="SEC",
        help="receive timeout in seconds (default: 2.0)",
    )
    cp.set_defaults(func=cmd_client)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: raw sockets require root. Run with sudo.")
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
