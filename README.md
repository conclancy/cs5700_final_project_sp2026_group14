# CS5700 Computer Networking Final Project Spring 2026 Group 14
This repository contains our implementation of a Simple Reliable File Transfer (SRFT) protocol built on top of UDP using raw sockets, developed for Northeastern University’s CS 5700 – Computer Networking course.

# Group Members
- Connor Clancy (clancy.co@northeastern.edu)
- Cenling Gao (gao.cen@northeastern.edu)
- Drew Greene (greene.d@northeastern.edu)
- Yuesheng Huang (huang.yues@northeastern.edu)

---

# Project Structure

| File | Description |
|---|---|
| `srft.py` | CLI entry point — use this to start the server or client |
| `srft_udpserver.py` | SRFT server: Go-Back-N sender over raw UDP |
| `srft_udpclient.py` | SRFT client: Go-Back-N receiver over raw UDP |
| `srft_packet.py` | Shared packet utilities (build, parse, checksum) |
| `header.py` | UDP header construction and checksum |
| `config.py` | Shared constants and protocol parameters |

---

# How to Run Locally

## Prerequisites

- Python 3.10 or higher
- No third-party packages are required — only Python standard library modules are used
- **Root / Administrator privileges** are required because the program uses raw sockets

---

## macOS

### Step 1 — Find your local IP address

Open a terminal and run:

```bash
python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80)); print(s.getsockname()[0])"
```

This prints your machine’s active local IP (e.g. `192.168.1.42`). Use this value in the commands below — **do not use `127.0.0.1`**, as macOS does not reliably deliver raw socket packets on the loopback interface.

### Step 2 — Start the server

Open a terminal in the project directory and run:

```bash
sudo python3 srft.py server --ip <your-local-ip>
```

The server will print `SRFT server listening on <ip>:9000` and wait for a client request. The file being requested must exist in the directory where the server is running.

### Step 3 — Start the client

Open a **second** terminal in the project directory and run:

```bash
sudo python3 srft.py client <filename> --dest-ip <your-local-ip>
```

Replace `<filename>` with the name of the file you want to transfer (e.g. `sample.txt`). The file must be present in the server’s working directory.

**Example using `sample.txt`:**

```bash
sudo python3 srft.py client sample.txt --dest-ip 192.168.1.42
```

### Step 4 — Verify the transfer

The client writes the received file as `received_<filename>` in the current directory. Compare the MD5 hashes to confirm the file was transferred correctly:

```bash
md5 sample.txt
md5 received_sample.txt
```

Both hashes must match. A transfer report is written to `client_transfer_report.txt` and the server writes its report to `transfer_report.txt`.

---

## CLI Reference

Run `python3 srft.py --help` at any time to see available commands.

### `srft.py server`

```
sudo python3 srft.py server [--ip IP] [--port PORT] [--window N] [--timeout SEC]
```

| Flag | Default | Description |
|---|---|---|
| `--ip` | auto-detected | IP address the server binds to |
| `--port` | `9000` | UDP port to listen on |
| `--window` | `5` | Go-Back-N sliding window size |
| `--timeout` | `0.5` | Retransmission timeout in seconds |

### `srft.py client`

```
sudo python3 srft.py client FILENAME [--dest-ip IP] [--dest-port PORT] [--src-ip IP] [--src-port PORT] [--timeout SEC]
```

| Flag | Default | Description |
|---|---|---|
| `FILENAME` | *(required)* | Name of the file to request from the server |
| `--dest-ip` | auto-detected | Server IP address |
| `--dest-port` | `9000` | Server UDP port |
| `--src-ip` | auto-detected | Local IP address to send from |
| `--src-port` | `12345` | Local UDP port to send from |
| `--timeout` | `2.0` | Receive timeout in seconds |

---

## Windows

Windows blocks raw socket **sending** for `SOCK_RAW` + `IPPROTO_UDP` since Windows XP SP2 (the call fails with `WSAEACCES` even as Administrator). Because this project requires raw socket send and receive on both client and server, **native Windows is not supported**.

The recommended approach on Windows is to run the project inside **WSL2** (Windows Subsystem for Linux), which provides a full Linux kernel and supports raw sockets correctly.

### Step 1 — Install WSL2

If WSL2 is not already installed, open PowerShell as Administrator and run:

```powershell
wsl --install
```

Restart your machine when prompted. This installs Ubuntu by default.

### Step 2 — Install Python inside WSL2

Open the Ubuntu terminal from the Start Menu and run:

```bash
sudo apt update && sudo apt install -y python3 python3-pip
```

### Step 3 — Clone or copy the project into WSL2

Option A — clone the repo directly inside WSL2:

```bash
git clone <repo-url>
cd cs5700_final_project_sp2026_group14
```

Option B — access your Windows files through the WSL2 mount path:

```bash
cd /mnt/c/Users/<your-windows-username>/path/to/project
```

### Step 4 — Run the server and client

From inside WSL2, follow the **macOS instructions above** exactly — the commands are identical. Use `ip addr` to find your WSL2 IP address if needed:

```bash
ip addr show eth0 | grep "inet " | awk ‘{print $2}’ | cut -d/ -f1
```

Then substitute that IP for `<your-local-ip>` in the server and client commands.
