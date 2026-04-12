# CS5700 Computer Networking Final Project Spring 2026 Group 14
This repository contains our implementation of a Simple Reliable File Transfer (SRFT) protocol built on top of UDP using raw sockets, developed for Northeastern University's CS 5700 – Computer Networking course.

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
| `srft_udpserver.py` | SRFT server: Go-Back-N sender over raw UDP with PSK handshake and AES-256-GCM encryption |
| `srft_udpclient.py` | SRFT client: Go-Back-N receiver over raw UDP with PSK handshake, decryption, and file verification |
| `srft_packet.py` | Shared packet utilities (build, parse, checksum) |
| `header.py` | UDP header construction and checksum |
| `config.py` | Shared constants, protocol parameters, and Pre-Shared Key (PSK) |
| `security_psk.py` | PSK cryptographic primitives: nonce generation, HMAC-SHA256, HKDF key derivation, AES-256-GCM encrypt/decrypt |
| `client_hello.py` | Builds the ClientHello handshake message and processes the ServerHello response |
| `server_hello.py` | Processes the ClientHello message and builds the ServerHello response |
| `verification.py` | End-to-end file integrity verification using SHA-256 + AES-GCM |

---

# How to Run Locally

## Prerequisites

- Python 3.10 or higher
- **Root / Administrator privileges** are required because the program uses raw sockets
- The `cryptography` package is required for AES-256-GCM encryption:

```bash
pip install cryptography
```

---

## macOS

### Step 1 — Find your local IP address

Open a terminal and run:

```bash
python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80)); print(s.getsockname()[0])"
```

This prints your machine's active local IP (e.g. `192.168.1.42`). Use this value in the commands below — **do not use `127.0.0.1`**, as macOS does not reliably deliver raw socket packets on the loopback interface.

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

Replace `<filename>` with the name of the file you want to transfer (e.g. `sample.txt`). The file must be present in the server's working directory.

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

Both hashes must match. The client also performs an automatic end-to-end integrity check using the SHA-256 digest carried in the FIN packet and will print `Integrity check: PASS` or a warning if the check fails.

Transfer reports are written with the session ID appended to the filename for easy pairing:
- Server: `transfer_report_<session_id>.txt`
- Client: `client_transfer_report_<session_id>.txt`

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
| `--window` | `64` | Go-Back-N sliding window size |
| `--timeout` | `0.05` | Retransmission timeout in seconds |

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

### Step 2 — Install Python and dependencies inside WSL2

Open the Ubuntu terminal from the Start Menu and run:

```bash
sudo apt update && sudo apt install -y python3 python3-pip
pip install cryptography
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
ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

Then substitute that IP for `<your-local-ip>` in the server and client commands.

# How to Run in AWS
## Set Up
1. Sign into the group [AWS Account](https://388147131160.signin.aws.amazon.com/console)
2. Navigate to the [EC2 US-East-2 Landing Page](https://us-east-2.console.aws.amazon.com/ec2/home?region=us-east-2#Instances)
3. Create a key-pair following the [AWS Key Pair documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html) for each instance. Recommended to store the `.pem` files in the project root. They are automatically ignored by the `.gitignore` file.

## EC2 Access & Running the Code

### SRFT Server
#### Login
```bash
ssh -i <Server Key Pair Name>.pem ubuntu@3.147.82.30
```

Example if your key-pair is named `srft-server-keypair.pem`:
```bash
ssh -i srft-server-keypair.pem ubuntu@3.147.82.30
```

#### Running the Server
```bash
sudo python3 srft.py server --ip 172.31.1.158
```

### SRFT Client
#### Login
```bash
ssh -i <Client Key Pair Name>.pem ubuntu@3.141.2.243
```

Example if your key-pair is named `srft-client-keypair.pem`:
```bash
ssh -i srft-client-keypair.pem ubuntu@3.141.2.243
```

#### Running the Client
```bash
sudo python3 srft.py client <Requesting File Name> --dest-ip 172.31.1.158
```

Example request for the `sample.txt` file:
```bash
sudo python3 srft.py client sample.txt --dest-ip 172.31.1.158
```

## Migrate Code to the EC2 Instances
1. Log into the EC2 instances following the steps above.
2. Run `rm -rf ~/cs5700_final_project_sp2026_group14` to remove the existing copy of the code on the EC2.
3. Open a new terminal **on your local machine** and run the following commands:
    - Server: `scp -r -i srft-server-keypair.pem . ubuntu@3.147.82.30:~/cs5700_final_project_sp2026_group14`
    - Client: `scp -r -i cs5700_final_project_sp2026_group14/srft-client-keypair.pem cs5700_final_project_sp2026_group14 ubuntu@3.141.2.243:~`
4. If successful, the code will now be in the home directory of the EC2 instance.
5. On **each** EC2 instance, install the required Python dependency:
```bash
sudo apt install python3-cryptography
```