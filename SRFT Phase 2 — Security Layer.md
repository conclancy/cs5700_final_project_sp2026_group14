# SRFT Phase 2 — Security Layer

## Implementation Documentation

---

## File Structure and Responsibilities

| File | Responsibility |
|---|---|
| `config.py` | Centralised constants, the Pre-Shared Key (PSK), and the `format_bytes` utility. |
| `security_psk.py` | PSK cryptographic primitives: nonce generation, HMAC-SHA256, HKDF key derivation, and AES-256-GCM encrypt/decrypt. |
| `client_hello.py` | Builds the ClientHello packet and processes the ServerHello response; derives session keys on the client side. |
| `server_hello.py` | Processes the ClientHello packet, builds the ServerHello response, and derives session keys on the server side. |
| `verification.py` | End-to-end file integrity verification using SHA-256 + AES-GCM, transmitted in the FIN packet payload. |

---

## `config.py`

### Key constant: PSK

```python
PSK = b"H34TzTGjeesW7zcP83KXTMm43d8Y4Vok"
```

The PSK is hard-coded here intentionally. Both programs share one copy of `config.py`, so the value is always identical on both sides. The project specification permits storing the PSK in a configuration file.

### Security-related constants

```python
CLIENT_NONCE_SIZE = 16   # bytes
SERVER_NONCE_SIZE = 16   # bytes
SESSION_ID_SIZE   = 8    # bytes
```

---

## `security_psk.py`

### `generate_nonce(length)`

Returns `os.urandom(length)` — a cryptographically secure random byte string. Used by both sides to generate nonces for the handshake.

### `compute_hmac(data)` / `verify_hmac(data, received_hmac)`

Computes or verifies `HMAC-SHA256(PSK, data)`. The PSK acts as the signing key. `verify_hmac` uses `hmac.compare_digest` for constant-time comparison, preventing timing-based side-channel attacks.

### `hkdf_extract_expand(client_nonce, server_nonce)`

Derives two independent 32-byte session keys from the PSK and the two handshake nonces using HKDF-SHA256:

```
# Step 1 — Extract
ikm = client_nonce + server_nonce
prk = HMAC-SHA256(salt=PSK, data=ikm)

# Step 2 — Expand (run twice with different info strings)
enc_key = HMAC-SHA256(prk, b"SRFT enc key" + 0x01)[:32]
ack_key = HMAC-SHA256(prk, b"SRFT ack key" + 0x02)[:32]
```

Returns `(enc_key, ack_key)`:
- `enc_key` — 32-byte key for AES-256-GCM encryption of DATA packets and the FIN digest.
- `ack_key` — 32-byte key reserved for ACK authentication (available for future use).

Different info strings and counter bytes ensure `enc_key` and `ack_key` are cryptographically independent even though they share the same PRK.

### `encrypt(data, key, session_id, seq_num, flags, ack_num)`

Encrypts `data` using AES-256-GCM. The `session_id`, `seq_num`, `ack_num`, and `flags` are passed as GCM associated data — they are authenticated by the tag but not encrypted, so any tampering with SRFT header fields will cause decryption to fail.

Wire format produced:

```
[ nonce (12 B) ][ ciphertext (N B) ][ GCM tag (16 B) ]
```

### `decrypt(blob, key, session_id, seq_num, flags, ack_num)`

Verifies and decrypts a blob produced by `encrypt()`. Raises `cryptography.exceptions.InvalidTag` if the key, associated data, or ciphertext has been tampered with.

### Encryption scope

Only `FLAG_DATA` packets are encrypted. Control packets (`FLAG_SYN`, `FLAG_SYN|FLAG_ACK`, `FLAG_FIN`, `FLAG_ACK`, `FLAG_ERR`) are never encrypted — they carry no sensitive file data and must be readable before the session key is established.

---

## `client_hello.py`

### `build_client_hello()`

Constructs the ClientHello packet and returns it together with the client nonce (kept for the KDF step).

Wire format:

```
| version (1B) | cipher (1B) | client_nonce (16B) | HMAC-SHA256 (32B) |
  <-------------- payload covered by HMAC (18B) -------------->
```

**Struct format: `"!BB16s"`**

| Token | Field |
|---|---|
| `!` | Network byte order (Big-Endian) |
| `B` | `version` — value `1` |
| `B` | `cipher` — value `1` (AES-256-GCM) |
| `16s` | `client_nonce` — 16 random bytes |

### `process_server_hello(packet, client_nonce)`

Validates the ServerHello and derives session keys. Returns `(enc_key, ack_key, session_id)`.

Steps:
1. Split the last 32 bytes as the received HMAC.
2. Call `verify_hmac(payload, received_mac)` — raise immediately if invalid.
3. Unpack with `"!16s8s"` to get `server_nonce` and `session_id`.
4. Call `hkdf_extract_expand(client_nonce, server_nonce)` to derive `(enc_key, ack_key)`.

---

## `server_hello.py`

### `process_client_hello(packet)`

Processes the ClientHello, builds the ServerHello response, and derives session keys. Returns `(response_packet, enc_key, ack_key, session_id, client_nonce)`.

Steps:
1. Split the last 32 bytes as the received HMAC — reject immediately if invalid.
2. Unpack with `"!BB16s"` to get `version`, `cipher`, and `client_nonce`.
3. Generate `server_nonce = os.urandom(16)` and `session_id = os.urandom(8)`.
4. Pack the ServerHello payload with `"!16s8s"`, compute its HMAC, and append it.
5. Call `hkdf_extract_expand(client_nonce, server_nonce)` to derive `(enc_key, ack_key)`.

ServerHello wire format:

```
| server_nonce (16B) | session_id (8B) | HMAC-SHA256 (32B) |
```

---

## `verification.py`

### `encrypt_file(file_bytes, aead_obj, nonce)`

Called on the server side when building the FIN packet. Computes a SHA-256 digest of the complete file, then encrypts it with AES-GCM using the session key. The encrypted digest is carried as the FIN payload.

### `verify_transfer(encrypted_data, assembled_packet, aead_obj, nonce)`

Called on the client side after assembling the received file. Decrypts the digest from the FIN payload, independently computes a SHA-256 digest of the assembled file, and compares the two. Returns `True` if the file arrived intact, `False` otherwise.

Both sides use a fixed nonce of `b"\x00" * 12` for the digest encryption. This is safe because it is a one-time verification blob transmitted over an already-authenticated, per-session encrypted channel.

---

## Handshake Flow

```
Client                                      Server
  |                                            |
  |── SYN (ClientHello payload) ──────────────>|  verify HMAC, derive keys
  |                                            |
  |<── SYN+ACK (ServerHello payload) ──────────|  client verifies HMAC, derives keys
  |                                            |
  |── SYN (filename) ──────────────────────────>|  both sides now share session_key + session_id
  |                                            |
  |<── DATA (encrypted chunks) ────────────────|
  |── ACK + SACK ──────────────────────────────>|
  |              ...                           |
  |<── FIN (encrypted SHA-256 digest) ─────────|
  |── ACK ─────────────────────────────────────>|
  |                                            |
  client verifies digest, writes file
```

---

## Transfer Reports

Transfer reports are named with the session ID appended so that the server and client reports for a given session can be easily paired:

- Server: `transfer_report_<session_id>.txt`
- Client: `client_transfer_report_<session_id>.txt`

The session ID is the 8-byte random value generated by the server during the handshake, rendered as a 16-character hex string (e.g. `transfer_report_a3f2b91c44e07d5a.txt`).

---

## Dependency

```bash
pip install cryptography
```

The `cryptography` library provides the production-quality AES-GCM implementation used by `security_psk.py` and `verification.py`.