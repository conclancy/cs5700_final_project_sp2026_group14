# SRFT Phase 2 — Security Layer



## Implementation Documentation

------

## File Structure and Responsibilities

| File              | Responsibility                                               |
| ----------------- | ------------------------------------------------------------ |
| `config.py`       | Centralised constants and the Pre-Shared Key (PSK). All other modules import from here. |
| `security_psk.py` | PSK cryptographic primitives: nonce generation, HMAC-SHA256, and HKDF key derivation. |
| `client_hello.py` | Builds the ClientHello packet and processes the ServerHello response; derives session keys on the client side. |
| `server_hello.py` | Processes the ClientHello packet, builds the ServerHello response, and derives session keys on the server side. |
| `aead.py`         | **To be implemented.** AES-256-GCM encrypt / decrypt for all DATA and ACK packets after handshake completes. |

------

## `config.py` 

### Key constant: PSK

```python
PSK = b"SRFT_demo_pre_shared_key_32_bytes_long!!"
```

> The PSK is hard-coded here intentionally. Both programs share one copy of `config.py`, so the value is always identical on both sides. The project specification permits storing the PSK in a configuration file.

### 3.3 Security-related constants

```python
CLIENT_NONCE_SIZE = 16   # bytes
SERVER_NONCE_SIZE = 16   # bytes
SESSION_ID_SIZE   = 8    # bytes
```

------

##  `security_psk.py` 

### `generate_nonce(length)`

Returns `os.urandom(length)` — a cryptographically secure random byte string. Used by both sides to generate nonces for the handshake.

### `compute_hmac(data)` / `verify_hmac(data, received_hmac)`

Computes or verifies `HMAC-SHA256(PSK, data)`. The PSK acts as the signing key. `verify_hmac` uses `hmac.compare_digest` for constant-time comparison, which prevents timing-based side-channel attacks.

### `hkdf_extract_expand(client_nonce, server_nonce)`

Derives two independent 32-byte session keys from the PSK and the two handshake nonces using HKDF-SHA256. This is the standard two-step construction:

```
# Step 1 — Extract
ikm = client_nonce + server_nonce
prk = HMAC-SHA256(salt=PSK, data=ikm)

# Step 2 — Expand  (run twice with different info strings)
enc_key = HMAC-SHA256(prk, b"SRFT enc key" + 0x01)[:32]
ack_key = HMAC-SHA256(prk, b"SRFT ack key" + 0x02)[:32]
```

The function returns a tuple:

- `enc_key` — 32-byte key for AES-256-GCM encryption of DATA and ACK packets.
- `ack_key` — 32-byte key for authenticating ACK-only packets (prepared for optional use).

> Different info strings (`"SRFT enc key"` vs `"SRFT ack key"`) and different counter bytes (`0x01` vs `0x02`) are essential. They ensure `enc_key` and `ack_key` are cryptographically independent even though they share the same PRK.

------

## `client_hello.py`

### `build_client_hello()`

Constructs the ClientHello packet and returns it together with the client nonce (which must be kept for the KDF step later).

Packet layout on the wire:

```
| version (1B) | cipher (1B) | client_nonce (16B) | HMAC-SHA256 (32B) |
  <-------------- payload covered by HMAC (18B) ------------->
```

**Struct format: `"!BB16s"`**

| Token | Field meaning                                                |
| ----- | ------------------------------------------------------------ |
| `!`   | Network byte order (Big-Endian). Mandatory for all network structs. |
| `B`   | `version` — 1-byte unsigned integer (value = 1).             |
| `B`   | `cipher` — 1-byte unsigned integer (value = 1, meaning AES-256-GCM). |
| `16s` | `client_nonce` — raw 16-byte string (no type conversion, sent as-is). |

The HMAC is appended after the packed payload so the server can verify that the sender knows the PSK without transmitting the PSK itself.

### `process_server_hello(packet, client_nonce)`

Validates the ServerHello and derives session keys. Returns `(enc_key, ack_key, session_id)`.

Steps performed:

1. Split the last 32 bytes as the received HMAC; the rest is the payload.
2. Call `verify_hmac(payload, received_mac)`. Raise an exception immediately if this fails — the server is not authenticated.
3. Unpack payload with `"!16s8s"` to get `server_nonce` and `session_id`.
4. Call `hkdf_extract_expand(client_nonce, server_nonce)` to derive `(enc_key, ack_key)`.

**Struct format: `"!16s8s"`**

| Token | Field meaning                  |
| ----- | ------------------------------ |
| `!`   | Network byte order.            |
| `16s` | `server_nonce` — 16 raw bytes. |
| `8s`  | `session_id` — 8 raw bytes.    |

------

## `server_hello.py`

### `process_client_hello(packet)`

Processes the ClientHello, builds the ServerHello response, and derives session keys. Returns a 5-tuple:

```python
(response_packet, enc_key, ack_key, session_id, client_nonce)
```

Steps performed:

1. Split the last 32 bytes as the received HMAC; the rest is the payload.
2. Call `verify_hmac(payload, received_mac)`. Reject the connection immediately if this fails.
3. Unpack payload with `"!BB16s"` to get `version`, `cipher`, and `client_nonce`.
4. Generate `server_nonce = os.urandom(16)` and `session_id = os.urandom(8)`.
5. Pack the ServerHello payload with `"!16s8s"`, compute its HMAC, and append it.
6. Call `hkdf_extract_expand(client_nonce, server_nonce)` to derive `(enc_key, ack_key)`.

------

## Next Step: AEAD Encryption Module (`aead.py`)

### Recommended packet layout

```
[ AAD (plaintext, authenticated) ]
  session_id  (8B)
  seq_number  (4B)
  ack_number  (4B)
  flags       (2B)

[ Nonce / IV  (12B, plaintext) ]

[ Ciphertext  (variable, encrypted) ]

[ Auth Tag    (16B, appended by AES-GCM) ]
```

### Dependency

```bash
pip install cryptography
```

> The `cryptography` library provides a production-quality AES-GCM implementation.

## 