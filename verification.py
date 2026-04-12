import hashlib # https://docs.python.org/3/library/hashlib.html
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # https://cryptography.io/en/latest/hazmat/primitives/aead/

# sender side
def encrypt_file(file_bytes: bytes, aead_obj: AESGCM, nonce: bytes):

    # Compute SHA-256 and get the digest, then using AESGCM (AEAD) to encrypt the file
    encrypted_data = hashlib.sha256(file_bytes).digest()
    encrypted_data = aead_obj.encrypt(nonce, encrypted_data, b"")

    return encrypted_data

# receiver side
def verify_transfer(encrypted_data: bytes, assembled_packet: bytes, aead_obj: AESGCM, nonce: bytes):

    # decrypt client's digest
    client_digest = aead_obj.decrypt(nonce, encrypted_data, b"")
    
    # compute SHA-256 from receiver's assembled_packet and get the digest
    receiver_digest = hashlib.sha256(assembled_packet).digest()

    # compare if both digests are the same
    if client_digest == receiver_digest:
        return True
    else:
        return False

############################## TEST CODE ##############################

if __name__ == "__main__":
    file_bytes = b'Hello World\n'
    assembled_packet = b'Hello World\n'

    aead_key = AESGCM.generate_key(bit_length=128)
    aead_obj = AESGCM(aead_key)
    nonce = os.urandom(12)

    encrypted_data = encrypt_file(file_bytes, aead_obj, nonce)

    print("End-to-End File Verification...", end="")
    transfer_status = verify_transfer(encrypted_data, assembled_packet, aead_obj, nonce)
    if transfer_status is True:
        print("PASS")
    else:
        print("FAILED")