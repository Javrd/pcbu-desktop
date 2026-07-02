"""Re-implementation of pcbu-desktop's CryptUtils (common/src/utils/CryptUtils.cpp).

Wire format for a single AES blob:
    IV (16 bytes) | SALT (16 bytes) | CIPHERTEXT | GCM TAG (16 bytes)

Key derivation: PBKDF2-HMAC-SHA256, 65535 iterations, 32 byte (AES-256) key.

"Packet" blobs additionally prefix the plaintext with an 8 byte big-endian
millisecond timestamp before encrypting, and reject anything more than
CRYPT_PACKET_TIMEOUT ms away from "now" on decrypt (replay/clock-skew guard).
"""
import hashlib
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

AES_KEY_SIZE = 32  # 256 bit
IV_SIZE = 16
SALT_SIZE = 16
GCM_TAG_SIZE = 16
ITERATIONS = 65535
CRYPT_PACKET_TIMEOUT_MS = 60000 * 2


class CryptError(Exception):
    pass


class InvalidTimestampError(CryptError):
    pass


def sha3_256_hex(text: str) -> str:
    """Matches CryptUtils::Sha256, which (despite the name) uses SHA3-256."""
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def _derive_key(pwd: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=salt, iterations=ITERATIONS)
    return kdf.derive(pwd.encode("utf-8"))


def encrypt_aes_raw(data: bytes, pwd: str) -> bytes:
    iv = os.urandom(IV_SIZE)
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(pwd, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + salt + ciphertext + encryptor.tag


def decrypt_aes_raw(data: bytes, pwd: str) -> bytes:
    if len(data) < IV_SIZE + SALT_SIZE + GCM_TAG_SIZE:
        raise CryptError("Ciphertext too short")
    iv = data[:IV_SIZE]
    salt = data[IV_SIZE:IV_SIZE + SALT_SIZE]
    tag = data[-GCM_TAG_SIZE:]
    ciphertext = data[IV_SIZE + SALT_SIZE:-GCM_TAG_SIZE]
    key = _derive_key(pwd, salt)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as ex:
        raise CryptError(f"Decryption failed: {ex}") from ex


def encrypt_aes_str(data: str, pwd: str) -> str:
    """Matches CryptUtils::EncryptAES(std::string, std::string) -> hex string."""
    return encrypt_aes_raw(data.encode("utf-8"), pwd).hex()


def decrypt_aes_str(data_hex: str, pwd: str) -> str:
    """Matches CryptUtils::DecryptAES(std::string, std::string) -> plain string."""
    return decrypt_aes_raw(bytes.fromhex(data_hex), pwd).decode("utf-8")


def encrypt_aes_packet(data: bytes, pwd: str) -> bytes:
    """Matches CryptUtils::EncryptAESPacket: prefixes an 8 byte timestamp."""
    timestamp = struct.pack(">q", int(time.time() * 1000))
    return encrypt_aes_raw(timestamp + data, pwd)


def decrypt_aes_packet(data: bytes, pwd: str) -> bytes:
    """Matches CryptUtils::DecryptAESPacket: validates the embedded timestamp."""
    plain = decrypt_aes_raw(data, pwd)
    if len(plain) < 8:
        raise CryptError("Decrypted packet too short")
    (timestamp,) = struct.unpack(">q", plain[:8])
    diff = int(time.time() * 1000) - timestamp
    if diff < -CRYPT_PACKET_TIMEOUT_MS or diff > CRYPT_PACKET_TIMEOUT_MS:
        raise InvalidTimestampError("Packet timestamp out of range (clock skew or replay)")
    return plain[8:]
