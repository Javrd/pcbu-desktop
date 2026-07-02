"""Wire protocol re-implementation of common/src/connection/{BaseConnection,Packets}.

Frame layout (all integers big-endian / network order):
    8 bytes  PACKET_HEADER magic (0xDB065AC7AFDFA4CC)
    2 bytes  packet id
    2 bytes  payload length
    N bytes  payload
"""
import base64
import json
import socket
import struct

PACKET_HEADER = 0xDB065AC7AFDFA4CC

PACKET_ID_PAIR_INIT = 0x50
PACKET_ID_PAIR_RESPONSE = 0x51

PACKET_ID_DEVICE_ID = 0xB0
PACKET_ID_UNLOCK_REQUEST = 0xB1
PACKET_ID_UNLOCK_RESPONSE = 0xB2

_HEADER_BYTES = struct.pack(">Q", PACKET_HEADER)

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class PacketError(Exception):
    pass


def read_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise PacketError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def read_packet(sock: socket.socket):
    """Returns (packet_id, payload_bytes)."""
    header = read_exact(sock, 8)
    if header != _HEADER_BYTES:
        raise PacketError("Bad packet header (out of sync with peer)")
    packet_id = struct.unpack(">H", read_exact(sock, 2))[0]
    length = struct.unpack(">H", read_exact(sock, 2))[0]
    if length == 0:
        raise PacketError("Empty packet received")
    payload = read_exact(sock, length)
    return packet_id, payload


def write_packet(sock: socket.socket, packet_id: int, payload: bytes) -> None:
    if len(payload) > 0xFFFF:
        raise PacketError("Payload too large")
    sock.sendall(_HEADER_BYTES + struct.pack(">HH", packet_id, len(payload)) + payload)


def write_encrypted_packet(sock: socket.socket, packet_id: int, data: str, enc_key: str) -> None:
    from . import crypto_utils

    enc = crypto_utils.encrypt_aes_packet(data.encode("utf-8"), enc_key)
    write_packet(sock, packet_id, enc)


def read_encrypted_packet(sock: socket.socket, enc_key: str):
    from . import crypto_utils

    packet_id, payload = read_packet(sock)
    plain = crypto_utils.decrypt_aes_packet(payload, enc_key)
    return packet_id, plain.decode("utf-8")


def base32_encode_nopad(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def base32_decode_nopad(text: str) -> bytes:
    text = text.upper()
    pad = (-len(text)) % 8
    return base64.b32decode(text + ("=" * pad))


def decode_pairing_code(code: str) -> dict:
    """Reverses PairingForm::GetPairingCode(): strips '-' separators, base32-decodes, parses JSON."""
    cleaned = code.strip().replace("-", "").replace(" ", "")
    raw = base32_decode_nopad(cleaned)
    return json.loads(raw.decode("utf-8"))


def decode_pairing_payload(text: str) -> dict:
    """Accepts either a raw JSON QR payload or a dashed base32 pairing code."""
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    return decode_pairing_code(text)
