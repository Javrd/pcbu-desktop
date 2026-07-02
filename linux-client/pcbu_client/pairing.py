"""Pairing handshake — client side of common/src/connection/pairing/PairingServer.cpp."""
import json
import socket

from . import identity, packets
from .storage import PairedDevice, Storage

PROTO_VERSION = "3.0.0"


class PairingError(Exception):
    pass


def pair(code: str, udp_port: int, connect_timeout: float = 10.0) -> PairedDevice:
    try:
        qr_data = packets.decode_pairing_payload(code)
    except Exception as ex:
        raise PairingError(f"Invalid pairing code: {ex}") from ex

    try:
        pc_ip = qr_data["ip"]
        pc_port = int(qr_data["port"])
        enc_key = qr_data["encKey"]
    except KeyError as ex:
        raise PairingError(f"Pairing code missing field {ex}") from ex

    device_uuid = identity.get_or_create_device_uuid()
    init_packet = {
        "protoVersion": PROTO_VERSION,
        "deviceUUID": device_uuid,
        "deviceName": identity.get_device_name(),
        "ipAddress": identity.get_local_ip(pc_ip),
        "tcpPort": 0,
        "udpPort": udp_port,
        "udpManualPort": udp_port,
        "cloudToken": "",
    }

    sock = socket.create_connection((pc_ip, pc_port), timeout=connect_timeout)
    try:
        sock.settimeout(connect_timeout)
        packets.write_encrypted_packet(sock, packets.PACKET_ID_PAIR_INIT, json.dumps(init_packet), enc_key)
        packet_id, payload = packets.read_encrypted_packet(sock, enc_key)
    finally:
        sock.close()

    if packet_id != packets.PACKET_ID_PAIR_RESPONSE:
        raise PairingError(f"Unexpected response packet id 0x{packet_id:X}")

    response = json.loads(payload)
    if response.get("errMsg"):
        raise PairingError(response["errMsg"])

    data = response["data"]
    device = PairedDevice(
        id=data["deviceId"],
        deviceName=data.get("deviceName", ""),
        deviceOS=data.get("deviceOS", ""),
        userName=data.get("userName", ""),
        ipAddress=data.get("ipAddress", ""),
        port=int(data.get("port", 0)),
        macAddress=data.get("macAddress", ""),
        encryptionKey=enc_key,
        passwordKey=data.get("passwordKey", ""),
        udpPort=udp_port,
    )

    Storage().add(device)
    return device
