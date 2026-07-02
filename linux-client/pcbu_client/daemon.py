"""Background daemon: listens for pcbu-desktop's UDP discovery broadcast
(common/src/connection/UDPBroadcaster.cpp) and, for any recognised paired
device, automatically completes the unlock handshake
(common/src/connection/unlock/servers/TCPUnlockServer.cpp +
common/src/handler/UnlockHandler.cpp) with no user interaction.
"""
import json
import logging
import socket
import threading
import time

from . import crypto_utils, packets
from .storage import PairedDevice, Storage

log = logging.getLogger("pcbu_client.daemon")

CONNECT_TIMEOUT = 5.0
SOCKET_TIMEOUT = 15.0


class UnlockDaemon:
    def __init__(self, udp_port: int, storage: Storage = None):
        self.udp_port = udp_port
        self.storage = storage or Storage()
        self._in_progress = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def run_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.udp_port))
        log.info("Listening for pcbu-desktop broadcasts on UDP port %d", self.udp_port)

        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                if self._stop.is_set():
                    break
                raise
            self._handle_broadcast(data, addr)

    def stop(self) -> None:
        self._stop.set()

    def _handle_broadcast(self, data: bytes, addr) -> None:
        try:
            payload = json.loads(data.decode("utf-8"))
            device_id = payload["deviceId"]
            pcbu_ip = payload["pcbuIP"]
            pcbu_port = int(payload["pcbuPort"])
        except Exception:
            log.debug("Ignoring malformed broadcast from %s", addr)
            return

        device = self.storage.get_by_id(device_id)
        if device is None:
            log.debug("Ignoring broadcast for unknown device %s from %s", device_id, addr)
            return

        with self._lock:
            if device_id in self._in_progress:
                return
            self._in_progress.add(device_id)

        thread = threading.Thread(
            target=self._safe_unlock, args=(device, pcbu_ip, pcbu_port), daemon=True
        )
        thread.start()

    def _safe_unlock(self, device: PairedDevice, pcbu_ip: str, pcbu_port: int) -> None:
        try:
            self._perform_unlock(device, pcbu_ip, pcbu_port)
        except Exception as ex:
            log.warning("Unlock attempt for %s (%s) failed: %s", device.deviceName, device.id, ex)
        finally:
            with self._lock:
                self._in_progress.discard(device.id)

    def _perform_unlock(self, device: PairedDevice, pcbu_ip: str, pcbu_port: int) -> None:
        log.info("Detected pcbu-desktop for '%s' at %s:%d, attempting auto-unlock...", device.deviceName, pcbu_ip, pcbu_port)
        sock = socket.create_connection((pcbu_ip, pcbu_port), timeout=CONNECT_TIMEOUT)
        try:
            sock.settimeout(SOCKET_TIMEOUT)

            # 1) Identify ourselves.
            packets.write_packet(sock, packets.PACKET_ID_DEVICE_ID, device.id.encode("utf-8"))

            # 2) Read the unlock request (contains an AES blob keyed by our shared encryptionKey).
            packet_id, payload = packets.read_packet(sock)
            if packet_id != packets.PACKET_ID_UNLOCK_REQUEST:
                raise RuntimeError(f"Unexpected packet id 0x{packet_id:X}")
            request = json.loads(payload.decode("utf-8"))
            enc_data = bytes.fromhex(request["encData"])
            request_data = json.loads(crypto_utils.decrypt_aes_packet(enc_data, device.encryptionKey).decode("utf-8"))
            unlock_token = request_data["unlockToken"]
            log.info("Unlock request for user='%s' program='%s'", request_data.get("user"), request_data.get("program"))

            # 3) Reply with the token echoed back plus the passwordKey we were given at pairing time,
            #    proving we hold the shared secret and letting pcbu-desktop decrypt its stored password.
            response_data = {"unlockToken": unlock_token, "passwordKey": device.passwordKey}
            response_enc = crypto_utils.encrypt_aes_packet(
                json.dumps(response_data).encode("utf-8"), device.encryptionKey
            ).hex()
            response = {"error": "", "encData": response_enc}
            packets.write_packet(sock, packets.PACKET_ID_UNLOCK_RESPONSE, json.dumps(response).encode("utf-8"))
            log.info("Auto-unlock signal sent successfully for '%s'.", device.deviceName)
        finally:
            sock.close()
