"""Persistent client identity (deviceUUID) — mirrors what the mobile app keeps locally."""
import json
import os
import socket
import stat
import uuid
from pathlib import Path

from .storage import default_home


def _identity_file() -> Path:
    return default_home() / "identity.json"


def get_or_create_device_uuid() -> str:
    path = _identity_file()
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)["deviceUUID"]

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, stat.S_IRWXU)
    device_uuid = str(uuid.uuid4())
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"deviceUUID": device_uuid}, f)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return device_uuid


def get_device_name() -> str:
    return socket.gethostname()


def get_local_ip(target_ip: str) -> str:
    """Best-effort local IP that can reach target_ip, without sending any traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 1))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()
