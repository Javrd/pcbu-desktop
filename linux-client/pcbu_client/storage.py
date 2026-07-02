"""Local storage for paired PCBU devices.

Each entry holds the shared secrets (encryptionKey / passwordKey) needed to
complete the unlock handshake with a paired pcbu-desktop instance. Anyone
holding this file can unlock the paired PC, so it is written with 0600
permissions inside a 0700 directory.
"""
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def default_home() -> Path:
    env = os.environ.get("PCBU_CLIENT_HOME")
    if env:
        return Path(env)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/etc/pcbu-client")
    return Path.home() / ".config" / "pcbu-client"


@dataclass
class PairedDevice:
    id: str
    deviceName: str = ""
    deviceOS: str = ""
    userName: str = ""
    ipAddress: str = ""
    port: int = 0
    macAddress: str = ""
    encryptionKey: str = ""
    passwordKey: str = ""
    udpPort: int = 0


class Storage:
    def __init__(self, home: Optional[Path] = None):
        self.home = home or default_home()
        self.file = self.home / "devices.json"

    def _ensure_dir(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, stat.S_IRWXU)

    def load(self) -> List[PairedDevice]:
        if not self.file.exists():
            return []
        with open(self.file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return [PairedDevice(**entry) for entry in raw]

    def save(self, devices: List[PairedDevice]) -> None:
        self._ensure_dir()
        tmp = self.file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([asdict(d) for d in devices], f, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.file)
        os.chmod(self.file, stat.S_IRUSR | stat.S_IWUSR)

    def add(self, device: PairedDevice) -> None:
        devices = [d for d in self.load() if d.id != device.id]
        devices.append(device)
        self.save(devices)

    def remove(self, device_id: str) -> bool:
        devices = self.load()
        filtered = [d for d in devices if d.id != device_id]
        if len(filtered) == len(devices):
            return False
        self.save(filtered)
        return True

    def get_by_id(self, device_id: str) -> Optional[PairedDevice]:
        for d in self.load():
            if d.id == device_id:
                return d
        return None
