# pcbu-client (Linux companion client)

A headless, Python-only reimplementation of the pairing/unlock role that the
official PC Bio Unlock mobile app plays, targeting Linux boxes (e.g. a
Raspberry Pi, NAS, or always-on server on the same LAN as the PC you want to
unlock). It talks the exact same wire protocol as `pcbu-desktop`
(`common/src/connection/**`), so it pairs directly with the desktop app's
pairing wizard and needs no changes on the `pcbu-desktop` side.

Unlike the phone app, this client has no user to prompt for a fingerprint —
once paired, it **automatically approves every unlock request** from that
paired PC. Only pair it with machines you're happy to have unlock themselves
whenever this device is reachable on the network.

## How it works

1. **Pairing** (`pcbu-client pair <code>`): connects over TCP to the
   pairing server pcbu-desktop starts during its pairing wizard, performs the
   AES-256-GCM encrypted handshake (`PACKET_ID_PAIR_INIT` /
   `PACKET_ID_PAIR_RESPONSE`), and stores the resulting device id,
   `encryptionKey` and `passwordKey` locally.
2. **Daemon** (`pcbu-client daemon`): listens on a UDP port for
   pcbu-desktop's discovery broadcast (sent whenever that PC's lock/login
   screen is waiting for an unlock). When a broadcast matches a paired
   device id, it opens a TCP connection to the advertised
   `pcbuIP:pcbuPort`, identifies itself, decrypts the unlock request, and
   replies with the unlock token + `passwordKey` — completing the unlock
   automatically, with no interaction required.

## Requirements

- Any Linux distribution with Python 3.8+ and systemd
- `cryptography` Python package

Install the dependency with your distro's package manager (examples below),
or with `pip install cryptography` if you don't have a matching package:

```bash
# Debian/Ubuntu
sudo apt install python3-pip python3-cryptography

# Fedora
sudo dnf install python3-pip python3-cryptography

# Arch
sudo pacman -S python-pip python-cryptography
```

## Install

```bash
cd linux-client
sudo pip install .
```

This installs the `pcbu-client` command system-wide.

## Pairing

On the PC running `pcbu-desktop`, open the pairing wizard and choose the
**default/automatic (UDP)** method (this client does not implement the
Bluetooth pairing method). Use the text pairing code shown under the QR
code — no camera/QR scanner needed:

```bash
sudo pcbu-client pair "XXXXX-XXXXX-XXXXX-..."
```

By default the client registers itself to listen for discovery broadcasts on
UDP port `43297`. If that port is already used on your network, pick another
one and pass it to *both* pairing and the daemon:

```bash
sudo pcbu-client pair "XXXXX-..." --udp-port 44000
```

Make sure the chosen UDP port is reachable from the target PC (same subnet,
no firewall blocking inbound UDP broadcast on that port on this machine, and
outbound broadcast from the target PC).

List / remove paired devices:

```bash
sudo pcbu-client list
sudo pcbu-client remove <device-id>
```

## Running the daemon

Manually, in the foreground:

```bash
sudo pcbu-client daemon -v
```

As a systemd service (recommended — starts on boot, restarts on failure):

```bash
sudo cp systemd/pcbu-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pcbu-client.service
sudo journalctl -u pcbu-client -f
```

The service runs as root and stores its state in `/etc/pcbu-client`
(`devices.json`, `identity.json`, mode `0600`/`0700`) since those files
contain the secrets required to unlock the paired PC.

## Security notes

- `devices.json` contains `encryptionKey` and `passwordKey` for every paired
  PC. Anyone with read access to that file — or network access to this
  daemon while it's running — can trigger an unlock of the paired machine.
  Treat this host as a trusted credential the same way you'd treat the
  phone running the official app.
- The daemon approves unlock requests unconditionally for any paired
  device id it recognizes; there is intentionally no biometric/consent step.
  Only run it on hosts you fully control, on a trusted network.
- Traffic is AES-256-GCM encrypted with a per-pairing key negotiated out of
  band via the pairing code (never sent over the network), matching
  `pcbu-desktop`'s own crypto (`common/src/utils/CryptUtils.cpp`).

## Layout

```
pcbu_client/
  crypto_utils.py   AES-256-GCM + PBKDF2-HMAC-SHA256, mirrors CryptUtils.cpp
  packets.py        Wire framing + pairing-code base32/JSON decoding
  identity.py        Persistent client deviceUUID
  storage.py        Paired-device secrets storage (0600 JSON file)
  pairing.py        Pairing handshake (client side of PairingServer.cpp)
  daemon.py         UDP discovery listener + auto unlock handshake
  cli.py            `pcbu-client` command line entry point
systemd/pcbu-client.service
```
