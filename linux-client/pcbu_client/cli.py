import argparse
import logging
import sys

from . import identity
from .daemon import UnlockDaemon
from .pairing import PairingError, pair
from .storage import Storage

DEFAULT_UDP_PORT = 43297


def cmd_pair(args: argparse.Namespace) -> int:
    try:
        device = pair(args.code, udp_port=args.udp_port)
    except PairingError as ex:
        print(f"Pairing failed: {ex}", file=sys.stderr)
        return 1
    print("Paired successfully:")
    print(f"  Device ID : {device.id}")
    print(f"  Name      : {device.deviceName}")
    print(f"  OS        : {device.deviceOS}")
    print(f"  User      : {device.userName}")
    print(f"  Host      : {device.ipAddress}:{device.port}")
    print(f"  UDP port  : {device.udpPort} (make sure this is reachable/broadcast-visible on your LAN)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    devices = Storage().load()
    if not devices:
        print("No paired devices.")
        return 0
    for d in devices:
        print(f"{d.id}  {d.deviceName!r} ({d.deviceOS})  user={d.userName}  host={d.ipAddress}:{d.port}  udpPort={d.udpPort}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    if Storage().remove(args.device_id):
        print("Removed.")
        return 0
    print("No such device.", file=sys.stderr)
    return 1


def cmd_daemon(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    devices = Storage().load()
    if not devices:
        logging.warning("No paired devices yet. Listening anyway; run 'pcbu-client pair <CODE>' to add one (the daemon picks up new pairings automatically).")
    ports = {d.udpPort for d in devices}
    if len(ports) > 1:
        logging.warning("Paired devices use different udpPort values (%s); only listening on %d.", ports, args.udp_port)
    daemon = UnlockDaemon(udp_port=args.udp_port)
    try:
        daemon.run_forever()
    except KeyboardInterrupt:
        daemon.stop()
    return 0


def cmd_id(args: argparse.Namespace) -> int:
    print(identity.get_or_create_device_uuid())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pcbu-client", description="Linux companion client for pcbu-desktop (PC Bio Unlock).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pair = sub.add_parser("pair", help="Pair with a pcbu-desktop instance using its pairing code.")
    p_pair.add_argument("code", help="Pairing code shown in pcbu-desktop's pairing wizard (or raw QR JSON).")
    p_pair.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT, help=f"UDP port this client listens on for discovery broadcasts (default {DEFAULT_UDP_PORT}).")
    p_pair.set_defaults(func=cmd_pair)

    p_list = sub.add_parser("list", help="List paired devices.")
    p_list.set_defaults(func=cmd_list)

    p_remove = sub.add_parser("remove", help="Remove a paired device.")
    p_remove.add_argument("device_id")
    p_remove.set_defaults(func=cmd_remove)

    p_daemon = sub.add_parser("daemon", help="Run the auto-unlock background daemon (also: 'run').")
    p_daemon.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT, help=f"UDP port to listen on (default {DEFAULT_UDP_PORT}).")
    p_daemon.add_argument("-v", "--verbose", action="store_true")
    p_daemon.set_defaults(func=cmd_daemon)

    p_run = sub.add_parser("run", help="Alias for 'daemon'.")
    p_run.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    p_run.add_argument("-v", "--verbose", action="store_true")
    p_run.set_defaults(func=cmd_daemon)

    p_id = sub.add_parser("id", help="Print this client's persistent device UUID.")
    p_id.set_defaults(func=cmd_id)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
