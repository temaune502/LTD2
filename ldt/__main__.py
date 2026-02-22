"""
LDT — Local Data Transfer  CLI entry point.

Usage:
    python -m ldt send <path> [<path>...] [--to <peer>] [--port N] [--level N] [--quiet]
    python -m ldt receive [--dir DIR] [--port N] [--quiet]
    python -m ldt peers [--wait N]
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
import uuid

from .discovery import Discovery
from .progress import NullProgress, ProgressTracker
from .session import ReceiveServer, SendSession
from .transfer import walk_targets


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_peers(args: argparse.Namespace) -> int:
    """List discovered peers on the local network."""
    disc = Discovery(tcp_port=args.port)
    disc.start()
    disc.query()                          # trigger immediate responses

    wait = max(1, args.wait)
    print(f"Scanning for {wait}s …", file=sys.stderr)
    time.sleep(wait)

    peers = disc.get_peers()
    disc.stop()

    if not peers:
        print("No peers found.")
        return 0

    print(f"\n{'NAME':<24} {'IP':<18} {'PORT'}")
    print("-" * 50)
    for p in peers:
        print(f"{p.name:<24} {p.host:<18} {p.port}")
    return 0


def cmd_receive(args: argparse.Namespace) -> int:
    """Start receiver — listens indefinitely."""
    disc = Discovery(tcp_port=args.port)
    disc.start()

    server = ReceiveServer(dest_dir=args.dir, port=args.port)
    server.start()

    print(f"[LDT] Listening on port {args.port}  →  {args.dir}")
    print("[LDT] Press Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        disc.stop()

    return 0


def cmd_send(args: argparse.Namespace) -> int:
    """Send one or more files/folders to a peer."""
    # Resolve peer
    disc = Discovery(tcp_port=args.port)
    disc.start()

    target_host: str
    target_port: int

    if args.to:
        # Give peers 3 s to respond
        disc.query()
        time.sleep(3)
        peer = disc.find_peer(args.to)
        if peer is None:
            # Maybe args.to is a raw IP
            target_host = args.to
            target_port = args.port
        else:
            target_host = peer.host
            target_port = peer.port
    else:
        print("Error: --to <peer-name-or-ip> is required.", file=sys.stderr)
        disc.stop()
        return 1

    # Collect files
    try:
        entries = list(walk_targets(args.paths, chunk_size=512 * 1024))
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        disc.stop()
        return 1

    if not entries:
        print("No files to send.", file=sys.stderr)
        disc.stop()
        return 1

    total_size = sum(e.size for e in entries)
    print(f"[LDT] Sending {len(entries)} file(s) ({_fmt_size(total_size)}) → {target_host}:{target_port}")

    # Progress
    progress: ProgressTracker | NullProgress
    if args.quiet:
        progress = NullProgress()
    else:
        progress = ProgressTracker(
            total_files=len(entries),
            peer_name=f"{target_host}:{target_port}",
            direction="↑ SEND",
        )
        progress.start()

    # Connect + transfer
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    exit_code = 0
    try:
        sock.connect((target_host, target_port))
        sock.settimeout(None)           # blocking from here on

        session = SendSession(
            sock=sock,
            entries=entries,
            sender_id=str(uuid.uuid4()),
            sender_name=socket.gethostname(),
            compress_level=args.level,
            progress=progress,
        )
        session.run()
        print(f"\n[LDT] ✓ Transfer complete — {len(entries)} file(s) sent.")
    except ConnectionRefusedError:
        print(f"\n[LDT] Connection refused ({target_host}:{target_port}). "
              "Is the receiver running?", file=sys.stderr)
        exit_code = 1
    except Exception as exc:
        print(f"\n[LDT] Transfer failed: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        progress.stop()
        sock.close()
        disc.stop()

    return exit_code


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ldt",
        description="LDT — Local Data Transfer  (serverless, P2P, zstd-compressed)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- peers ---
    p_peers = sub.add_parser("peers", help="List peers on the local network")
    p_peers.add_argument("--port", type=int, default=9998,
                         help="TCP port used for peer announcements (default 9998)")
    p_peers.add_argument("--wait", type=float, default=3,
                         help="Seconds to wait for peer responses (default 3)")

    # --- receive ---
    p_recv = sub.add_parser("receive", help="Start receiver — accept incoming transfers")
    p_recv.add_argument("--dir", default="./received",
                        help="Directory to save received files (default: ./received)")
    p_recv.add_argument("--port", type=int, default=9998,
                        help="TCP port to listen on (default 9998)")
    p_recv.add_argument("--quiet", action="store_true", help="No progress bars")

    # --- send ---
    p_send = sub.add_parser("send", help="Send files/folders to a peer")
    p_send.add_argument("paths", nargs="+", help="Files or directories to send")
    p_send.add_argument("--to", required=True,
                        help="Peer hostname or IP address")
    p_send.add_argument("--port", type=int, default=9998,
                        help="Peer TCP port (default 9998)")
    p_send.add_argument("--level", type=int, default=3, choices=range(1, 23),
                        metavar="1-22",
                        help="zstd compression level (default 3)")
    p_send.add_argument("--quiet", action="store_true", help="No progress bars")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    handlers = {
        "peers":   cmd_peers,
        "receive": cmd_receive,
        "send":    cmd_send,
    }
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
