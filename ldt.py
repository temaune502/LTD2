#!/usr/bin/env python3
"""
ldt.py — Local Data Transfer
==============================
Serverless P2P file/folder transfer over a local network.
Devices find each other automatically — no server needed.

USAGE
-----
  python ldt.py <name> receive [--dir ./received] [--port 9900]
  python ldt.py <name> send <target> <path> [path ...]  [--port 9900]
  python ldt.py <name> peers [--wait 3]

EXAMPLES
--------
  # Machine A — start receiver, call yourself "Alice"
  python ldt.py Alice receive

  # Machine B — list who is visible on the network
  python ldt.py Bob peers

  # Machine B — send a file to Alice
  python ldt.py Bob send Alice report.pdf

  # Machine B — send an entire folder to Alice
  python ldt.py Bob send Alice ./project

Requirements: Python 3.10+ (stdlib only)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL  (LDTv1 — all integers big-endian)
#
# Every TCP message is a frame:
#   [ magic 4B ][ type 1B ][ payload_len 4B ][ payload NB ]
#
# Magic = b"LDT\x01"
#
# CHUNK payload layout:
#   [ chunk_index 4B ][ sha256 32B ][ data_len 4B ][ zlib-compressed data ]
#
# Discovery (UDP multicast 239.255.42.42:9900):
#   JSON datagrams: {"t":"AN","id":"…","name":"…","port":9900,"v":1}
#   Types: AN=announce, QR=query, BY=bye
# ─────────────────────────────────────────────────────────────────────────────

MAGIC           = b"LDT\x01"
HDR_FMT         = "!4sBI"          # magic(4s) type(B) payload_len(I)
HDR_SIZE        = struct.calcsize(HDR_FMT)   # 9 bytes
CHUNK_HDR_FMT   = "!I32sI"        # index(I) hash(32s) datalen(I)
CHUNK_HDR_SIZE  = struct.calcsize(CHUNK_HDR_FMT)  # 40 bytes

TCP_PORT        = 9900
MCAST_GROUP     = "239.255.42.42"
MCAST_PORT      = 9900            # same port, different socket so UDP/TCP share the number
DISC_INTERVAL   = 5.0             # seconds between beacons
PEER_TTL        = 30.0            # forget peer after this many seconds
CHUNK_SIZE      = 512 * 1024      # 512 KiB per chunk
MAX_RETRY       = 3

# Message type bytes
T_HELLO       = 0x01
T_HELLO_ACK   = 0x02
T_FILE_META   = 0x10
T_CHUNK       = 0x11
T_CHUNK_ACK   = 0x12
T_FILE_END    = 0x13
T_FILE_END_ACK= 0x14
T_SESSION_END = 0x20
T_ERROR       = 0xFF

log = logging.getLogger("ldt")


# ─────────────────────────────────────────────────────────────────────────────
# LOW-LEVEL I/O
# ─────────────────────────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(sock: socket.socket, msg_type: int, payload: bytes) -> None:
    header = struct.pack(HDR_FMT, MAGIC, msg_type, len(payload))
    sock.sendall(header + payload)


def _read_frame(sock: socket.socket) -> tuple[int, bytes]:
    raw = _recv_exact(sock, HDR_SIZE)
    magic, msg_type, plen = struct.unpack(HDR_FMT, raw)
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    return msg_type, _recv_exact(sock, plen)


# ─────────────────────────────────────────────────────────────────────────────
# COMPRESSION & INTEGRITY  (stdlib only)
# ─────────────────────────────────────────────────────────────────────────────

def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=6)


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()       # 32 bytes


# ─────────────────────────────────────────────────────────────────────────────
# PEER DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Peer:
    id: str
    name: str
    host: str
    port: int
    seen: float = 0.0

    def __str__(self) -> str:
        return f"{self.name}  [{self.host}:{self.port}]"


class Discovery:
    """UDP multicast beacon — runs as a daemon background thread."""

    def __init__(self, my_name: str, tcp_port: int = TCP_PORT):
        self.my_name = my_name
        self.tcp_port = tcp_port
        self.my_id = str(uuid.uuid4())
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    # ── public ────────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._sock = self._make_sock()
        threading.Thread(target=self._loop, daemon=True, name="ldt-disc").start()

    def stop(self) -> None:
        self._stop.set()
        self._send({"t": "BY", "id": self.my_id})
        if self._sock:
            try: self._sock.close()
            except OSError: pass

    def peers(self) -> list[Peer]:
        now = time.monotonic()
        with self._lock:
            return [p for p in self._peers.values() if now - p.seen < PEER_TTL]

    def find(self, name_or_ip: str) -> Optional[Peer]:
        return next(
            (p for p in self.peers() if p.name == name_or_ip or p.host == name_or_ip),
            None,
        )

    def query(self) -> None:
        self._send({"t": "QR", "id": self.my_id,
                    "name": self.my_name, "port": self.tcp_port, "v": 1})

    # ── internal ──────────────────────────────────────────────────────────────

    def _make_sock(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass
        s.bind(("", MCAST_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.settimeout(1.0)
        return s

    def _send(self, msg: dict) -> None:
        try:
            data = json.dumps(msg, separators=(",", ":")).encode()
            if self._sock:
                self._sock.sendto(data, (MCAST_GROUP, MCAST_PORT))
        except OSError: pass

    def _announce(self) -> None:
        self._send({"t": "AN", "id": self.my_id,
                    "name": self.my_name, "port": self.tcp_port, "v": 1})

    def _loop(self) -> None:
        last = 0.0
        while not self._stop.is_set():
            if time.monotonic() - last >= DISC_INTERVAL:
                self._announce()
                last = time.monotonic()
            try:
                assert self._sock
                data, (src_ip, _) = self._sock.recvfrom(1024)
                self._handle(json.loads(data), src_ip)
            except (TimeoutError, OSError, json.JSONDecodeError):
                pass

    def _handle(self, msg: dict, src_ip: str) -> None:
        t  = msg.get("t")
        pid = msg.get("id", "")
        if pid == self.my_id:
            return
        if t == "BY":
            with self._lock: self._peers.pop(pid, None)
            return
        if t in ("AN", "QR"):
            peer = Peer(id=pid, name=msg.get("name", src_ip),
                        host=src_ip, port=msg.get("port", TCP_PORT),
                        seen=time.monotonic())
            with self._lock: self._peers[pid] = peer
            if t == "QR":
                self._announce()


# ─────────────────────────────────────────────────────────────────────────────
# FILE WALKER & CHUNKER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileEntry:
    abs_path: Path
    rel_path: str    # path as sent to receiver (forward slashes)
    size: int
    mtime: float
    chunks: int      # number of CHUNK messages


def _entries(paths: list[str]) -> list[FileEntry]:
    result: list[FileEntry] = []
    for raw in paths:
        p = Path(raw).resolve()
        if p.is_file():
            st = p.stat()
            n = max(1, (st.st_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if st.st_size else 1
            result.append(FileEntry(p, p.name, st.st_size, st.st_mtime, n))
        elif p.is_dir():
            parent = p.parent
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    fp = Path(root) / f
                    st = fp.stat()
                    n = max(1, (st.st_size + CHUNK_SIZE - 1) // CHUNK_SIZE) if st.st_size else 1
                    rel = str(fp.relative_to(parent)).replace(os.sep, "/")
                    result.append(FileEntry(fp, rel, st.st_size, st.st_mtime, n))
        else:
            raise FileNotFoundError(f"Not found: {p}")
    return result


def _read_chunks(path: Path) -> Iterator[bytes]:
    if path.stat().st_size == 0:
        yield b""
        return
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK_SIZE)
            if not block:
                break
            yield block


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS  (pure stdout, no external libs)
# ─────────────────────────────────────────────────────────────────────────────

class Progress:
    """Single-line updating progress bar written to stderr."""

    BAR_WIDTH = 30

    def __init__(self, filename: str, total: int) -> None:
        self.filename = filename
        self.total = max(total, 1)
        self._done = 0
        self._t0 = time.monotonic()
        self._last_print = 0.0

    def advance(self, n: int) -> None:
        self._done += n
        now = time.monotonic()
        if now - self._last_print >= 0.1 or self._done >= self.total:
            self._last_print = now
            self._draw()

    def finish(self) -> None:
        self._done = self.total
        self._draw()
        sys.stderr.write("\n")
        sys.stderr.flush()

    def _draw(self) -> None:
        pct = self._done / self.total
        filled = int(self.BAR_WIDTH * pct)
        bar = "#" * filled + "." * (self.BAR_WIDTH - filled)
        elapsed = time.monotonic() - self._t0
        speed = self._done / elapsed if elapsed > 0 else 0
        eta = (self.total - self._done) / speed if speed > 0 else 0

        name = self.filename[-22:] if len(self.filename) > 22 else self.filename
        line = (
            f"\r  {name:<22}  [{bar}] {pct*100:5.1f}%"
            f"  {_fmt(speed)}/s  ETA {_fmt_t(eta)}"
        )
        sys.stderr.write(line)
        sys.stderr.flush()


def _fmt(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:6.1f} {u}"
        n /= 1024
    return f"{n:6.1f} TB"


def _fmt_t(s: float) -> str:
    if s < 60: return f"{s:.0f}s"
    if s < 3600: return f"{s/60:.0f}m{s%60:.0f}s"
    return f"{s/3600:.0f}h{(s%3600)/60:.0f}m"


# ─────────────────────────────────────────────────────────────────────────────
# SENDER
# ─────────────────────────────────────────────────────────────────────────────

def _send_session(sock: socket.socket, entries: list[FileEntry],
                  my_name: str, quiet: bool = False) -> None:
    # HELLO
    hello = json.dumps({"name": my_name, "files": len(entries)}).encode()
    _send_frame(sock, T_HELLO, hello)
    t, pl = _read_frame(sock)
    ack = json.loads(pl)
    if t != T_HELLO_ACK or not ack.get("ok"):
        raise RuntimeError(f"Rejected: {ack.get('reason', '?')}")

    for idx, entry in enumerate(entries):
        print(f"  [{idx+1}/{len(entries)}] {entry.rel_path}  ({_fmt(entry.size).strip()})")
        _send_file(sock, idx, entry, quiet)

    _send_frame(sock, T_SESSION_END, b"")


def _send_file(sock: socket.socket, idx: int, entry: FileEntry, quiet: bool) -> None:
    meta = json.dumps({
        "i": idx, "p": entry.rel_path,
        "s": entry.size, "c": entry.chunks, "m": entry.mtime,
    }).encode()
    _send_frame(sock, T_FILE_META, meta)

    prog = None if quiet else Progress(entry.rel_path, entry.size)
    raw_parts: list[bytes] = []

    for ci, raw in enumerate(_read_chunks(entry.abs_path)):
        raw_parts.append(raw)
        _send_chunk(sock, ci, raw)
        if prog:
            prog.advance(len(raw))

    if prog:
        prog.finish()

    # whole-file hash
    file_hash = _sha256(b"".join(raw_parts))
    _send_frame(sock, T_FILE_END, struct.pack("!I32s", idx, file_hash))

    t, pl = _read_frame(sock)
    ack = json.loads(pl)
    if t != T_FILE_END_ACK or not ack.get("ok"):
        raise RuntimeError(f"File {entry.rel_path} rejected: {ack.get('reason','?')}")


def _send_chunk(sock: socket.socket, ci: int, raw: bytes, attempt: int = 0) -> None:
    h = _sha256(raw)
    comp = _compress(raw)
    payload = struct.pack(CHUNK_HDR_FMT, ci, h, len(comp)) + comp
    _send_frame(sock, T_CHUNK, payload)

    t, pl = _read_frame(sock)
    ack = json.loads(pl)
    if t != T_CHUNK_ACK or not ack.get("ok"):
        if attempt < MAX_RETRY:
            log.warning("Chunk %d NACK — retry %d/%d", ci, attempt+1, MAX_RETRY)
            _send_chunk(sock, ci, raw, attempt + 1)
        else:
            raise RuntimeError(f"Chunk {ci} failed after {MAX_RETRY} retries")


# ─────────────────────────────────────────────────────────────────────────────
# RECEIVER
# ─────────────────────────────────────────────────────────────────────────────

def _recv_server(dest_dir: Path, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen(8)
    s.settimeout(1.0)
    return s


def _recv_loop(server: socket.socket, dest_dir: Path, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            conn, addr = server.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        t = threading.Thread(
            target=_recv_conn, args=(conn, addr[0], dest_dir),
            daemon=True, name=f"ldt-conn-{addr[0]}"
        )
        t.start()


def _recv_conn(sock: socket.socket, peer_ip: str, dest_dir: Path) -> None:
    try:
        _recv_session(sock, peer_ip, dest_dir)
    except EOFError:
        pass
    except Exception as e:
        print(f"\n  !! Error from {peer_ip}: {e}", file=sys.stderr)
    finally:
        try: sock.close()
        except OSError: pass


def _recv_session(sock: socket.socket, peer_ip: str, dest_dir: Path) -> None:
    # HELLO
    t, pl = _read_frame(sock)
    if t != T_HELLO:
        _send_frame(sock, T_HELLO_ACK, json.dumps({"ok": False, "reason": "expected HELLO"}).encode())
        return
    info = json.loads(pl)
    sender = info.get("name", peer_ip)
    _send_frame(sock, T_HELLO_ACK, json.dumps({"ok": True}).encode())

    print(f"\n  <- {sender} ({peer_ip}) is sending {info.get('files','?')} file(s)")

    while True:
        t, pl = _read_frame(sock)
        if t == T_SESSION_END:
            print(f"  OK Transfer from {sender} complete\n")
            break
        elif t == T_FILE_META:
            _recv_file(sock, json.loads(pl), dest_dir)
        elif t == T_ERROR:
            err = json.loads(pl)
            print(f"  !! Sender error: {err.get('msg','?')}", file=sys.stderr)
            break


def _recv_file(sock: socket.socket, meta: dict, dest_dir: Path) -> None:
    idx       = meta["i"]
    rel_path  = meta["p"]
    total     = meta["s"]
    n_chunks  = meta["c"]
    mtime     = meta["m"]

    # safety: block directory traversal
    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "unsafe path"}).encode())
        return

    dest = dest_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)

    print(f"  >> {rel_path}  ({_fmt(total).strip()})")  # >> = incoming
    prog = Progress(rel_path, total)
    raw_parts: dict[int, bytes] = {}

    for _ in range(n_chunks):
        t, pl = _read_frame(sock)
        if t == T_ERROR:
            print(f"\n  ✗ Sender error mid-transfer", file=sys.stderr)
            return
        if t != T_CHUNK:
            _send_frame(sock, T_CHUNK_ACK,
                        json.dumps({"ok": False, "reason": f"unexpected {t}"}).encode())
            return

        ci, expected_hash, dlen = struct.unpack_from(CHUNK_HDR_FMT, pl)
        comp = pl[CHUNK_HDR_SIZE: CHUNK_HDR_SIZE + dlen]

        try:
            raw = _decompress(comp)
        except zlib.error as e:
            _send_frame(sock, T_CHUNK_ACK,
                        json.dumps({"ok": False, "reason": f"decompress: {e}"}).encode())
            return

        if _sha256(raw) != expected_hash:
            _send_frame(sock, T_CHUNK_ACK,
                        json.dumps({"ok": False, "reason": "hash mismatch"}).encode())
            log.warning("Chunk %d hash mismatch", ci)
            return

        _send_frame(sock, T_CHUNK_ACK, json.dumps({"ok": True}).encode())
        raw_parts[ci] = raw
        prog.advance(len(raw))

    prog.finish()

    # write file
    with open(dest, "wb") as fh:
        for i in range(n_chunks):
            fh.write(raw_parts[i])
    try: os.utime(dest, (mtime, mtime))
    except OSError: pass

    # FILE_END / whole-file hash
    t, pl = _read_frame(sock)
    if t != T_FILE_END:
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": f"expected FILE_END"}).encode())
        return

    _, file_hash = struct.unpack("!I32s", pl)
    actual = _sha256(b"".join(raw_parts[i] for i in range(n_chunks)))
    if actual != file_hash:
        dest.unlink(missing_ok=True)
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "file hash mismatch"}).encode())
        print(f"  !! {rel_path}: file hash mismatch -- deleted", file=sys.stderr)
        return

    _send_frame(sock, T_FILE_END_ACK, json.dumps({"ok": True}).encode())
    print(f"  OK saved -> {dest}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI COMMANDS
# ─────────────────────────────────────────────────────────────────────────────

def cmd_receive(args: argparse.Namespace) -> int:
    dest = Path(args.dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    disc = Discovery(args.name, args.port)
    disc.start()

    server = _recv_server(dest, args.port)
    stop = threading.Event()
    t = threading.Thread(target=_recv_loop, args=(server, dest, stop),
                         daemon=True, name="ldt-server")
    t.start()

    print(f"LDT receiver  |  name: {args.name}  |  port: {args.port}  |  saving to: {dest}")
    print("Waiting for transfers…  (Ctrl-C to stop)\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    stop.set()
    try: server.close()
    except OSError: pass
    disc.stop()
    print("\nStopped.")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    try:
        entries = _entries(args.paths)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not entries:
        print("Nothing to send.", file=sys.stderr)
        return 1

    # discover target
    disc = Discovery(args.name, args.port)
    disc.start()
    disc.query()

    host: str
    port: int

    # wait up to 3 s for peer
    deadline = time.monotonic() + 3
    peer = None
    while time.monotonic() < deadline:
        peer = disc.find(args.target)
        if peer:
            break
        time.sleep(0.2)

    if peer:
        host, port = peer.host, peer.port
        print(f"Found {peer.name} at {host}:{port}")
    else:
        # treat target as raw IP
        host, port = args.target, args.port
        print(f"Peer '{args.target}' not found via discovery — trying {host}:{port} directly")

    total = sum(e.size for e in entries)
    print(f"Sending {len(entries)} file(s)  ({_fmt(total).strip()})  →  {host}:{port}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"Cannot connect to {host}:{port} — {e}", file=sys.stderr)
        disc.stop()
        return 1
    sock.settimeout(None)

    rc = 0
    try:
        t0 = time.monotonic()
        _send_session(sock, entries, args.name, quiet=args.quiet)
        dt = time.monotonic() - t0
        speed = total / dt if dt else 0
        print(f"\nDone  {_fmt(total).strip()} in {_fmt_t(dt)}  (avg {_fmt(speed).strip()}/s)")
    except Exception as e:
        print(f"\nTransfer failed: {e}", file=sys.stderr)
        rc = 1
    finally:
        sock.close()
        disc.stop()

    return rc


def cmd_peers(args: argparse.Namespace) -> int:
    disc = Discovery(args.name, args.port)
    disc.start()
    disc.query()

    wait = max(1, args.wait)
    print(f"Scanning for {wait:.0f}s …")
    time.sleep(wait)

    peers = disc.peers()
    disc.stop()

    if not peers:
        print("No peers found.")
        return 0

    print(f"\n  {'NAME':<20}  {'IP':<16}  PORT")
    print("  " + "─" * 44)
    for p in peers:
        print(f"  {p.name:<20}  {p.host:<16}  {p.port}")
    print()
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        prog="ldt",
        description="LDT — Local Data Transfer  (serverless · P2P · no dependencies)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python ldt.py Alice receive
  python ldt.py Bob   peers
  python ldt.py Bob   send Alice report.pdf
  python ldt.py Bob   send Alice ./project_folder
""",
    )
    p.add_argument("name", help="Your display name on the network")
    p.add_argument("--port", type=int, default=TCP_PORT,
                   help=f"UDP/TCP port (default {TCP_PORT})")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    # receive
    r = sub.add_parser("receive", help="Accept incoming transfers")
    r.add_argument("--dir", default="./received",
                   help="Directory to save received files  (default: ./received)")

    # send
    s = sub.add_parser("send", help="Send files/folders to a peer")
    s.add_argument("target", help="Recipient name or IP address")
    s.add_argument("paths", nargs="+", metavar="path",
                   help="Files or folders to send")
    s.add_argument("--quiet", action="store_true", help="No progress bars")

    # peers
    q = sub.add_parser("peers", help="List peers visible on the network")
    q.add_argument("--wait", type=float, default=3,
                   help="Seconds to wait for responses  (default 3)")

    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                            datefmt="%H:%M:%S")

    handlers = {"receive": cmd_receive, "send": cmd_send, "peers": cmd_peers}
    sys.exit(handlers[args.cmd](args))


if __name__ == "__main__":
    main()
