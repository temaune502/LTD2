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

PROTOCOL  (LDTv1)
-----------------
TCP frame:
  [ magic 4B ][ type 1B ][ payload_len 4B ][ payload NB ]

CHUNK payload:
  [ chunk_index 4B ][ sha256 32B ][ data_len 4B ][ zlib-compressed data ]

Transfer is fully PIPELINED — sender streams all chunks without waiting for
per-chunk ACKs.  Integrity is verified with SHA-256 per chunk on the
receiver side and a whole-file SHA-256 at the end.  If any chunks are
corrupt the receiver returns a NACK list and the sender retries only those.

Discovery: UDP multicast 239.255.42.42:9900
  {"t":"AN","id":"…","name":"…","port":9900,"v":1}
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
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MAGIC           = b"LDT\x01"
HDR_FMT         = "!4sBI"
HDR_SIZE        = struct.calcsize(HDR_FMT)   # 9 bytes
# CHUNK header includes a flags byte: 0x01 = zlib compressed, 0x00 = raw
CHUNK_HDR_FMT   = "!I32sIB"  # index(4) sha256(32) datalen(4) flags(1)
CHUNK_HDR_SIZE  = struct.calcsize(CHUNK_HDR_FMT)  # 41 bytes
FLAG_COMPRESSED = 0x01
FLAG_RAW        = 0x00

TCP_PORT        = 9900
MCAST_GROUP     = "239.255.42.42"
MCAST_PORT      = 9900
DISC_INTERVAL   = 5.0
PEER_TTL        = 30.0

# Chunk / socket tuning
CHUNK_SIZE      = 2 * 1024 * 1024   # 2 MiB per chunk
SOCK_BUF        = 16 * 1024 * 1024  # 16 MiB — important for high-latency WiFi
MAX_RETRY_FILES = 3
# Compression: probe ratio on first chunk; skip zlib if gain < this threshold
COMPRESS_MIN_GAIN = 0.05   # need at least 5% size reduction to bother

# Message types
T_HELLO        = 0x01
T_HELLO_ACK    = 0x02
T_FILE_META    = 0x10
T_CHUNK        = 0x11               # no per-chunk ACK — pipelined
T_FILE_END     = 0x13               # sender: file_index + file_sha256
T_FILE_END_ACK = 0x14               # receiver: ok | bad_chunks list
T_SESSION_END  = 0x20
T_ERROR        = 0xFF

log = logging.getLogger("ldt")


# ─────────────────────────────────────────────────────────────────────────────
# SOCKET HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _tune(sock: socket.socket) -> None:
    """Apply performance socket options."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, SOCK_BUF)
        except OSError:
            pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    if n == 0:
        return b""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        count = sock.recv_into(view[received:], n - received)
        if not count:
            raise EOFError("Connection closed")
        received += count
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
# COMPRESSION & INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────

def _compress(data: bytes) -> bytes:
    return zlib.compress(data, level=1)   # level 1 = fastest, still decent ratio


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


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
    def __init__(self, my_name: str, tcp_port: int = TCP_PORT):
        self.my_name = my_name
        self.tcp_port = tcp_port
        self.my_id = str(uuid.uuid4())
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

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
                self._announce(); last = time.monotonic()
            try:
                assert self._sock
                data, (src_ip, _) = self._sock.recvfrom(1024)
                self._handle(json.loads(data), src_ip)
            except (TimeoutError, OSError, json.JSONDecodeError):
                pass

    def _handle(self, msg: dict, src_ip: str) -> None:
        t = msg.get("t"); pid = msg.get("id", "")
        if pid == self.my_id: return
        if t == "BY":
            with self._lock: self._peers.pop(pid, None)
            return
        if t in ("AN", "QR"):
            peer = Peer(id=pid, name=msg.get("name", src_ip),
                        host=src_ip, port=msg.get("port", TCP_PORT),
                        seen=time.monotonic())
            with self._lock: self._peers[pid] = peer
            if t == "QR": self._announce()


# ─────────────────────────────────────────────────────────────────────────────
# FILE WALKER & CHUNKER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileEntry:
    abs_path: Path
    rel_path: str
    size: int
    mtime: float
    chunks: int


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
    """Yield raw chunks from file; empty file yields one empty bytes."""
    if path.stat().st_size == 0:
        yield b""; return
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK_SIZE)
            if not block: break
            yield block


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────────────────

class Progress:
    BAR = 28

    def __init__(self, label: str, total: int) -> None:
        self._label = label[-20:] if len(label) > 20 else label
        self._total = max(total, 1)
        self._done = 0
        self._t0 = time.monotonic()
        self._last = 0.0

    def advance(self, n: int) -> None:
        self._done += n
        now = time.monotonic()
        if now - self._last >= 0.15 or self._done >= self._total:
            self._last = now; self._draw()

    def finish(self) -> None:
        self._done = self._total; self._draw(); sys.stderr.write("\n"); sys.stderr.flush()

    def _draw(self) -> None:
        pct = self._done / self._total
        bar = "#" * int(self.BAR * pct) + "." * (self.BAR - int(self.BAR * pct))
        dt = time.monotonic() - self._t0
        speed = self._done / dt if dt else 0
        eta   = (self._total - self._done) / speed if speed > 0 else 0
        sys.stderr.write(
            f"\r  {self._label:<20} [{bar}] {pct*100:5.1f}%"
            f"  {_fmt(speed)}/s  ETA {_fmt_t(eta)}"
        ); sys.stderr.flush()


def _fmt(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024: return f"{n:6.1f} {u}"
        n /= 1024
    return f"{n:6.1f} TB"

def _fmt_t(s: float) -> str:
    if s < 60: return f"{s:.0f}s"
    return f"{s/60:.0f}m{int(s)%60:02d}s"


# ─────────────────────────────────────────────────────────────────────────────
# SENDER  — fully pipelined, no per-chunk ACK
# ─────────────────────────────────────────────────────────────────────────────

def _send_session(sock: socket.socket, entries: list[FileEntry],
                  my_name: str, quiet: bool = False) -> None:
    _tune(sock)

    # HELLO
    _send_frame(sock, T_HELLO,
                json.dumps({"name": my_name, "files": len(entries)}).encode())
    t, pl = _read_frame(sock)
    ack = json.loads(pl)
    if t != T_HELLO_ACK or not ack.get("ok"):
        raise RuntimeError(f"Rejected: {ack.get('reason', '?')}")

    for idx, entry in enumerate(entries):
        print(f"  [{idx+1}/{len(entries)}] {entry.rel_path}  ({_fmt(entry.size).strip()})")
        _send_file(sock, idx, entry, quiet)


def _send_file(sock: socket.socket, idx: int, entry: FileEntry,
               quiet: bool, attempt: int = 0) -> None:
    """Stream one file; retry on whole-file hash mismatch (up to MAX_RETRY_FILES)."""

    # ── decide whether to compress this file ─────────────────────────────────
    # Probe the first CHUNK_SIZE bytes. If zlib saves < COMPRESS_MIN_GAIN,
    # skip compression entirely — big win for video/zip/jpg/etc.
    use_compress = True
    if entry.size > 0:
        probe_size = min(entry.size, CHUNK_SIZE)
        with open(entry.abs_path, "rb") as fh:
            probe = fh.read(probe_size)
        probe_comp = _compress(probe)
        ratio = 1.0 - len(probe_comp) / len(probe)
        use_compress = ratio >= COMPRESS_MIN_GAIN
        if not use_compress:
            log.debug("%s: skipping compression (ratio %.1f%%)", entry.rel_path, ratio * 100)

    meta = json.dumps({
        "i": idx, "p": entry.rel_path,
        "s": entry.size, "c": entry.chunks, "m": entry.mtime,
        "retry": attempt,
        "nc": not use_compress,   # nc=True means no compression used
    }).encode()
    _send_frame(sock, T_FILE_META, meta)

    # ── pipeline: send all chunks without waiting for per-chunk ACK ──────────
    prog = None if quiet else Progress(entry.rel_path, entry.size)
    file_hasher = hashlib.sha256()

    for ci, raw in enumerate(_read_chunks(entry.abs_path)):
        file_hasher.update(raw)
        chunk_hash = _sha256(raw)
        if use_compress:
            data = _compress(raw)
            flags = FLAG_COMPRESSED
        else:
            data = raw
            flags = FLAG_RAW
        payload = struct.pack(CHUNK_HDR_FMT, ci, chunk_hash, len(data), flags) + data
        _send_frame(sock, T_CHUNK, payload)
        if prog:
            prog.advance(len(raw))

    if prog:
        prog.finish()

    # Send FILE_END with whole-file hash
    file_hash = file_hasher.digest()
    _send_frame(sock, T_FILE_END, struct.pack("!I32s", idx, file_hash))

    # Wait for FILE_END_ACK
    t, pl = _read_frame(sock)
    ack = json.loads(pl)

    if t == T_FILE_END_ACK and ack.get("ok"):
        return  # success

    # Receiver reports bad chunk indices → retry those only
    bad: list[int] = ack.get("bad", [])
    if bad:
        log.warning("%s: %d bad chunk(s): %s", entry.rel_path, len(bad), bad)
    else:
        log.warning("%s: file hash mismatch", entry.rel_path)

    reason = ack.get("reason", "?")
    if attempt >= MAX_RETRY_FILES:
        raise RuntimeError(f"{entry.rel_path} failed after {MAX_RETRY_FILES} retries: {reason}")

    print(f"  Retry {attempt+1}/{MAX_RETRY_FILES} for {entry.rel_path} ({reason})")
    _send_file(sock, idx, entry, quiet, attempt + 1)

    # Final SESSION_END (called by caller after all files)


def _finish_session(sock: socket.socket) -> None:
    _send_frame(sock, T_SESSION_END, b"")


# ─────────────────────────────────────────────────────────────────────────────
# RECEIVER  — stream chunks directly to disk, one SHA-256 file check
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
        threading.Thread(
            target=_recv_conn, args=(conn, addr[0], dest_dir),
            daemon=True, name=f"ldt-{addr[0]}"
        ).start()


def _recv_conn(sock: socket.socket, peer_ip: str, dest_dir: Path) -> None:
    try:
        _tune(sock)
        _recv_session(sock, peer_ip, dest_dir)
    except EOFError:
        pass
    except Exception as e:
        print(f"\n  !! Error from {peer_ip}: {e}", file=sys.stderr)
    finally:
        try: sock.close()
        except OSError: pass


def _recv_session(sock: socket.socket, peer_ip: str, dest_dir: Path) -> None:
    t, pl = _read_frame(sock)
    if t != T_HELLO:
        _send_frame(sock, T_HELLO_ACK,
                    json.dumps({"ok": False, "reason": "expected HELLO"}).encode())
        return
    info = json.loads(pl)
    sender = info.get("name", peer_ip)
    _send_frame(sock, T_HELLO_ACK, json.dumps({"ok": True}).encode())

    print(f"\n  <- {sender} ({peer_ip})  {info.get('files','?')} file(s)")

    while True:
        t, pl = _read_frame(sock)
        if t == T_SESSION_END:
            print(f"  OK Transfer from {sender} complete\n")
            break
        elif t == T_FILE_META:
            _recv_file(sock, json.loads(pl), dest_dir)
        elif t == T_ERROR:
            print(f"  !! {json.loads(pl).get('msg','?')}", file=sys.stderr)
            break


import queue as _queue  # noqa: E402  (stdlib)


def _recv_file(sock: socket.socket, meta: dict, dest_dir: Path) -> None:
    idx      = meta["i"]
    rel_path = meta["p"]
    total    = meta["s"]
    n_chunks = meta["c"]
    mtime    = meta["m"]
    no_comp  = meta.get("nc", False)   # True = sender sent raw (no zlib)

    # Security: block path traversal
    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        for _ in range(n_chunks): _read_frame(sock)
        _read_frame(sock)  # FILE_END
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "unsafe path"}).encode())
        return

    dest = dest_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)

    is_retry = meta.get("retry", 0) > 0
    label = f"{'retry ' if is_retry else ''}{rel_path}"
    print(f"  >> {label}  ({_fmt(total).strip()})")
    prog = Progress(rel_path, total)

    # ── async write queue so disk I/O never blocks socket reads ──────────────
    write_q: _queue.Queue[bytes | None] = _queue.Queue(maxsize=4)
    write_error: list[Exception] = []

    def _writer() -> None:
        try:
            with open(dest, "wb") as fh:
                while True:
                    block = write_q.get()
                    if block is None:   # sentinel
                        break
                    fh.write(block)
        except Exception as e:
            write_error.append(e)

    writer_thread = threading.Thread(target=_writer, daemon=True, name="ldt-write")
    writer_thread.start()

    # ── receive all chunks ────────────────────────────────────────────────────
    file_hasher = hashlib.sha256()
    bad_chunks: list[int] = []

    for _ in range(n_chunks):
        t, pl = _read_frame(sock)
        if t == T_ERROR:
            write_q.put(None)
            writer_thread.join()
            print(f"\n  !! sender error mid-transfer", file=sys.stderr)
            return

        if t != T_CHUNK:
            bad_chunks.append(-1)
            continue

        ci, expected_hash, dlen, flags = struct.unpack_from(CHUNK_HDR_FMT, pl)
        raw_data = pl[CHUNK_HDR_SIZE: CHUNK_HDR_SIZE + dlen]

        if flags & FLAG_COMPRESSED:
            try:
                raw = _decompress(raw_data)
            except zlib.error as e:
                log.warning("Chunk %d decompress error: %s", ci, e)
                bad_chunks.append(ci)
                write_q.put(b"\x00" * (CHUNK_SIZE if ci < n_chunks - 1 else total % CHUNK_SIZE or CHUNK_SIZE))
                continue
        else:
            raw = raw_data   # raw passthrough — no decompression needed

        if _sha256(raw) != expected_hash:
            log.warning("Chunk %d hash mismatch", ci)
            bad_chunks.append(ci)
            write_q.put(raw)   # write to keep file position correct
        else:
            file_hasher.update(raw)
            write_q.put(raw)

        prog.advance(len(raw))

    # Signal writer to finish, wait for all disk writes to complete
    write_q.put(None)
    writer_thread.join()

    if write_error:
        print(f"  !! Write error: {write_error[0]}", file=sys.stderr)
        dest.unlink(missing_ok=True)
        # drain FILE_END
        _read_frame(sock)
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": f"write error: {write_error[0]}"}).encode())
        return

    prog.finish()

    # FILE_END with whole-file hash
    t, pl = _read_frame(sock)
    if t != T_FILE_END:
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "expected FILE_END"}).encode())
        return

    _, sender_hash = struct.unpack("!I32s", pl)
    actual_hash = file_hasher.digest()

    if bad_chunks or actual_hash != sender_hash:
        dest.unlink(missing_ok=True)
        _send_frame(sock, T_FILE_END_ACK, json.dumps({
            "ok": False, "reason": "hash mismatch", "bad": bad_chunks,
        }).encode())
        print(f"  !! {rel_path}: hash mismatch -- will retry", file=sys.stderr)
        return

    try: os.utime(dest, (mtime, mtime))
    except OSError: pass

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
    threading.Thread(target=_recv_loop, args=(server, dest, stop),
                     daemon=True, name="ldt-server").start()

    print(f"LDT  |  name: {args.name}  |  port: {args.port}  |  saving to: {dest}")
    print("Waiting for transfers...  (Ctrl-C to stop)\n")
    try:
        while True: time.sleep(1)
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
        print(f"Error: {e}", file=sys.stderr); return 1

    if not entries:
        print("Nothing to send.", file=sys.stderr); return 1

    disc = Discovery(args.name, args.port)
    disc.start()
    disc.query()

    host: str; port: int
    deadline = time.monotonic() + 3
    peer = None
    while time.monotonic() < deadline:
        peer = disc.find(args.target)
        if peer: break
        time.sleep(0.2)

    if peer:
        host, port = peer.host, peer.port
        print(f"Found {peer.name} at {host}:{port}")
    else:
        host, port = args.target, args.port
        print(f"Peer '{args.target}' not found — trying {host}:{port} directly")

    total = sum(e.size for e in entries)
    print(f"Sending {len(entries)} file(s)  ({_fmt(total).strip()})  ->  {host}:{port}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"Cannot connect: {e}", file=sys.stderr); disc.stop(); return 1
    sock.settimeout(None)

    rc = 0
    try:
        t0 = time.monotonic()
        _send_session(sock, entries, args.name, quiet=args.quiet)
        _finish_session(sock)
        dt = time.monotonic() - t0
        speed = total / dt if dt else 0
        print(f"\nDone  {_fmt(total).strip()} in {_fmt_t(dt)}  ({_fmt(speed).strip()}/s avg)")
    except Exception as e:
        print(f"\nTransfer failed: {e}", file=sys.stderr); rc = 1
    finally:
        sock.close(); disc.stop()
    return rc


def cmd_peers(args: argparse.Namespace) -> int:
    disc = Discovery(args.name, args.port)
    disc.start()
    disc.query()

    wait = max(1, args.wait)
    print(f"Scanning for {wait:.0f}s ...")
    time.sleep(wait)

    peers = disc.peers()
    disc.stop()

    if not peers:
        print("No peers found."); return 0

    print(f"\n  {'NAME':<20}  {'IP':<16}  PORT")
    print("  " + "-" * 44)
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
        description="LDT -- Local Data Transfer  (serverless, P2P, stdlib only)",
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

    r = sub.add_parser("receive", help="Accept incoming transfers")
    r.add_argument("--dir", default="./received",
                   help="Directory for received files  (default: ./received)")

    s = sub.add_parser("send", help="Send files/folders to a peer")
    s.add_argument("target", help="Recipient name or IP")
    s.add_argument("paths", nargs="+", metavar="path")
    s.add_argument("--quiet", action="store_true", help="No progress bars")

    q = sub.add_parser("peers", help="List peers on the network")
    q.add_argument("--wait", type=float, default=3)

    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S")

    sys.exit({"receive": cmd_receive, "send": cmd_send, "peers": cmd_peers}[args.cmd](args))


if __name__ == "__main__":
    main()
