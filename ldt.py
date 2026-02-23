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
import shlex
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
T_EXEC         = 0x15               # sender: JSON {"cmd": "..."}
T_EXEC_RESULT  = 0x16               # receiver: JSON {"stdout": "...", "stderr": "...", "rc": 0}
T_SESSION_END  = 0x20
T_CANCEL       = 0x21               # either side: abort current transfer cleanly
T_ERROR        = 0xFF

RESUME_DIR     = ".ldt_resume"      # folder inside dest_dir for manifests

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


import queue as _diskq


def _read_chunks(path: Path) -> Iterator[bytes]:
    """Yield raw chunks from file; empty file yields one empty bytes."""
    if path.stat().st_size == 0:
        yield b""; return
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK_SIZE)
            if not block: break
            yield block


def _read_chunks_async(path: Path) -> Iterator[bytes]:
    """Same as _read_chunks but pre-fetches the next chunk in a background
    thread, overlapping disk I/O with network transmission."""
    q: _diskq.Queue[bytes | None] = _diskq.Queue(maxsize=2)

    def _reader() -> None:
        try:
            for chunk in _read_chunks(path):
                q.put(chunk)
        finally:
            q.put(None)  # sentinel

    threading.Thread(target=_reader, daemon=True, name="ldt-disk").start()
    while True:
        chunk = q.get()
        if chunk is None:
            break
        yield chunk


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR & COORDINATION
# ─────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()


class Progress:
    BAR = 28

    def __init__(self, label: str, total: int, quiet: bool = False) -> None:
        self._label = label[-20:] if len(label) > 20 else label
        self._total = max(total, 1)
        self._done = 0
        self._t0 = time.monotonic()
        self._last = 0.0
        self._quiet = quiet

    def advance(self, n: int) -> None:
        if self._quiet: return
        self._done += n
        now = time.monotonic()
        if now - self._last >= 0.15 or self._done >= self._total:
            self._last = now
            with _print_lock:
                self._draw()

    def finish(self) -> None:
        if self._quiet: return
        self._done = self._total
        with _print_lock:
            self._draw()
            sys.stderr.write("\n")
            sys.stderr.flush()

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


class _SharedProgress:
    """Coordinated progress bar for parallel workers."""
    BAR = 28

    def __init__(self, n_files: int, total_bytes: int) -> None:
        self.n_files = n_files
        self.total_bytes = max(total_bytes, 1)
        self.done_bytes = 0
        self.done_files = 0
        self.lock = threading.Lock()
        self.t0 = time.monotonic()
        self.last_draw = 0.0

    def file_done(self) -> None:
        with self.lock:
            self.done_files += 1

    def advance(self, n: int) -> None:
        with self.lock:
            self.done_bytes += n
            now = time.monotonic()
            if now - self.last_draw < 0.2 and self.done_bytes < self.total_bytes:
                return
            self.last_draw = now
            
        # Draw outside lock but under _print_lock
        with _print_lock:
            pct = self.done_bytes / self.total_bytes
            bar = "#" * int(self.BAR * pct) + "." * (self.BAR - int(self.BAR * pct))
            dt = time.monotonic() - self.t0
            speed = self.done_bytes / dt if dt else 0
            eta = (self.total_bytes - self.done_bytes) / speed if speed > 0 else 0
            sys.stderr.write(
                f"\r  Progress [{bar}] {pct*100:5.1f}%  ({self.done_files}/{self.n_files} files)"
                f"  {_fmt(speed)}/s  ETA {_fmt_t(eta)}    "
            ); sys.stderr.flush()

    def finish(self) -> None:
        self.done_bytes = self.total_bytes
        self.advance(0)
        with _print_lock:
            sys.stderr.write("\n")
            sys.stderr.flush()


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

# ─────────────────────────────────────────────────────────────────────────────
# RESUME HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# Global lock — protects manifest from concurrent writes by parallel-worker threads
_manifest_lock = threading.Lock()


def _resume_manifest_path(dest_dir: Path) -> Path:
    return dest_dir / RESUME_DIR / "manifest.json"


def _load_manifest(dest_dir: Path) -> dict:
    """Read manifest (must be called while holding _manifest_lock)."""
    p = _resume_manifest_path(dest_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _write_manifest(dest_dir: Path, m: dict) -> None:
    """Write manifest atomically (must be called while holding _manifest_lock)."""
    p = _resume_manifest_path(dest_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Use thread-ID in temp-name so concurrent calls never collide
    tmp = p.with_name(f"manifest_{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps(m), encoding="utf-8")
    tmp.replace(p)


def _manifest_set(dest_dir: Path, key: str, value: dict) -> None:
    """Atomically add/update one entry in the manifest."""
    with _manifest_lock:
        m = _load_manifest(dest_dir)
        m[key] = value
        _write_manifest(dest_dir, m)


def _manifest_remove(dest_dir: Path, key: str) -> None:
    """Atomically delete one entry from the manifest."""
    with _manifest_lock:
        m = _load_manifest(dest_dir)
        if key in m:
            del m[key]
            _write_manifest(dest_dir, m)


def _check_receiver_state(
    entries: list[FileEntry], dest_dir: Path
) -> tuple[list[int], dict[int, int]]:
    """Check dest_dir for completed / partial files.
    Returns (skip_indices, resume_map) where resume_map maps idx→chunk_count.
    """
    with _manifest_lock:
        manifest = _load_manifest(dest_dir)
    skip: list[int] = []
    resume: dict[int, int] = {}

    for idx, entry in enumerate(entries):
        dest = dest_dir / Path(entry.rel_path)
        part = dest.with_suffix(dest.suffix + ".ldtpart")

        if dest.exists() and dest.stat().st_size == entry.size:
            skip.append(idx)
        elif entry.rel_path in manifest:
            n_chunks = manifest[entry.rel_path].get("chunks", 0)
            if n_chunks > 0 and part.exists():
                resume[idx] = n_chunks

    return skip, resume


# ─────────────────────────────────────────────────────────────────────────────
# SENDER  — fully pipelined, no per-chunk ACK
# ─────────────────────────────────────────────────────────────────────────────

def _send_session(
    sock: socket.socket, entries: list[FileEntry],
    my_name: str, quiet: bool = False,
    g_offset: int = 0, g_total: int = 0,
    cancel: threading.Event | None = None,
    shared_prog: _SharedProgress | None = None,
) -> None:
    """g_offset / g_total: global file numbering for parallel workers.
    cancel: set this Event to abort cleanly with T_CANCEL.
    """
    _tune(sock)
    total_label = g_total or len(entries)

    # HELLO — include lightweight manifest for resume negotiation
    manifest_payload = [{"p": e.rel_path, "s": e.size, "m": e.mtime}
                        for e in entries]
    _send_frame(sock, T_HELLO,
                json.dumps({"name": my_name, "files": len(entries),
                            "manifest": manifest_payload}).encode())
    t, pl = _read_frame(sock)
    ack = json.loads(pl)
    if t != T_HELLO_ACK or not ack.get("ok"):
        raise RuntimeError(f"Rejected: {ack.get('reason', '?')}")

    skip_set: set[int] = set(ack.get("skip", []))
    resume_map: dict[int, int] = {int(k): v for k, v in ack.get("resume", {}).items()}

    for idx, entry in enumerate(entries):
        global_idx = g_offset + idx + 1

        if cancel and cancel.is_set():
            _send_frame(sock, T_CANCEL, b"")
            return

        if idx in skip_set:
            if not quiet and not shared_prog:
                with _print_lock:
                    print(f"  [{global_idx}/{total_label}] {entry.rel_path}  "
                          f"({_fmt(entry.size).strip()})  -- SKIP (already on receiver)")
            if shared_prog:
                shared_prog.advance(entry.size)
                shared_prog.file_done()
            continue

        resume_from = resume_map.get(idx, 0)
        if not quiet and not shared_prog:
            with _print_lock:
                resume_label = f" -- RESUME from chunk {resume_from}" if resume_from else ""
                print(f"  [{global_idx}/{total_label}] {entry.rel_path}  "
                      f"({_fmt(entry.size).strip()}){resume_label}")

        _send_file(sock, idx, entry, quiet, attempt=0,
                   resume_from=resume_from, cancel=cancel, shared_prog=shared_prog)
        if shared_prog:
            shared_prog.file_done()


def _send_file(
    sock: socket.socket, idx: int, entry: FileEntry,
    quiet: bool, attempt: int = 0,
    resume_from: int = 0,
    cancel: threading.Event | None = None,
    shared_prog: _SharedProgress | None = None,
) -> None:
    """Stream one file; retry on whole-file hash mismatch (up to MAX_RETRY_FILES)."""

    # ── decide whether to compress this file ─────────────────────────────────
    use_compress = True
    if entry.size > 0:
        probe_size = min(entry.size, CHUNK_SIZE)
        with open(entry.abs_path, "rb") as fh:
            fh.seek(resume_from * CHUNK_SIZE)  # probe from current position
            probe = fh.read(probe_size)
        if probe:
            probe_comp = _compress(probe)
            ratio = 1.0 - len(probe_comp) / len(probe)
            use_compress = ratio >= COMPRESS_MIN_GAIN

    meta = json.dumps({
        "i": idx, "p": entry.rel_path,
        "s": entry.size, "c": entry.chunks, "m": entry.mtime,
        "retry": attempt,
        "nc": not use_compress,
        "resume_from": resume_from,   # NEW: tell receiver where we're starting
    }).encode()
    _send_frame(sock, T_FILE_META, meta)

    # ── pipeline: send chunks; hash entire file for integrity ───────────────
    already_done = resume_from * CHUNK_SIZE
    display_size = max(entry.size - already_done, 0)
    
    # Use shared progress if in parallel mode, else local one
    prog = None
    if not quiet and not shared_prog:
        prog = Progress(entry.rel_path, max(display_size, 1))
    
    file_hasher = hashlib.sha256()

    with open(entry.abs_path, "rb") as fh:
        # Pre-hash the skipped prefix so full-file hash matches receiver
        if resume_from:
            remaining = already_done
            while remaining > 0:
                block = fh.read(min(CHUNK_SIZE, remaining))
                if not block:
                    break
                file_hasher.update(block)
                remaining -= len(block)

        # Send chunks from resume_from onward
        ci = resume_from
        while True:
            if cancel and cancel.is_set():
                _send_frame(sock, T_CANCEL, b"")
                return
            raw = fh.read(CHUNK_SIZE)
            if not raw:
                break
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
            if shared_prog:
                shared_prog.advance(len(raw))
            ci += 1

    if prog:
        prog.finish()

    # FILE_END carries full-file hash (from byte 0)
    file_hash = file_hasher.digest()
    _send_frame(sock, T_FILE_END, struct.pack("!I32s", idx, file_hash))

    # Wait for FILE_END_ACK
    t, pl = _read_frame(sock)
    ack = json.loads(pl)

    if t == T_FILE_END_ACK and ack.get("ok"):
        return

    bad: list[int] = ack.get("bad", [])
    reason = ack.get("reason", "?")
    if bad:
        log.warning("%s: %d bad chunk(s): %s", entry.rel_path, len(bad), bad)
    if attempt >= MAX_RETRY_FILES:
        raise RuntimeError(f"{entry.rel_path} failed after {MAX_RETRY_FILES} retries: {reason}")

    print(f"  Retry {attempt+1}/{MAX_RETRY_FILES} for {entry.rel_path} ({reason})")
    _send_file(sock, idx, entry, quiet, attempt + 1, resume_from=0,
               cancel=cancel, shared_prog=shared_prog)


def _finish_session(sock: socket.socket) -> None:
    _send_frame(sock, T_SESSION_END, b"")


def _cancel_session(sock: socket.socket) -> None:
    """Send T_CANCEL and close — used for clean abort."""
    try:
        _send_frame(sock, T_CANCEL, b"")
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# PARALLEL SEND  — split file list across N TCP connections
# ─────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def _send_parallel(
    entries: list[FileEntry], host: str, port: int,
    my_name: str, workers: int, quiet: bool,
    cancel: threading.Event | None = None,
) -> None:
    """Send files across `workers` simultaneous TCP connections.
    Each connection carries a round-robin slice of the file list.
    Receiver already handles multiple concurrent connections.
    """
    workers = min(workers, len(entries))
    groups: list[list[FileEntry]] = [[] for _ in range(workers)]
    for i, e in enumerate(entries):
        groups[i % workers].append(e)

    errors: list[Exception] = []
    err_lock = threading.Lock()

    g_total = len(entries)
    total_bytes = sum(e.size for e in entries)
    shared_prog = None if quiet else _SharedProgress(g_total, total_bytes)
    
    g_offsets = [0] * workers
    count = 0
    for i in range(workers):
        g_offsets[i] = count
        assigned = len(groups[i])
        count += assigned

    def _worker(group: list[FileEntry], wid: int, g_off: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        try:
            sock.connect((host, port))
        except OSError as e:
            with err_lock: errors.append(e)
            return
        sock.settimeout(None)
        try:
            _send_session(sock, group, my_name, quiet,
                          g_offset=g_off, g_total=g_total, cancel=cancel,
                          shared_prog=shared_prog)
            if cancel and cancel.is_set():
                _cancel_session(sock)
            else:
                _finish_session(sock)
        except Exception as e:
            with err_lock: errors.append(e)
        finally:
            sock.close()

    threads = [
        threading.Thread(target=_worker, args=(g, i, g_offsets[i]),
                         name=f"ldt-send-{i}", daemon=True)
        for i, g in enumerate(groups) if g
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    if shared_prog:
        shared_prog.finish()

    if errors:
        raise errors[0]


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


def _recv_loop(server: socket.socket, dest_dir: Path, stop: threading.Event, allow_exec: bool = False) -> None:
    while not stop.is_set():
        try:
            conn, addr = server.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        threading.Thread(
            target=_recv_conn, args=(conn, addr[0], dest_dir, allow_exec),
            daemon=True, name=f"ldt-{addr[0]}"
        ).start()


def _recv_conn(sock: socket.socket, peer_ip: str, dest_dir: Path, allow_exec: bool = False) -> None:
    try:
        _tune(sock)
        _recv_session(sock, peer_ip, dest_dir, allow_exec=allow_exec)
    except EOFError:
        pass
    except Exception as e:
        print(f"\n  !! Error from {peer_ip}: {e}", file=sys.stderr)
    finally:
        try: sock.close()
        except OSError: pass


def _recv_session(sock: socket.socket, peer_ip: str, dest_dir: Path, allow_exec: bool = False) -> None:
    t, pl = _read_frame(sock)
    if t != T_HELLO:
        _send_frame(sock, T_HELLO_ACK,
                    json.dumps({"ok": False, "reason": "expected HELLO"}).encode())
        return
    info = json.loads(pl)
    sender = info.get("name", peer_ip)

    # ── Resume negotiation ────────────────────────────────────────────────────
    # Build FileEntry list from manifest the sender included in HELLO
    raw_manifest = info.get("manifest", [])
    skip_list: list[int] = []
    resume_dict: dict[int, int] = {}

    if raw_manifest:
        fake_entries = [
            FileEntry(
                abs_path=Path("/"),  # not used here
                rel_path=m["p"],
                size=int(m["s"]),
                mtime=float(m["m"]),
                chunks=max(1, -(-int(m["s"]) // CHUNK_SIZE)),
            )
            for m in raw_manifest
        ]
        skip_list, resume_dict = _check_receiver_state(fake_entries, dest_dir)
        if skip_list:
            print(f"  Resume: skipping {len(skip_list)} already-complete file(s)")
        if resume_dict:
            print(f"  Resume: continuing {len(resume_dict)} partial file(s)")

    _send_frame(sock, T_HELLO_ACK, json.dumps({
        "ok": True,
        "skip": skip_list,
        "resume": {str(k): v for k, v in resume_dict.items()},
    }).encode())

    print(f"\n  <- {sender} ({peer_ip})  {info.get('files','?')} file(s)")

    while True:
        t, pl = _read_frame(sock)
        if t == T_SESSION_END:
            print(f"  OK Transfer from {sender} complete\n")
            break
        elif t == T_CANCEL:
            print(f"  !! Transfer from {sender} was cancelled by sender", file=sys.stderr)
            break
        elif t == T_FILE_META:
            _recv_file(sock, json.loads(pl), dest_dir)
        elif t == T_EXEC:
            info = json.loads(pl)
            cmd = info.get("cmd", "")
            if not allow_exec:
                _send_frame(sock, T_EXEC_RESULT, json.dumps({
                    "rc": 1, "stderr": "Remote execution is disabled on this peer (use --allow-exec to enable)."
                }).encode())
            else:
                try:
                    import subprocess
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    _send_frame(sock, T_EXEC_RESULT, json.dumps({
                        "rc": res.returncode, "stdout": res.stdout, "stderr": res.stderr
                    }).encode())
                except Exception as e:
                    _send_frame(sock, T_EXEC_RESULT, json.dumps({
                        "rc": 1, "stderr": str(e)
                    }).encode())
        elif t == T_ERROR:
            print(f"  !! {json.loads(pl).get('msg','?')}", file=sys.stderr)
            break


import queue as _queue  # noqa: E402  (stdlib)


def _recv_file(sock: socket.socket, meta: dict, dest_dir: Path) -> None:
    idx       = meta["i"]
    rel_path  = meta["p"]
    total     = meta["s"]
    n_chunks  = meta["c"]
    mtime     = meta["m"]
    no_comp   = meta.get("nc", False)
    resume_from = int(meta.get("resume_from", 0))   # chunk index sender started from

    # Security: block path traversal
    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        for _ in range(n_chunks - resume_from): _read_frame(sock)
        _read_frame(sock)  # FILE_END
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "unsafe path"}).encode())
        return

    dest = dest_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".ldtpart")

    is_retry = meta.get("retry", 0) > 0
    label = f"{'retry ' if is_retry else ''}{rel_path}"
    if resume_from:
        label = f"resume {rel_path} (chunk {resume_from}+)"
    print(f"  >> {label}  ({_fmt(total).strip()})")

    # Progress shows only what we're receiving now
    recv_size = max(total - resume_from * CHUNK_SIZE, 1)
    prog = Progress(rel_path, recv_size)

    # ── async write queue ─────────────────────────────────────────────────────
    write_q: _queue.Queue[bytes | None] = _queue.Queue(maxsize=4)
    write_error: list[Exception] = []

    def _writer() -> None:
        try:
            mode = "ab" if resume_from else "wb"   # append for resume
            with open(part, mode) as fh:
                while True:
                    block = write_q.get()
                    if block is None:
                        break
                    fh.write(block)
        except Exception as e:
            write_error.append(e)

    writer_thread = threading.Thread(target=_writer, daemon=True, name="ldt-write")
    writer_thread.start()

    # ── Hash already-saved bytes if resuming ──────────────────────────────────
    file_hasher = hashlib.sha256()
    # If resuming, we need to replay hash of already-saved bytes
    if resume_from and part.exists():
        with open(part, "rb") as fh:
            for block in iter(lambda: fh.read(CHUNK_SIZE), b""):
                file_hasher.update(block)

    bad_chunks: list[int] = []
    chunks_received = resume_from

    # ── receive all chunks ────────────────────────────────────────────────────
    for _ in range(n_chunks - resume_from):
        t, pl = _read_frame(sock)

        if t in (T_ERROR, T_CANCEL):
            # Sender cancelled or errored — keep .ldtpart for resume later
            write_q.put(None)
            writer_thread.join()
            _manifest_set(dest_dir, rel_path, {"chunks": chunks_received, "size": total})
            if t == T_CANCEL:
                print(f"  !! Sender cancelled — partial file kept for resume")
            else:
                print(f"  !! Sender error mid-transfer — partial kept", file=sys.stderr)
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
                write_q.put(b"\x00" * CHUNK_SIZE)
                continue
        else:
            raw = raw_data

        if _sha256(raw) != expected_hash:
            log.warning("Chunk %d hash mismatch", ci)
            bad_chunks.append(ci)
            write_q.put(raw)
        else:
            file_hasher.update(raw)
            write_q.put(raw)
            chunks_received += 1

        prog.advance(len(raw))

    # ── wait for all writes to complete ──────────────────────────────────────
    write_q.put(None)
    writer_thread.join()

    if write_error:
        print(f"  !! Write error: {write_error[0]}", file=sys.stderr)
        _manifest_set(dest_dir, rel_path, {"chunks": chunks_received, "size": total})
        _read_frame(sock)  # drain FILE_END
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": f"write error: {write_error[0]}"}).encode())
        return

    prog.finish()

    # ── FILE_END with transmitted-chunk hash ──────────────────────────────────
    t, pl = _read_frame(sock)
    if t != T_FILE_END:
        _send_frame(sock, T_FILE_END_ACK,
                    json.dumps({"ok": False, "reason": "expected FILE_END"}).encode())
        return

    _, sender_hash = struct.unpack("!I32s", pl)
    actual_hash = file_hasher.digest()

    if bad_chunks or actual_hash != sender_hash:
        # Keep partial for next attempt
        _manifest_set(dest_dir, rel_path, {"chunks": resume_from, "size": total})  # restart from before resume
        part.unlink(missing_ok=True)  # bad data — restart from 0
        _send_frame(sock, T_FILE_END_ACK, json.dumps({
            "ok": False, "reason": "hash mismatch", "bad": bad_chunks,
        }).encode())
        print(f"  !! {rel_path}: hash mismatch -- will retry", file=sys.stderr)
        return

    # ── Success: rename .ldtpart → final, clean manifest ─────────────────────
    try: os.utime(part, (mtime, mtime))
    except OSError: pass

    # Atomic rename
    try:
        part.replace(dest)
    except OSError:
        import shutil
        shutil.move(str(part), str(dest))

    # Remove from resume manifest
    _manifest_remove(dest_dir, rel_path)


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
    threading.Thread(target=_recv_loop, args=(server, dest, stop, args.allow_exec),
                     daemon=True, name="ldt-server").start()

    print(f"LDT  |  name: {args.name}  |  port: {args.port}  |  saving to: {dest}")
    if args.allow_exec:
        print("  WARNING: Remote execution is ENABLED on this machine.")
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
    workers = min(args.workers, len(entries))
    if workers <= 1:
        workers = 1
    print(f"Sending {len(entries)} file(s)  ({_fmt(total).strip()})  ->  {host}:{port}"
          + (f"  [workers={workers}]" if workers > 1 else "") + "\n")

    rc = 0
    try:
        t0 = time.monotonic()
        if workers <= 1:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            try:
                sock.connect((host, port))
            except OSError as e:
                print(f"Cannot connect: {e}", file=sys.stderr)
                disc.stop(); return 1
            sock.settimeout(None)
            try:
                _send_session(sock, entries, args.name, quiet=args.quiet)
                _finish_session(sock)
            finally:
                sock.close()
        else:
            _send_parallel(entries, host, port, args.name, workers, args.quiet)
        dt = time.monotonic() - t0
        speed = total / dt if dt else 0
        print(f"\nDone  {_fmt(total).strip()} in {_fmt_t(dt)}  ({_fmt(speed).strip()}/s avg)")
    except Exception as e:
        print(f"\nTransfer failed: {e}", file=sys.stderr); rc = 1
    finally:
        disc.stop()
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
# INTERACTIVE (REPL) MODE
# ─────────────────────────────────────────────────────────────────────────────

_REPL_HELP = """
Commands:
  peers                            List peers on the network
  send <target> <path> [<path>...]  Send files/folders to a peer
       --workers N                 Use N parallel connections (default 1)
  dir [PATH]                       Change/show save directory for received files
  quiet                            Toggle quiet mode (no progress bars)
  exec <target> <cmd>             Execute a shell command on a peer
  help                             Show this message
  exit                             Quit (Ctrl-C during a send cancels it; Ctrl-C at prompt exits)
"""


def _do_exec_interactive(
    disc: Discovery, target: str, cmd: str,
    my_name: str, port: int,
) -> None:
    """Send T_EXEC to a peer and wait for T_EXEC_RESULT."""
    # Resolve peer
    disc.query()
    deadline = time.monotonic() + 3
    peer = None
    while time.monotonic() < deadline:
        peer = disc.find(target)
        if peer: break
        time.sleep(0.2)

    if peer:
        host, p_port = peer.host, peer.port
    else:
        host, p_port = target, port

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((host, p_port))
        sock.settimeout(None)
        try:
            # HELLO
            _send_frame(sock, T_HELLO, json.dumps({"name": my_name, "files": 0}).encode())
            t, pl = _read_frame(sock)
            
            # T_EXEC
            _send_frame(sock, T_EXEC, json.dumps({"cmd": cmd}).encode())
            t, pl = _read_frame(sock)
            if t == T_EXEC_RESULT:
                res = json.loads(pl)
                print(f"\n  --- Result from {target} ---")
                if res.get("stdout"):
                    print(res["stdout"])
                if res.get("stderr"):
                    print(res["stderr"], file=sys.stderr)
                print(f"  --- Return Code: {res.get('rc')} ---")
            else:
                print(f"  !! Unexpected response: {t}")
            _finish_session(sock)
        finally:
            sock.close()
    except Exception as e:
        print(f"  !! Exec failed: {e}")


def _do_send_interactive(
    disc: Discovery, line_parts: list[str],
    my_name: str, port: int, quiet: bool,
    cancel: threading.Event,
) -> None:
    """Parse and execute a `send` command entered at the interactive prompt.
    `cancel` is set to abort mid-transfer; checked between every chunk.
    """
    # Parse workers flag
    workers = 1
    clean: list[str] = []
    i = 0
    while i < len(line_parts):
        if line_parts[i] == "--workers" and i + 1 < len(line_parts):
            try: workers = int(line_parts[i + 1])
            except ValueError: pass
            i += 2
        else:
            clean.append(line_parts[i]); i += 1

    if len(clean) < 2:
        print("  Usage: send <target> <path> [<path>...]")
        return

    target, raw_paths = clean[0], clean[1:]

    try:
        entries = _entries(raw_paths)
    except FileNotFoundError as e:
        print(f"  Error: {e}"); return

    if not entries:
        print("  Nothing to send."); return

    # Resolve peer
    disc.query()
    deadline = time.monotonic() + 3
    peer = None
    while time.monotonic() < deadline:
        if cancel.is_set():
            print("  Cancelled.")
            return
        peer = disc.find(target)
        if peer: break
        time.sleep(0.2)

    if peer:
        host, p_port = peer.host, peer.port
        print(f"  -> {peer.name}  [{host}:{p_port}]")
    else:
        host, p_port = target, port
        print(f"  Peer '{target}' not found — trying {host}:{p_port} directly")

    if cancel.is_set():
        print("  Cancelled.")
        return

    total = sum(e.size for e in entries)
    workers = min(workers, len(entries))
    print(f"  Sending {len(entries)} file(s)  ({_fmt(total).strip()})" +
          (f"  [workers={workers}]" if workers > 1 else "") + "\n")

    try:
        t0 = time.monotonic()
        if workers <= 1:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((host, p_port))
            sock.settimeout(None)
            try:
                _send_session(sock, entries, my_name, quiet, cancel=cancel)
                if not cancel.is_set():
                    _finish_session(sock)
                else:
                    _cancel_session(sock)
                    print("\n  Transfer cancelled.")
                    return
            finally:
                sock.close()
        else:
            _send_parallel(entries, host, p_port, my_name, workers, quiet,
                           cancel=cancel)
            if cancel.is_set():
                print("\n  Transfer cancelled.")
                return
        dt = time.monotonic() - t0
        speed = total / dt if dt else 0
        print(f"\n  Done  {_fmt(total).strip()} in {_fmt_t(dt)}  ({_fmt(speed).strip()}/s)")
    except OSError as e:
        print(f"  Cannot connect: {e}")
    except Exception as e:
        print(f"  Transfer failed: {e}")


def cmd_interactive(args: argparse.Namespace) -> int:
    """Default mode: receiver always on, interactive send/peers commands."""
    recv_dir = Path(getattr(args, "dir", "./received")).resolve()
    recv_dir.mkdir(parents=True, exist_ok=True)

    disc = Discovery(args.name, args.port)
    disc.start()

    server = _recv_server(recv_dir, args.port)
    stop = threading.Event()
    threading.Thread(target=_recv_loop, args=(server, recv_dir, stop, args.allow_exec),
                     daemon=True, name="ldt-server").start()

    print(f"LDT  |  {args.name}  |  port {args.port}  |  saving to {recv_dir}")
    if args.allow_exec:
        print("  WARNING: Remote execution is ENABLED on this machine.")
    print("Ready. Type 'help' for commands, Ctrl-C cancels send / exits.\n")

    quiet = False

    try:
        while True:
            try:
                line = input("ldt> ").strip()
            except EOFError:
                break
            except KeyboardInterrupt:
                # Ctrl-C at the prompt → exit
                break

            if not line:
                continue

            try:
                parts = shlex.split(line)
            except ValueError as e:
                print(f"  Parse error: {e}"); continue

            cmd = parts[0].lower()
            rest = parts[1:]

            if cmd in ("exit", "quit", "q"):
                break

            elif cmd in ("help", "h", "?"):
                print(_REPL_HELP)

            elif cmd == "peers":
                disc.query()
                time.sleep(0.8)
                found = disc.peers()
                if not found:
                    print("  No peers found yet — peers announce every 5s")
                else:
                    print(f"\n  {'NAME':<20}  {'IP':<16}  PORT")
                    print("  " + "-" * 44)
                    for peer in found:
                        print(f"  {peer.name:<20}  {peer.host:<16}  {peer.port}")
                    print()

            elif cmd == "send":
                _active_cancel = threading.Event()
                _send_thread = threading.Thread(
                    target=_do_send_interactive,
                    args=(disc, rest, args.name, args.port, quiet, _active_cancel),
                    daemon=True, name="ldt-send",
                )
                _send_thread.start()
                try:
                    _send_thread.join()
                except KeyboardInterrupt:
                    # Ctrl-C during send → cancel only the transfer
                    print("\n  Cancelling... (press Ctrl-C again to force-quit)")
                    _active_cancel.set()
                    try:
                        _send_thread.join(timeout=5)
                    except KeyboardInterrupt:
                        pass  # force quit on second Ctrl-C

            elif cmd == "dir":
                if rest:
                    try:
                        new_dir = Path(rest[0]).resolve()
                        new_dir.mkdir(parents=True, exist_ok=True)
                        recv_dir = new_dir
                        # Restart server with new dest
                        stop.set()
                        try: server.close()
                        except OSError: pass
                        stop = threading.Event()
                        server = _recv_server(recv_dir, args.port)
                        threading.Thread(
                            target=_recv_loop, args=(server, recv_dir, stop, args.allow_exec),
                            daemon=True, name="ldt-server"
                        ).start()
                        print(f"  Saving to: {recv_dir}")
                    except Exception as e:
                        print(f"  Error: {e}")
                else:
                    print(f"  Saving to: {recv_dir}")

            elif cmd == "quiet":
                quiet = not quiet
                print(f"  Quiet mode: {'on' if quiet else 'off'}")

            elif cmd == "exec":
                if len(rest) < 2:
                    print("  Usage: exec <target> <command>")
                else:
                    target, command = rest[0], " ".join(rest[1:])
                    _do_exec_interactive(disc, target, command, args.name, args.port)

            else:
                print(f"  Unknown command: '{cmd}'  (type 'help')")

    except KeyboardInterrupt:
        pass

    stop.set()
    try: server.close()
    except OSError: pass
    disc.stop()
    print("\nBye.")
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
  python ldt.py Alice               <- interactive mode (recommended)
  python ldt.py Alice receive       <- receive-only mode
  python ldt.py Bob send Alice report.pdf
""",
    )
    p.add_argument("name", help="Your display name on the network")
    p.add_argument("--port", type=int, default=TCP_PORT,
                   help=f"UDP/TCP port (default {TCP_PORT})")
    p.add_argument("--dir", default="./received",
                   help="Directory for received files (default: ./received)")
    p.add_argument("--allow-exec", action="store_true", default=True,
                   help="Allow remote commands to be executed on this machine (SECURITY RISK)")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=False)

    r = sub.add_parser("receive", help="Receive-only mode (no interactive prompt)")
    r.add_argument("--dir", default="./received",
                   help="Directory for received files  (default: ./received)")

    s = sub.add_parser("send", help="Send files/folders to a peer (one-shot)")
    s.add_argument("target", help="Recipient name or IP")
    s.add_argument("paths", nargs="+", metavar="path")
    s.add_argument("--quiet", action="store_true", help="No progress bars")
    s.add_argument(
        "--workers", type=int, default=1, metavar="N",
        help="Parallel TCP connections (default 1; try 3-4 for folders on WiFi)",
    )

    q = sub.add_parser("peers", help="List peers on the network (one-shot)")
    q.add_argument("--wait", type=float, default=3)

    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S")

    dispatch = {
        "receive": cmd_receive,
        "send":    cmd_send,
        "peers":   cmd_peers,
    }
    fn = dispatch.get(args.cmd or "", cmd_interactive)
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
