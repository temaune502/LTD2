"""
LDTv1 Protocol — wire format encode/decode.

Frame layout (TCP):
  [magic: 4B][type: 1B][payload_len: 4B][payload: NB]

Magic = 0x4C445401  ("LDT\x01")
All integers big-endian.

CHUNK payload:
  [chunk_index: 4B][hash: 32B][data_len: 4B][zstd-compressed data: NB]
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC: bytes = b"LDT\x01"
MAGIC_INT: int = 0x4C445401
HEADER_FMT: str = "!4sBI"           # magic(4s) type(B) payload_len(I)
HEADER_SIZE: int = struct.calcsize(HEADER_FMT)  # = 9

CHUNK_HEADER_FMT: str = "!I32sI"    # chunk_index(I) hash(32s) data_len(I)
CHUNK_HEADER_SIZE: int = struct.calcsize(CHUNK_HEADER_FMT)  # = 40

DEFAULT_TCP_PORT: int = 9998
DISCOVERY_PORT: int = 9999
MULTICAST_GROUP: str = "239.255.42.42"
MAX_CHUNK_BYTES: int = 512 * 1024   # 512 KiB uncompressed
MAX_CHUNK_RETRY: int = 3
DISCOVERY_INTERVAL: float = 5.0
PEER_TTL: float = 30.0


# ---------------------------------------------------------------------------
# Message type enum
# ---------------------------------------------------------------------------

class MsgType(IntEnum):
    HELLO         = 0x01
    HELLO_ACK     = 0x02
    FILE_META     = 0x10
    CHUNK         = 0x11
    CHUNK_ACK     = 0x12
    FILE_END      = 0x13
    FILE_END_ACK  = 0x14
    SESSION_END   = 0x20
    ERROR         = 0xFF


# ---------------------------------------------------------------------------
# Payload dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HelloPayload:
    sender_id: str
    sender_name: str
    file_count: int

@dataclass
class HelloAckPayload:
    accepted: bool
    reason: str = ""

@dataclass
class FileMetaPayload:
    file_index: int          # 0-based index in transfer
    rel_path: str            # relative path (for folder structure)
    size: int                # total uncompressed size in bytes
    total_chunks: int        # number of chunks to expect
    mtime: float             # original modification time

@dataclass
class ChunkPayload:
    chunk_index: int
    chunk_hash: bytes        # 32-byte BLAKE3 digest
    data: bytes              # zstd-compressed chunk data

@dataclass
class ChunkAckPayload:
    chunk_index: int
    ok: bool
    reason: str = ""

@dataclass
class FileEndPayload:
    file_index: int
    file_hash: bytes         # 32-byte BLAKE3 of entire raw file

@dataclass
class FileEndAckPayload:
    file_index: int
    ok: bool
    reason: str = ""

@dataclass
class ErrorPayload:
    code: int
    message: str


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _pack_frame(msg_type: MsgType, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FMT, MAGIC, int(msg_type), len(payload))
    return header + payload


def encode_hello(p: HelloPayload) -> bytes:
    body = json.dumps({
        "id": p.sender_id,
        "name": p.sender_name,
        "files": p.file_count,
    }).encode()
    return _pack_frame(MsgType.HELLO, body)


def encode_hello_ack(p: HelloAckPayload) -> bytes:
    body = json.dumps({"ok": p.accepted, "reason": p.reason}).encode()
    return _pack_frame(MsgType.HELLO_ACK, body)


def encode_file_meta(p: FileMetaPayload) -> bytes:
    body = json.dumps({
        "idx": p.file_index,
        "path": p.rel_path,
        "size": p.size,
        "chunks": p.total_chunks,
        "mtime": p.mtime,
    }).encode()
    return _pack_frame(MsgType.FILE_META, body)


def encode_chunk(p: ChunkPayload) -> bytes:
    chunk_hdr = struct.pack(CHUNK_HEADER_FMT,
                            p.chunk_index, p.chunk_hash, len(p.data))
    return _pack_frame(MsgType.CHUNK, chunk_hdr + p.data)


def encode_chunk_ack(p: ChunkAckPayload) -> bytes:
    body = json.dumps({"idx": p.chunk_index, "ok": p.ok, "reason": p.reason}).encode()
    return _pack_frame(MsgType.CHUNK_ACK, body)


def encode_file_end(p: FileEndPayload) -> bytes:
    body = struct.pack("!I32s", p.file_index, p.file_hash)
    return _pack_frame(MsgType.FILE_END, body)


def encode_file_end_ack(p: FileEndAckPayload) -> bytes:
    body = json.dumps({"idx": p.file_index, "ok": p.ok, "reason": p.reason}).encode()
    return _pack_frame(MsgType.FILE_END_ACK, body)


def encode_session_end() -> bytes:
    return _pack_frame(MsgType.SESSION_END, b"")


def encode_error(p: ErrorPayload) -> bytes:
    body = json.dumps({"code": p.code, "msg": p.message}).encode()
    return _pack_frame(MsgType.ERROR, body)


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------

def recv_exact(sock, n: int) -> bytes:
    """Blocking read of exactly n bytes from socket. Raises EOFError on close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock) -> tuple[MsgType, bytes]:
    """Read one complete frame from socket. Returns (type, payload_bytes)."""
    raw_hdr = recv_exact(sock, HEADER_SIZE)
    magic, msg_type_byte, payload_len = struct.unpack(HEADER_FMT, raw_hdr)
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    msg_type = MsgType(msg_type_byte)
    payload = recv_exact(sock, payload_len) if payload_len else b""
    return msg_type, payload


def decode_hello(payload: bytes) -> HelloPayload:
    d = json.loads(payload)
    return HelloPayload(sender_id=d["id"], sender_name=d["name"], file_count=d["files"])


def decode_hello_ack(payload: bytes) -> HelloAckPayload:
    d = json.loads(payload)
    return HelloAckPayload(accepted=d["ok"], reason=d.get("reason", ""))


def decode_file_meta(payload: bytes) -> FileMetaPayload:
    d = json.loads(payload)
    return FileMetaPayload(
        file_index=d["idx"], rel_path=d["path"],
        size=d["size"], total_chunks=d["chunks"], mtime=d["mtime"],
    )


def decode_chunk(payload: bytes) -> ChunkPayload:
    chunk_index, chunk_hash, data_len = struct.unpack_from(CHUNK_HEADER_FMT, payload)
    data = payload[CHUNK_HEADER_SIZE: CHUNK_HEADER_SIZE + data_len]
    return ChunkPayload(chunk_index=chunk_index, chunk_hash=chunk_hash, data=data)


def decode_chunk_ack(payload: bytes) -> ChunkAckPayload:
    d = json.loads(payload)
    return ChunkAckPayload(chunk_index=d["idx"], ok=d["ok"], reason=d.get("reason", ""))


def decode_file_end(payload: bytes) -> FileEndPayload:
    file_index, file_hash = struct.unpack("!I32s", payload)
    return FileEndPayload(file_index=file_index, file_hash=file_hash)


def decode_file_end_ack(payload: bytes) -> FileEndAckPayload:
    d = json.loads(payload)
    return FileEndAckPayload(file_index=d["idx"], ok=d["ok"], reason=d.get("reason", ""))


def decode_error(payload: bytes) -> ErrorPayload:
    d = json.loads(payload)
    return ErrorPayload(code=d["code"], message=d["msg"])
