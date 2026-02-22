"""
LDT transfer session: sender and receiver sides.

SendSession
-----------
    Connects to a receiver, sends HELLO → FILE_META → CHUNKs → FILE_END
    for each file, then sends SESSION_END.
    Retries bad chunks up to MAX_CHUNK_RETRY times.

ReceiveServer
-------------
    Listens for incoming connections in a daemon thread.
    Spawns a ReceiveSession per connection.
    Reconstructs files under dest_dir, verifying per-chunk hashes
    and whole-file hash on FILE_END.
"""

from __future__ import annotations

import logging
import math
import os
import socket
import threading
from pathlib import Path

from . import compress, integrity
from .protocol import (
    MAX_CHUNK_BYTES,
    MAX_CHUNK_RETRY,
    MsgType,
    ChunkAckPayload,
    ChunkPayload,
    ErrorPayload,
    FileEndAckPayload,
    FileEndPayload,
    FileMetaPayload,
    HelloAckPayload,
    HelloPayload,
    decode_chunk_ack,
    decode_file_end_ack,
    decode_file_meta,
    decode_hello,
    decode_hello_ack,
    decode_error,
    encode_chunk,
    encode_chunk_ack,
    encode_error,
    encode_file_end,
    encode_file_end_ack,
    encode_file_meta,
    encode_hello,
    encode_hello_ack,
    encode_session_end,
    read_frame,
)
from .transfer import FileEntry, chunk_file, walk_targets
from .progress import ProgressTracker, NullProgress

log = logging.getLogger("ldt.session")


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_HASH_MISMATCH = 1
ERR_FILE_HASH_MISMATCH = 2
ERR_REJECTED = 3
ERR_INTERNAL = 99


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

class SendSession:
    """
    Send one or more files to a receiver over an established socket.
    The socket must be connected; caller is responsible for closing it.
    """

    def __init__(
        self,
        sock: socket.socket,
        entries: list[FileEntry],
        sender_id: str,
        sender_name: str,
        compress_level: int = 3,
        progress: ProgressTracker | NullProgress | None = None,
    ) -> None:
        self._sock = sock
        self._entries = entries
        self._sender_id = sender_id
        self._sender_name = sender_name
        self._compress_level = compress_level
        self._progress = progress or NullProgress()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the full transfer. Raises on fatal error."""
        self._handshake()
        for idx, entry in enumerate(self._entries):
            self._send_file(idx, entry)
        self._sock.sendall(encode_session_end())
        log.info("Session complete — %d file(s) sent", len(self._entries))

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _handshake(self) -> None:
        hello = HelloPayload(
            sender_id=self._sender_id,
            sender_name=self._sender_name,
            file_count=len(self._entries),
        )
        self._sock.sendall(encode_hello(hello))
        msg_type, payload = read_frame(self._sock)
        if msg_type != MsgType.HELLO_ACK:
            raise RuntimeError(f"Expected HELLO_ACK, got {msg_type}")
        ack = decode_hello_ack(payload)
        if not ack.accepted:
            raise RuntimeError(f"Connection rejected: {ack.reason}")
        log.debug("Handshake OK")

    def _send_file(self, idx: int, entry: FileEntry) -> None:
        log.info("Sending [%d/%d] %s (%d bytes)",
                 idx + 1, len(self._entries), entry.rel_path, entry.size)

        # FILE_META
        meta = FileMetaPayload(
            file_index=idx,
            rel_path=entry.rel_path,
            size=entry.size,
            total_chunks=entry.total_chunks,
            mtime=entry.mtime,
        )
        self._sock.sendall(encode_file_meta(meta))

        # Whole-file hasher
        file_hasher_chunks: list[bytes] = []

        with self._progress.file(entry.rel_path, entry.size) as fp:
            for chunk_idx, raw_chunk in enumerate(
                chunk_file(entry.abs_path, MAX_CHUNK_BYTES)
            ):
                file_hasher_chunks.append(raw_chunk)
                self._send_chunk(chunk_idx, raw_chunk)
                fp.advance(len(raw_chunk))

        # Whole-file hash
        all_raw = b"".join(file_hasher_chunks)
        file_hash = integrity.hash_bytes(all_raw)
        self._sock.sendall(encode_file_end(FileEndPayload(
            file_index=idx, file_hash=file_hash
        )))

        msg_type, payload = read_frame(self._sock)
        if msg_type != MsgType.FILE_END_ACK:
            raise RuntimeError(f"Expected FILE_END_ACK, got {msg_type}")
        ack = decode_file_end_ack(payload)
        if not ack.ok:
            raise RuntimeError(f"File rejected by receiver: {ack.reason}")
        log.debug("File %s accepted", entry.rel_path)

    def _send_chunk(self, chunk_idx: int, raw_chunk: bytes, attempt: int = 0) -> None:
        chunk_hash = integrity.hash_bytes(raw_chunk)
        compressed = compress.compress(raw_chunk, level=self._compress_level)

        chunk_payload = ChunkPayload(
            chunk_index=chunk_idx,
            chunk_hash=chunk_hash,
            data=compressed,
        )
        self._sock.sendall(encode_chunk(chunk_payload))

        msg_type, payload = read_frame(self._sock)
        if msg_type != MsgType.CHUNK_ACK:
            raise RuntimeError(f"Expected CHUNK_ACK, got {msg_type}")
        ack = decode_chunk_ack(payload)

        if ack.ok:
            return

        # NACK — retry
        if attempt < MAX_CHUNK_RETRY:
            log.warning("Chunk %d NACK, retry %d/%d: %s",
                        chunk_idx, attempt + 1, MAX_CHUNK_RETRY, ack.reason)
            self._send_chunk(chunk_idx, raw_chunk, attempt + 1)
        else:
            err = ErrorPayload(code=ERR_HASH_MISMATCH,
                               message=f"Chunk {chunk_idx} failed after {MAX_CHUNK_RETRY} retries")
            self._sock.sendall(encode_error(err))
            raise RuntimeError(err.message)


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------

class ReceiveServer:
    """
    TCP server that listens for incoming LDT connections on *port*.
    Each connection is handled in its own thread.
    """

    def __init__(self, dest_dir: str | Path, port: int = 9998) -> None:
        self._dest_dir = Path(dest_dir)
        self._port = port
        self._server_sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._dest_dir.mkdir(parents=True, exist_ok=True)
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("", self._port))
        self._server_sock.listen(8)
        self._server_sock.settimeout(1.0)
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="ldt-recv-server"
        )
        self._thread.start()
        log.info("Receiving on port %d → %s", self._port, self._dest_dir)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    def wait(self) -> None:
        """Block until Ctrl-C."""
        try:
            self._stop_event.wait()
        except KeyboardInterrupt:
            self.stop()

    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._server_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            log.info("Incoming connection from %s:%d", *addr)
            t = threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                daemon=True,
                name=f"ldt-recv-{addr[0]}",
            )
            t.start()

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        try:
            session = ReceiveSession(conn, self._dest_dir, addr[0])
            session.run()
        except EOFError:
            log.info("Connection from %s closed", addr[0])
        except Exception as exc:
            log.error("Error handling %s: %s", addr[0], exc, exc_info=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass


class ReceiveSession:
    """
    Handles the receiver side of one LDT connection.
    Runs synchronously in the calling thread.
    """

    def __init__(
        self,
        sock: socket.socket,
        dest_dir: Path,
        peer_ip: str,
    ) -> None:
        self._sock = sock
        self._dest_dir = dest_dir
        self._peer_ip = peer_ip

    def run(self) -> None:
        sender_name = self._handshake()
        log.info("Receiving from %s (%s)", sender_name, self._peer_ip)

        while True:
            msg_type, payload = read_frame(self._sock)

            if msg_type == MsgType.SESSION_END:
                log.info("Session END from %s", sender_name)
                break
            elif msg_type == MsgType.FILE_META:
                meta = decode_file_meta(payload)
                self._receive_file(meta, sender_name)
            elif msg_type == MsgType.ERROR:
                err = decode_error(payload)
                log.error("Received ERROR from sender: [%d] %s", err.code, err.message)
                break
            else:
                log.warning("Unexpected message type %s in session loop", msg_type)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _handshake(self) -> str:
        msg_type, payload = read_frame(self._sock)
        if msg_type != MsgType.HELLO:
            self._sock.sendall(encode_hello_ack(HelloAckPayload(
                accepted=False, reason="Expected HELLO"
            )))
            raise RuntimeError("Expected HELLO")
        hello = decode_hello(payload)
        self._sock.sendall(encode_hello_ack(HelloAckPayload(accepted=True)))
        return hello.sender_name

    def _receive_file(self, meta: FileMetaPayload, sender_name: str) -> None:
        # Resolve safe path (prevent directory traversal)
        rel = Path(meta.rel_path)
        if rel.is_absolute() or ".." in rel.parts:
            self._reject_file(meta.file_index, "Unsafe path")
            return

        dest = self._dest_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        log.info("Receiving file %s (%d bytes, %d chunks)",
                 meta.rel_path, meta.size, meta.total_chunks)

        raw_chunks: dict[int, bytes] = {}

        with self._progress_ctx(meta, sender_name) as fp:
            for _ in range(meta.total_chunks):
                msg_type, payload = self._expect(MsgType.CHUNK, MsgType.ERROR)
                if msg_type == MsgType.ERROR:
                    err = decode_error(payload)
                    log.error("Sender ERROR during file: %s", err.message)
                    return

                chunk = decode_chunk(payload)
                raw = self._verify_chunk(chunk)
                if raw is None:
                    return
                raw_chunks[chunk.chunk_index] = raw
                fp.advance(len(raw))

        # Write ordered chunks atomically
        with open(dest, "wb") as fh:
            for i in range(meta.total_chunks):
                fh.write(raw_chunks[i])

        # Restore mtime
        try:
            os.utime(dest, (meta.mtime, meta.mtime))
        except OSError:
            pass

        # Expect FILE_END and verify whole-file hash
        msg_type, payload = read_frame(self._sock)
        if msg_type != MsgType.FILE_END:
            self._reject_file(meta.file_index, f"Expected FILE_END, got {msg_type}")
            return

        file_end = decode_file_end(payload)
        all_raw = b"".join(raw_chunks[i] for i in range(meta.total_chunks))
        actual_hash = integrity.hash_bytes(all_raw)

        if actual_hash != file_end.file_hash:
            self._sock.sendall(encode_file_end_ack(FileEndAckPayload(
                file_index=meta.file_index, ok=False, reason="File hash mismatch"
            )))
            dest.unlink(missing_ok=True)
            log.error("File hash mismatch for %s — deleted", meta.rel_path)
            return

        self._sock.sendall(encode_file_end_ack(FileEndAckPayload(
            file_index=meta.file_index, ok=True
        )))
        log.info("File %s OK (%d bytes)", meta.rel_path, meta.size)

    def _verify_chunk(self, chunk: ChunkPayload) -> bytes | None:
        """Decompress and verify chunk hash. Sends ACK/NACK."""
        try:
            raw = compress.decompress(chunk.data)
        except Exception as exc:
            self._sock.sendall(encode_chunk_ack(ChunkAckPayload(
                chunk_index=chunk.chunk_index, ok=False,
                reason=f"Decompress error: {exc}"
            )))
            return None

        if not integrity.verify(raw, chunk.chunk_hash):
            self._sock.sendall(encode_chunk_ack(ChunkAckPayload(
                chunk_index=chunk.chunk_index, ok=False,
                reason="Hash mismatch"
            )))
            log.warning("Chunk %d hash mismatch", chunk.chunk_index)
            return None

        self._sock.sendall(encode_chunk_ack(ChunkAckPayload(
            chunk_index=chunk.chunk_index, ok=True
        )))
        return raw

    def _reject_file(self, file_index: int, reason: str) -> None:
        self._sock.sendall(encode_file_end_ack(FileEndAckPayload(
            file_index=file_index, ok=False, reason=reason
        )))
        log.error("Rejected file %d: %s", file_index, reason)

    def _expect(self, *expected: MsgType) -> tuple[MsgType, bytes]:
        msg_type, payload = read_frame(self._sock)
        if msg_type not in expected:
            raise RuntimeError(
                f"Expected {[t.name for t in expected]}, got {msg_type.name}"
            )
        return msg_type, payload

    @staticmethod
    def _progress_ctx(meta: FileMetaPayload, sender_name: str):
        """Inline no-op context so we don't depend on progress here."""
        class _Nop:
            def __enter__(self):
                class _F:
                    def advance(self, n): pass
                return _F()
            def __exit__(self, *a): pass
        return _Nop()
