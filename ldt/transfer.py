"""
File/folder walker and chunked streaming reader.

walk_targets(paths) → Iterator[FileEntry]
    Recursively yields FileEntry for every file in *paths*.
    Directories are walked recursively; individual files are emitted as-is.

chunk_file(path, chunk_size) → Iterator[bytes]
    Memory-efficient generator that reads a file in raw chunks of *chunk_size*
    bytes. Uses a buffered read — no mmap needed; works on all platforms.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .protocol import MAX_CHUNK_BYTES


@dataclass
class FileEntry:
    abs_path: Path       # absolute path on disk
    rel_path: str        # relative path to be reconstructed on receiver
    size: int            # file size in bytes
    mtime: float         # modification time (unix timestamp)
    total_chunks: int    # number of chunks at max_chunk_bytes


def _entry(abs_path: Path, rel_path: str, chunk_size: int) -> FileEntry:
    st = abs_path.stat()
    size = st.st_size
    total_chunks = max(1, (size + chunk_size - 1) // chunk_size) if size > 0 else 1
    return FileEntry(
        abs_path=abs_path,
        rel_path=rel_path,
        size=size,
        mtime=st.st_mtime,
        total_chunks=total_chunks,
    )


def walk_targets(
    paths: list[str | Path],
    chunk_size: int = MAX_CHUNK_BYTES,
) -> Iterator[FileEntry]:
    """
    Yield a FileEntry for each file found under *paths*.

    * A plain file → single FileEntry with its basename as rel_path.
    * A directory  → all files inside, rel_path relative to parent of the dir.
    """
    for raw in paths:
        p = Path(raw).resolve()
        if p.is_file():
            yield _entry(p, p.name, chunk_size)
        elif p.is_dir():
            parent = p.parent
            for root, _dirs, files in os.walk(p):
                for fname in sorted(files):
                    abs_p = Path(root) / fname
                    rel = str(abs_p.relative_to(parent)).replace(os.sep, "/")
                    yield _entry(abs_p, rel, chunk_size)
        else:
            raise FileNotFoundError(f"Path not found: {p}")


def chunk_file(
    path: Path | str,
    chunk_size: int = MAX_CHUNK_BYTES,
) -> Iterator[bytes]:
    """
    Yield raw (uncompressed) chunks of *path* up to *chunk_size* bytes each.
    Empty files yield exactly one empty bytes object so the protocol always
    sends at least one CHUNK message.
    """
    path = Path(path)
    size = path.stat().st_size
    if size == 0:
        yield b""
        return

    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            yield block
