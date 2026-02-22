"""
Compression helpers — zstandard (zstd).

compress(data, level) → bytes   (compressed)
decompress(data)      → bytes   (raw)

A module-level compressor/decompressor is reused across calls for
efficiency (avoids re-allocating the dictionary on every chunk).
"""

from __future__ import annotations

import zstandard as zstd

_DEFAULT_LEVEL: int = 3          # good balance speed vs ratio
_MAX_WINDOW_LOG: int = 27        # 128 MiB window (safe for large files)

# Shared context — thread-safe for compression; decompressor is also thread-safe.
_compressor: zstd.ZstdCompressor | None = None
_decompressor: zstd.ZstdDecompressor = zstd.ZstdDecompressor()


def _get_compressor(level: int) -> zstd.ZstdCompressor:
    global _compressor, _DEFAULT_LEVEL
    if _compressor is None or level != _DEFAULT_LEVEL:
        _DEFAULT_LEVEL = level
        _compressor = zstd.ZstdCompressor(level=level)
    return _compressor


def compress(data: bytes, level: int = _DEFAULT_LEVEL) -> bytes:
    """Return zstd-compressed bytes of *data* at the given compression *level*."""
    return _get_compressor(level).compress(data)


def decompress(data: bytes) -> bytes:
    """Decompress zstd-compressed *data* and return raw bytes."""
    return _decompressor.decompress(data)
