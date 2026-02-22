# LDT — Local Data Transfer

> Serverless P2P file/folder transfer for local networks.  
> Auto-discovery · zstd streaming · BLAKE3 integrity · No cloud, no server.

---

## Features

| Feature | Details |
|---|---|
| **Discovery** | UDP multicast `239.255.42.42:9999` — peers find each other automatically |
| **Transfer** | Direct TCP streaming between peers |
| **Compression** | zstd per chunk (level 1–22, default 3) |
| **Integrity** | BLAKE3 hash per chunk + whole-file hash — auto-retry on mismatch |
| **Progress** | Rich live progress bars with speed & ETA |
| **Multi-file** | Send individual files or entire directory trees |

---

## Protocol (LDTv1)

```
[ magic 4B ][ type 1B ][ payload_len 4B ][ payload NB ]
```

Magic = `LDT\x01` · all integers big-endian.

CHUNK payload:
```
[ chunk_index 4B ][ BLAKE3 hash 32B ][ data_len 4B ][ zstd-compressed data ]
```

See [`ldt/protocol.py`](ldt/protocol.py) for full spec.

---

## Install

```bash
pip install -r requirements.txt
```

## Usage

### Start receiver (Terminal 1)

```bash
python -m ldt receive --dir ./downloads
```

Options: `--port 9998`  `--quiet`

---

### List peers on network (Terminal 2)

```bash
python -m ldt peers
```

```
NAME                     IP                 PORT
--------------------------------------------------
laptop-home              192.168.1.42       9998
desktop-office           192.168.1.10       9998
```

---

### Send files (Terminal 2)

```bash
# Single file
python -m ldt send ./video.mp4 --to laptop-home

# Multiple files
python -m ldt send file1.txt file2.pdf --to 192.168.1.42

# Entire folder
python -m ldt send ./project_folder --to laptop-home

# Max compression
python -m ldt send ./archive.tar --to laptop-home --level 19
```

---

## Architecture

```
ldt/
├── __main__.py    CLI — send / receive / peers
├── protocol.py   LDTv1 wire format, frame encode/decode
├── compress.py   zstd wrapper (shared compressor context)
├── integrity.py  BLAKE3 hash helper
├── discovery.py  UDP multicast daemon
├── session.py    TCP send/receive session
├── transfer.py   File walker + chunk iterator
└── progress.py   Rich progress bars
```

## Transfer Flow

```
Sender                         Receiver
──────                         ────────
HELLO ─────────────────────→
                     ←──── HELLO_ACK

FILE_META ─────────────────→   (mkdir, prepare)
CHUNK 0 ──────────────────→
                     ←──── CHUNK_ACK ok
CHUNK 1 ──────────────────→
                     ←──── CHUNK_ACK NACK (hash bad)
CHUNK 1 (retry) ──────────→   (sender retries up to 3×)
                     ←──── CHUNK_ACK ok
...
FILE_END (file hash) ──────→
                     ←──── FILE_END_ACK ok

SESSION_END ───────────────→
```
