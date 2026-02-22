"""Benchmark E2E test for optimized ldt.py — pipelined version."""
import os, socket, tempfile, time, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import ldt as L
import threading

def run_test(size_mb: int, label: str) -> None:
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, f"bench_{size_mb}mb.bin")
    # Write size_mb of data (repeating pattern — at least somewhat compressible)
    chunk = bytes(range(256)) * 512  # 128 KB block
    with open(src, "wb") as f:
        written = 0
        while written < size_mb * 1024 * 1024:
            f.write(chunk)
            written += len(chunk)

    recv_dir = os.path.join(tmp, "received")
    os.makedirs(recv_dir)

    server = L._recv_server(pathlib.Path(recv_dir), 19995)
    stop = threading.Event()
    threading.Thread(target=L._recv_loop, args=(server, pathlib.Path(recv_dir), stop),
                     daemon=True).start()
    time.sleep(0.2)

    entries = L._entries([src])
    actual_size = sum(e.size for e in entries)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 19995))
    t0 = time.perf_counter()
    L._send_session(sock, entries, "bench", quiet=True)
    L._finish_session(sock)
    dt = time.perf_counter() - t0
    sock.close()
    time.sleep(0.3)
    stop.set()
    server.close()

    dst = pathlib.Path(recv_dir) / pathlib.Path(src).name
    assert dst.exists(), f"File missing: {dst}"
    assert dst.stat().st_size == actual_size, "Size mismatch!"

    speed = actual_size / dt / 1e6
    print(f"  {label:30s}  {actual_size/1e6:7.1f} MB  {dt:6.3f}s  {speed:8.1f} MB/s")

print(f"\n{'Test':<32}  {'Size':>7}  {'Time':>6}  {'Speed':>10}")
print("-" * 62)
run_test(10,  "10 MB  (1 chunk of 2 MiB x5)")
run_test(50,  "50 MB")
run_test(250, "250 MB")
print("\nAll benchmarks passed!")
