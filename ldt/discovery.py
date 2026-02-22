"""
UDP multicast peer discovery for LDT.

- Sends ANNOUNCE every DISCOVERY_INTERVAL seconds
- Listens for ANNOUNCE / QUERY from other peers
- Responds to QUERY with own ANNOUNCE
- Broadcasts BYE on shutdown
- Maintains a TTL-based registry of seen peers
- Thread-safe; runs as a daemon background thread

Usage::

    disc = Discovery(tcp_port=9998)
    disc.start()

    peers = disc.get_peers()
    peer  = disc.find_peer("hostname-or-ip")

    disc.stop()
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .protocol import (
    DISCOVERY_PORT,
    MULTICAST_GROUP,
    DISCOVERY_INTERVAL,
    PEER_TTL,
)

log = logging.getLogger("ldt.discovery")

MCAST_TTL: int = 4          # hops; enough for most LANs
BUFFER_SIZE: int = 2048


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    id: str
    name: str
    host: str           # IP address
    port: int           # TCP listen port
    last_seen: float = field(default_factory=time.monotonic)

    def __str__(self) -> str:
        return f"{self.name} ({self.host}:{self.port})"


# ---------------------------------------------------------------------------
# Discovery daemon
# ---------------------------------------------------------------------------

class Discovery:
    """Multicast peer discovery daemon."""

    def __init__(self, tcp_port: int = 9998, node_name: str | None = None):
        self.tcp_port = tcp_port
        self.node_id = str(uuid.uuid4())
        self.node_name: str = node_name or socket.gethostname()
        self._peers: dict[str, PeerInfo] = {}          # id → PeerInfo
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the discovery daemon thread."""
        self._sock = self._make_socket()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ldt-discovery"
        )
        self._thread.start()
        log.debug("Discovery started (id=%s name=%s)", self.node_id, self.node_name)

    def stop(self) -> None:
        """Send BYE and stop the daemon."""
        self._stop_event.set()
        self._send_msg({"type": "BYE", "id": self.node_id})
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        log.debug("Discovery stopped")

    def get_peers(self) -> list[PeerInfo]:
        """Return snapshot of currently-known live peers (excludes self)."""
        now = time.monotonic()
        with self._lock:
            return [
                p for p in self._peers.values()
                if now - p.last_seen < PEER_TTL
            ]

    def find_peer(self, name_or_ip: str) -> Optional[PeerInfo]:
        """Find a peer by hostname or IP. Returns None if not found."""
        for p in self.get_peers():
            if p.name == name_or_ip or p.host == name_or_ip:
                return p
        return None

    def query(self) -> None:
        """Broadcast a QUERY so peers respond immediately."""
        self._send_msg({
            "type": "QUERY",
            "id": self.node_id,
            "name": self.node_name,
            "port": self.tcp_port,
            "v": 1,
        })

    # ------------------------------------------------------------------
    # Internal socket helpers
    # ------------------------------------------------------------------

    def _make_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Windows doesn't have SO_REUSEPORT
        sock.bind(("", DISCOVERY_PORT))
        # Join multicast group
        mreq = struct.pack("4sL",
                           socket.inet_aton(MULTICAST_GROUP),
                           socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Set outgoing TTL
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_TTL)
        sock.settimeout(1.0)
        return sock

    def _send_msg(self, msg: dict) -> None:
        try:
            data = json.dumps(msg).encode()
            if self._sock:
                self._sock.sendto(data, (MULTICAST_GROUP, DISCOVERY_PORT))
        except OSError as e:
            log.warning("Discovery send error: %s", e)

    def _announce(self) -> None:
        self._send_msg({
            "type": "ANNOUNCE",
            "id": self.node_id,
            "name": self.node_name,
            "port": self.tcp_port,
            "v": 1,
        })

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        last_announce = 0.0
        while not self._stop_event.is_set():
            now = time.monotonic()
            if now - last_announce >= DISCOVERY_INTERVAL:
                self._announce()
                last_announce = now

            # Receive datagrams (1 s timeout)
            try:
                assert self._sock is not None
                data, addr = self._sock.recvfrom(BUFFER_SIZE)
                self._handle(data, addr[0])
            except TimeoutError:
                pass
            except OSError:
                if not self._stop_event.is_set():
                    log.exception("Discovery recv error")

    def _handle(self, data: bytes, src_ip: str) -> None:
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return

        msg_type = msg.get("type")
        peer_id = msg.get("id", "")

        if peer_id == self.node_id:
            return  # ignore own messages

        if msg_type == "BYE":
            with self._lock:
                self._peers.pop(peer_id, None)
            log.debug("Peer left: %s", peer_id)
            return

        if msg_type in ("ANNOUNCE", "QUERY"):
            peer = PeerInfo(
                id=peer_id,
                name=msg.get("name", src_ip),
                host=src_ip,
                port=msg.get("port", 9998),
                last_seen=time.monotonic(),
            )
            with self._lock:
                self._peers[peer_id] = peer
            log.debug("Peer seen: %s", peer)

            if msg_type == "QUERY":
                # Reply with own presence
                self._announce()
