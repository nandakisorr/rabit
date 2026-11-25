"""Peer-to-peer LAN networking for Rabit."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
DISCOVERY_GROUP = "239.255.77.77"
DISCOVERY_PORT = 47655
MAX_FRAME_SIZE = 128 * 1024
FILE_CHUNK_SIZE = 48 * 1024
MAX_FILE_SIZE = 100 * 1024 * 1024
_AAD = b"rabit/1"


def app_data_dir() -> Path:
    root = os.environ.get("APPDATA")
    path = Path(root) / "Rabit" if root else Path.home() / ".rabit"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_peer_id() -> str:
    identity_path = app_data_dir() / "identity.json"
    if identity_path.exists():
        try:
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            peer_id = str(uuid.UUID(identity["peer_id"]))
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Unable to read Rabit identity at {identity_path}: {error}") from error
        return peer_id

    peer_id = str(uuid.uuid4())
    temporary_path = identity_path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps({"peer_id": peer_id}), encoding="utf-8")
    os.replace(temporary_path, identity_path)
    return peer_id


def derive_room_key(passphrase: str, room_name: str) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Use a room passphrase of at least 12 characters.")
    if not room_name.strip():
        raise ValueError("Room name cannot be empty.")
    salt = hashlib.sha256(("rabit-room:" + room_name.strip().casefold()).encode("utf-8")).digest()[:16]
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))


def _seal(key: bytes, payload: dict) -> bytes:
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
    envelope = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    frame = json.dumps(envelope, separators=(",", ":")).encode("ascii") + b"\n"
    if len(frame) > MAX_FRAME_SIZE:
        raise ValueError("Encrypted message is too large.")
    return frame


def _open(key: bytes, frame: bytes) -> dict:
    if len(frame) > MAX_FRAME_SIZE or not frame.endswith(b"\n"):
        raise ValueError("Invalid or oversized network frame.")
    try:
        envelope = json.loads(frame.decode("ascii"))
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(nonce) != 12:
            raise ValueError("Invalid encrypted message nonce.")
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _AAD)
        payload = json.loads(plaintext.decode("utf-8"))
    except InvalidTag as error:
        raise ValueError("Message authentication failed; check the room passphrase.") from error
    except (UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid encrypted network message.") from error
    if not isinstance(payload, dict):
        raise ValueError("Invalid encrypted message payload.")
    return payload


def _clean_filename(value: str) -> str:
    name = value.replace("\\", "/").split("/")[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return name[:180] or "received-file"


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    index = 1
    while True:
        candidate = directory / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
        index += 1


@dataclass
class PeerConnection:
    peer_id: str
    name: str
    sock: socket.socket
    stream: BinaryIO
    send_lock: threading.Lock


class NetworkClient:
    def __init__(self, peer_id: str, display_name: str, room_name: str, key: bytes):
        self.peer_id = peer_id
        self.display_name = display_name.strip()[:32]
        self.room_name = room_name.strip()
        self.room_id = hashlib.sha256(self.room_name.casefold().encode("utf-8")).hexdigest()[:16]
        self.key = key
        self.events: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: dict[str, PeerConnection] = {}
        self._connecting: set[str] = set()
        self._last_attempt: dict[str, float] = {}
        self._reported_failures: set[str] = set()
        self._server: socket.socket | None = None
        self._discovery: socket.socket | None = None
        self._announcer: socket.socket | None = None
        self._port = 0
        self._downloads = app_data_dir() / "received_files"
        self._downloads.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server = server
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", 0))
            server.listen()
            server.settimeout(1)
            self._port = server.getsockname()[1]

            discovery = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._discovery = discovery
            discovery.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            discovery.bind(("", DISCOVERY_PORT))
            membership = socket.inet_aton(DISCOVERY_GROUP) + socket.inet_aton("0.0.0.0")
            discovery.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            discovery.settimeout(1)

            announcer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._announcer = announcer
            announcer.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            announcer.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except OSError:
            for sock in (self._server, self._discovery, self._announcer):
                if sock is not None:
                    sock.close()
            self._server = None
            self._discovery = None
            self._announcer = None
            raise

        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._discover_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._server, self._discovery, self._announcer):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        with self._lock:
            connections = list(self._connections.values())
        for connection in connections:
            self._drop_connection(connection)

    def connected_peers(self) -> list[tuple[str, str]]:
        with self._lock:
            return [(peer_id, connection.name) for peer_id, connection in self._connections.items()]

    def send_chat(self, scope: str, target: str | None, text: str) -> int:
        text = text.strip()
        if not text or len(text) > 2000:
            raise ValueError("Messages must contain 1 to 2000 characters.")
        event = {"kind": "chat", "scope": scope, "target": target, "text": text}
        connections = self._target_connections(scope, target)
        return len(self._send_to_all(connections, event))

    def send_file(self, path: str, scope: str, target: str | None) -> None:
        connections = self._target_connections(scope, target)
        if not connections:
            raise RuntimeError("No connected recipients for this conversation.")
        threading.Thread(
            target=self._send_file_worker,
            args=(Path(path), scope, target, connections),
            daemon=True,
        ).start()

    def _target_connections(self, scope: str, target: str | None) -> list[PeerConnection]:
        with self._lock:
            if scope == "group":
                return list(self._connections.values())
            if scope == "direct" and target in self._connections:
                return [self._connections[target]]
        if scope == "direct":
            raise RuntimeError("That contact is offline.")
        if scope != "group":
            raise ValueError("Unknown conversation type.")
        return []

    def _send(self, connection: PeerConnection, event: dict) -> None:
        with connection.send_lock:
            connection.sock.sendall(_seal(self.key, event))

    def _send_file_worker(
        self, path: Path, scope: str, target: str | None, connections: list[PeerConnection]
    ) -> None:
        transfer_id = secrets.token_hex(16)
        active: list[PeerConnection] = []
        try:
            size = path.stat().st_size
            if size > MAX_FILE_SIZE:
                raise ValueError("Files are limited to 100 MB in this version.")
            if not path.is_file():
                raise ValueError("The selected path is not a file.")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(FILE_CHUNK_SIZE), b""):
                    digest.update(block)
            expected_hash = digest.hexdigest()
            start = {
                "kind": "file_start",
                "scope": scope,
                "target": target,
                "transfer_id": transfer_id,
                "name": _clean_filename(path.name),
                "size": size,
                "sha256": expected_hash,
            }
            active = self._send_to_all(connections, start)
            if not active:
                raise RuntimeError("No recipients remained connected.")

            sent_hash = hashlib.sha256()
            sent_size = 0
            with path.open("rb") as source:
                while True:
                    block = source.read(FILE_CHUNK_SIZE)
                    if not block:
                        break
                    sent_size += len(block)
                    if sent_size > MAX_FILE_SIZE:
                        raise RuntimeError("The source file grew beyond the 100 MB transfer limit.")
                    sent_hash.update(block)
                    chunk = {
                        "kind": "file_chunk",
                        "transfer_id": transfer_id,
                        "data": base64.b64encode(block).decode("ascii"),
                    }
                    active = self._send_to_all(active, chunk)
                    if not active:
                        raise RuntimeError("All recipients disconnected during file transfer.")
            if sent_size != size or sent_hash.hexdigest() != expected_hash:
                raise RuntimeError("The source file changed during transfer; recipients will discard it.")
            self._send_to_all(active, {"kind": "file_end", "transfer_id": transfer_id})
            self.events.put({"type": "file_sent", "name": path.name, "scope": scope, "target": target})
        except (OSError, ValueError, RuntimeError) as error:
            if active:
                self._send_to_all(active, {"kind": "file_abort", "transfer_id": transfer_id})
            self.events.put({"type": "error", "text": f"File transfer failed: {error}"})

    def _send_to_all(self, connections: list[PeerConnection], event: dict) -> list[PeerConnection]:
        active = []
        for connection in connections:
            try:
                self._send(connection, event)
                active.append(connection)
            except OSError:
                self._drop_connection(connection)
        return active

    def _announce_loop(self) -> None:
        announcement = json.dumps(
            {
                "version": VERSION,
                "peer_id": self.peer_id,
                "name": self.display_name,
                "port": self._port,
                "room_id": self.room_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        while not self._stop.is_set():
            try:
                if self._announcer is not None:
                    self._announcer.sendto(announcement, (DISCOVERY_GROUP, DISCOVERY_PORT))
            except OSError as error:
                if not self._stop.is_set():
                    self.events.put({"type": "error", "text": f"LAN discovery failed: {error}"})
                    return
            self._stop.wait(2)

    def _discover_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._discovery is None:
                    return
                raw, address = self._discovery.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.events.put({"type": "error", "text": "LAN discovery socket stopped unexpectedly."})
                return
            try:
                announcement = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(announcement, dict):
                continue
            peer_id = announcement.get("peer_id")
            name = announcement.get("name")
            port = announcement.get("port")
            if (
                announcement.get("version") != VERSION
                or announcement.get("room_id") != self.room_id
                or not isinstance(peer_id, str)
                or not isinstance(name, str)
                or not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65535
                or peer_id == self.peer_id
            ):
                continue
            try:
                remote_id = str(uuid.UUID(peer_id))
                remote_address = ipaddress.ip_address(address[0])
                if not (
                    remote_address.is_private
                    or remote_address.is_loopback
                    or remote_address.is_link_local
                ):
                    continue
            except ValueError:
                continue
            self._maybe_connect(remote_id, name.strip()[:32], address[0], port)

    def _maybe_connect(self, peer_id: str, name: str, address: str, port: int) -> None:
        if self.peer_id > peer_id:
            return
        now = time.monotonic()
        with self._lock:
            if peer_id in self._connections or peer_id in self._connecting:
                return
            if now - self._last_attempt.get(peer_id, 0) < 12:
                return
            self._last_attempt[peer_id] = now
            self._connecting.add(peer_id)
        threading.Thread(
            target=self._connect_worker,
            args=(peer_id, name, address, port),
            daemon=True,
        ).start()

    def _connect_worker(self, peer_id: str, name: str, address: str, port: int) -> None:
        try:
            sock = socket.create_connection((address, port), timeout=5)
            self._handshake(sock, peer_id)
            with self._lock:
                self._reported_failures.discard(peer_id)
        except (OSError, ValueError, KeyError, TypeError) as error:
            with self._lock:
                report_failure = peer_id not in self._reported_failures
                self._reported_failures.add(peer_id)
            if report_failure and not self._stop.is_set():
                self.events.put({
                    "type": "error",
                    "text": f"Could not connect to {name}. Check the room passphrase and firewall. ({error})",
                })
        finally:
            with self._lock:
                self._connecting.discard(peer_id)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._server is None:
                    return
                sock, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.events.put({"type": "error", "text": "Chat listener stopped unexpectedly."})
                return
            threading.Thread(target=self._accepted_handshake, args=(sock,), daemon=True).start()

    def _accepted_handshake(self, sock: socket.socket) -> None:
        try:
            self._handshake(sock)
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def _handshake(self, sock: socket.socket, expected_peer_id: str | None = None) -> None:
        stream: BinaryIO | None = None
        try:
            sock.settimeout(8)
            stream = sock.makefile("rb")
            sock.sendall(_seal(self.key, {
                "kind": "hello",
                "peer_id": self.peer_id,
                "name": self.display_name,
                "version": VERSION,
            }))
            remote = _open(self.key, self._read_frame(stream))
            if remote.get("kind") != "hello" or remote.get("version") != VERSION:
                raise ValueError("Unsupported peer protocol.")
            peer_id = str(uuid.UUID(remote["peer_id"]))
            name = str(remote.get("name", "")).strip()[:32]
            if peer_id == self.peer_id or not name:
                raise ValueError("Invalid peer identity.")
            if expected_peer_id is not None and peer_id != expected_peer_id:
                raise ValueError("Peer identity did not match its LAN announcement.")
            sock.settimeout(None)
            connection = PeerConnection(peer_id, name, sock, stream, threading.Lock())
            with self._lock:
                if peer_id in self._connections:
                    stream.close()
                    sock.close()
                    return
                self._connections[peer_id] = connection
            self.events.put({"type": "peer_connected", "peer_id": peer_id, "name": name})
            threading.Thread(target=self._read_loop, args=(connection,), daemon=True).start()
            stream = None
            sock = None
        finally:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def _read_frame(stream: BinaryIO) -> bytes:
        frame = stream.readline(MAX_FRAME_SIZE + 1)
        if not frame or len(frame) > MAX_FRAME_SIZE or not frame.endswith(b"\n"):
            raise ValueError("Invalid or oversized network frame.")
        return frame

    def _read_loop(self, connection: PeerConnection) -> None:
        transfers: dict[str, dict] = {}
        try:
            while not self._stop.is_set():
                packet = _open(self.key, self._read_frame(connection.stream))
                self._handle_packet(connection, packet, transfers)
        except (OSError, ValueError):
            pass
        finally:
            for transfer in transfers.values():
                try:
                    transfer["file"].close()
                    Path(transfer["part_path"]).unlink(missing_ok=True)
                except OSError:
                    pass
            self._drop_connection(connection)

    def _handle_packet(self, connection: PeerConnection, packet: dict, transfers: dict[str, dict]) -> None:
        kind = packet.get("kind")
        if kind == "chat":
            scope = packet.get("scope")
            target = packet.get("target")
            text = packet.get("text")
            if not isinstance(text, str) or not text.strip() or len(text) > 2000:
                return
            if scope == "direct" and target != self.peer_id:
                return
            if scope not in ("group", "direct"):
                return
            self.events.put({
                "type": "message",
                "scope": scope,
                "peer_id": connection.peer_id,
                "name": connection.name,
                "text": text,
            })
            return
        if kind in ("file_start", "file_chunk", "file_end"):
            self._handle_file_packet(connection, packet, transfers)
        elif kind == "file_abort":
            self._handle_file_packet(connection, packet, transfers)

    def _handle_file_packet(self, connection: PeerConnection, packet: dict, transfers: dict[str, dict]) -> None:
        kind = packet["kind"]
        transfer_id = packet.get("transfer_id")
        if not isinstance(transfer_id, str) or not re.fullmatch(r"[a-f0-9]{32}", transfer_id):
            raise ValueError("Invalid file transfer ID.")

        if kind == "file_start":
            scope = packet.get("scope")
            target = packet.get("target")
            name = packet.get("name")
            size = packet.get("size")
            checksum = packet.get("sha256")
            if scope == "direct" and target != self.peer_id:
                return
            if scope not in ("group", "direct") or not isinstance(name, str):
                raise ValueError("Invalid file transfer metadata.")
            if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_SIZE:
                raise ValueError("File exceeds the 100 MB limit.")
            if not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum):
                raise ValueError("Invalid file checksum.")
            if transfer_id in transfers:
                raise ValueError("Duplicate file transfer.")
            temporary = tempfile.NamedTemporaryFile(
                mode="wb", prefix=".rabit-", suffix=".part", dir=self._downloads, delete=False
            )
            transfers[transfer_id] = {
                "file": temporary,
                "part_path": temporary.name,
                "name": _clean_filename(name),
                "scope": scope,
                "size": size,
                "written": 0,
                "sha256": checksum,
                "hasher": hashlib.sha256(),
            }
            return

        transfer = transfers.get(transfer_id)
        if transfer is None:
            raise ValueError("File data arrived before its transfer started.")
        if kind == "file_abort":
            transfer["file"].close()
            Path(transfer["part_path"]).unlink(missing_ok=True)
            del transfers[transfer_id]
            return
        if kind == "file_chunk":
            data = packet.get("data")
            if not isinstance(data, str):
                raise ValueError("Invalid file chunk.")
            try:
                block = base64.b64decode(data, validate=True)
            except ValueError as error:
                raise ValueError("Invalid file chunk encoding.") from error
            if len(block) > FILE_CHUNK_SIZE or transfer["written"] + len(block) > transfer["size"]:
                raise ValueError("Invalid file chunk size.")
            transfer["file"].write(block)
            transfer["hasher"].update(block)
            transfer["written"] += len(block)
            return

        transfer["file"].close()
        del transfers[transfer_id]
        part_path = Path(transfer["part_path"])
        if (
            transfer["written"] != transfer["size"]
            or transfer["hasher"].hexdigest() != transfer["sha256"]
        ):
            part_path.unlink(missing_ok=True)
            raise ValueError("File integrity check failed; the partial file was discarded.")
        destination = _unique_path(self._downloads, transfer["name"])
        os.replace(part_path, destination)
        self.events.put({
            "type": "file_received",
            "peer_id": connection.peer_id,
            "name": transfer["name"],
            "path": str(destination),
            "scope": transfer["scope"],
        })

    def _drop_connection(self, connection: PeerConnection) -> None:
        removed = False
        with self._lock:
            if self._connections.get(connection.peer_id) is connection:
                del self._connections[connection.peer_id]
                removed = True
        try:
            connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            connection.stream.close()
        except OSError:
            pass
        try:
            connection.sock.close()
        except OSError:
            pass
        if removed:
            self.events.put({
                "type": "peer_disconnected",
                "peer_id": connection.peer_id,
                "name": connection.name,
            })
