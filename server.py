"""Local HTTPS server that observes real ClientHello bytes before TLS wrapping."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_parser import ClientHelloIncomplete, ClientHelloParseError, extract_client_hello, parse_client_hello


BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"


def ensure_local_certificate(certificate_directory: Path = CERT_DIR) -> tuple[Path, Path]:
    """Create a localhost-only self-signed certificate when one is absent."""
    certificate_directory.mkdir(exist_ok=True)
    certificate_path = certificate_directory / "localhost-cert.pem"
    key_path = certificate_directory / "localhost-key.pem"
    if certificate_path.exists() and key_path.exists():
        return certificate_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    return certificate_path, key_path


class TLSCaptureServer:
    """Single-process TLS endpoint; each accepted socket yields a distinct record."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8443, log: Callable[[str], None] | None = None, data_dir: Path = BASE_DIR):
        self.host, self.port = host, port
        self.log = log or (lambda message: None)
        self.certificate_directory = data_dir / "certs"
        self.records: list[dict] = []
        self._records_lock = threading.Lock()
        self._record_event = threading.Condition(self._records_lock)
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._context: ssl.SSLContext | None = None

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"

    def start(self) -> None:
        if self._running.is_set():
            return
        certificate, key = ensure_local_certificate(self.certificate_directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self._context = context
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(20)
        self._socket.settimeout(0.5)
        self._running.set()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="tls-capture-server")
        self._thread.start()
        self.log(f"TLS capture server listening on {self.url}")

    def stop(self) -> None:
        self._running.clear()
        if self._socket:
            self._socket.close()
        if self._thread:
            self._thread.join(timeout=2)

    def clear(self) -> None:
        with self._records_lock:
            self.records.clear()

    def snapshot(self) -> list[dict]:
        with self._records_lock:
            return json.loads(json.dumps(self.records))

    def wait_for_label(self, client: str, run: int, timeout: float = 12) -> bool:
        """Wait until the post-handshake HTTP request has labelled this capture."""
        deadline = time.monotonic() + timeout
        with self._record_event:
            while time.monotonic() < deadline:
                if any(item.get("client") == client and item.get("run") == run for item in self.records):
                    return True
                self._record_event.wait(max(0.05, deadline - time.monotonic()))
        return False

    def _accept_loop(self) -> None:
        assert self._socket is not None
        while self._running.is_set():
            try:
                connection, address = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_connection, args=(connection, address), daemon=True).start()

    def _peek_client_hello(self, connection: socket.socket) -> bytes:
        connection.settimeout(6)
        while True:
            # MSG_PEEK copies bytes without consuming them, allowing SSLContext to perform the real handshake next.
            peeked = connection.recv(65535, socket.MSG_PEEK)
            if not peeked:
                raise ConnectionError("client closed before ClientHello")
            try:
                return extract_client_hello(peeked)
            except ClientHelloIncomplete:
                time.sleep(0.01)

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        record: dict | None = None
        try:
            handshake = self._peek_client_hello(connection)
            parsed = parse_client_hello(handshake)
            record = {
                "id": uuid.uuid4().hex,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "peer": f"{address[0]}:{address[1]}",
                "client": None,
                "run": None,
                "status": "clienthello_captured",
                **parsed,
            }
            with self._record_event:
                self.records.append(record)
                self._record_event.notify_all()

            assert self._context is not None
            with self._context.wrap_socket(connection, server_side=True) as tls_connection:
                request = tls_connection.recv(16384).decode("iso-8859-1", errors="replace")
                first_line = request.split("\r\n", 1)[0]
                path = first_line.split(" ")[1] if len(first_line.split(" ")) >= 2 else "/"
                query = parse_qs(urlparse(path).query)
                record["client"] = query.get("client", [None])[0]
                run_value = query.get("run", [None])[0]
                record["run"] = int(run_value) if run_value and run_value.isdigit() else None
                record["status"] = "completed"
                response_body = b'{"ok": true}'
                tls_connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(response_body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + response_body
                )
            with self._record_event:
                self._record_event.notify_all()
            self.log(f"Captured ClientHello {record['id'][:8]} for {record['client'] or 'unlabelled'} run {record['run']}")
        except (ClientHelloParseError, ssl.SSLError, OSError, ValueError) as error:
            self.log(f"TLS capture error from {address[0]}:{address[1]}: {error}")
            if record:
                record["status"] = "error"
                record["error"] = str(error)
        finally:
            try:
                connection.close()
            except OSError:
                pass

