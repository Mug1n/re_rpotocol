#!/usr/bin/env python3
"""Loopback-only deterministic HTTP service for acceptance capture."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys
import tempfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DOWNLOAD_BODY = (
    b"re_rpotocol acceptance payload v1\n"
    b"This plaintext is deterministic and safe for local packet capture.\n"
)
PERIODIC_BODY = b"re_rpotocol periodic response v1\n"
CHUNKED_BODY = b"chunked acceptance payload spans several HTTP chunks\n"
MAX_UPLOAD_BYTES = 8 * 1024 * 1024


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def service_manifest(host: str, port: int) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "base_url": f"http://{host}:{port}",
        "endpoints": {
            "download": {"path": "/download", "sha256": sha256_bytes(DOWNLOAD_BODY), "length": len(DOWNLOAD_BODY)},
            "periodic": {"path": "/periodic", "sha256": sha256_bytes(PERIODIC_BODY), "length": len(PERIODIC_BODY)},
            "chunked": {"path": "/chunked", "sha256": sha256_bytes(CHUNKED_BODY), "length": len(CHUNKED_BODY)},
            "gzip": {"path": "/gzip", "decoded_sha256": sha256_bytes(DOWNLOAD_BODY), "decoded_length": len(DOWNLOAD_BODY)},
            "zlib": {"path": "/zlib", "decoded_sha256": sha256_bytes(DOWNLOAD_BODY), "decoded_length": len(DOWNLOAD_BODY)},
            "upload": {"path": "/upload", "method": "POST"},
        },
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        Path(temporary).replace(path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def make_handler(*, record_dir: Path | None, max_upload_bytes: int):
    class AcceptanceHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "re_rpotocol-acceptance/0.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _fixed(self, body: bytes, *, content_type: str = "application/octet-stream", content_encoding: str | None = None) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if content_encoding:
                self.send_header("Content-Encoding", content_encoding)
            self.send_header("X-Content-SHA256", sha256_bytes(body))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/health":
                self._fixed(b"ok\n", content_type="text/plain")
            elif path == "/download":
                self._fixed(DOWNLOAD_BODY, content_type="text/plain; charset=utf-8")
            elif path == "/periodic":
                self._fixed(PERIODIC_BODY, content_type="text/plain; charset=utf-8")
            elif path == "/gzip":
                self._fixed(gzip.compress(DOWNLOAD_BODY, mtime=0), content_encoding="gzip")
            elif path == "/zlib":
                self._fixed(zlib.compress(DOWNLOAD_BODY), content_encoding="deflate")
            elif path == "/chunked":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("X-Decoded-SHA256", sha256_bytes(CHUNKED_BODY))
                self.end_headers()
                pieces = (CHUNKED_BODY[:9], CHUNKED_BODY[9:27], CHUNKED_BODY[27:])
                for piece in pieces:
                    self.wfile.write(f"{len(piece):X}\r\n".encode("ascii") + piece + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_error(404, "unknown acceptance endpoint")

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/upload":
                self.send_error(404, "unknown acceptance endpoint")
                return
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length or "")
            except ValueError:
                self.send_error(411, "valid Content-Length required")
                return
            if length < 0 or length > max_upload_bytes:
                self.send_error(413, "upload exceeds configured limit")
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400, "truncated upload")
                return
            digest = sha256_bytes(body)
            if record_dir is not None:
                _atomic_write(record_dir / f"upload-{digest}.bin", body)
            response = json.dumps({"length": length, "sha256": digest}, separators=(",", ":")).encode("utf-8") + b"\n"
            self._fixed(response, content_type="application/json")

    return AcceptanceHandler


def create_server(host: str, port: int, *, record_dir: Path | None = None, max_upload_bytes: int = MAX_UPLOAD_BYTES) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("acceptance service must bind to a loopback host")
    if not (0 <= port <= 65535) or max_upload_bytes <= 0:
        raise ValueError("invalid port or upload limit")
    return ThreadingHTTPServer((host, port), make_handler(record_dir=record_dir, max_upload_bytes=max_upload_bytes))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the deterministic loopback HTTP acceptance service.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--record-dir", type=Path)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--max-upload-bytes", type=int, default=MAX_UPLOAD_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = create_server(args.host, args.port, record_dir=args.record_dir, max_upload_bytes=args.max_upload_bytes)
    except (OSError, ValueError) as exc:
        print(f"acceptance-http-server: {exc}", file=sys.stderr)
        return 2
    host, port = server.server_address[:2]
    manifest = service_manifest(str(host), int(port))
    if args.ready_file:
        _atomic_write(args.ready_file, (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(json.dumps(manifest, ensure_ascii=False), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
