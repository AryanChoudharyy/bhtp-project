#!/usr/bin/env python3
"""Serve files over the BHTP/1 framed binary protocol."""

import argparse
import math
import mimetypes
import socket
import socketserver
import struct
import sys
from pathlib import Path


MAGIC = b"BHTP"
VERSION = 1
REQUEST = 1
RESPONSE = 2
MAX_PAYLOAD = 16 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
FRAME = struct.Struct("!4sBBBBII")
NAMES = {
    1: "host", 2: "user-agent", 3: "accept", 4: "accept-encoding",
    5: "connection", 6: "content-type", 7: "content-length",
    8: "server", 9: "cache-control", 10: "accept-ranges",
}
IDS = {name: number for number, name in NAMES.items()}


class ProtocolError(Exception):
    """A complete frame contains invalid BHTP/1 data."""


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if not data:
                return None
            raise EOFError("truncated frame")
        data.extend(chunk)
    return bytes(data)


def discard_exact(sock, size):
    while size:
        chunk = sock.recv(min(size, 65536))
        if not chunk:
            raise EOFError("truncated unknown frame")
        size -= len(chunk)


def parse_headers(payload, offset, count):
    seen = set()
    for _ in range(count):
        if len(payload) - offset < 3:
            raise ProtocolError("short header entry")
        name_id, size = struct.unpack_from("!BH", payload, offset)
        offset += 3
        if size > 1024 or len(payload) - offset < size:
            raise ProtocolError("invalid header value length")
        raw = payload[offset:offset + size]
        offset += size
        if b"\r" in raw or b"\n" in raw or b"\x00" in raw:
            raise ProtocolError("invalid header value")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("header value is not UTF-8") from exc
        name = NAMES.get(name_id)
        if name is not None:
            if name in seen:
                raise ProtocolError("duplicate header")
            seen.add(name)
    return offset


def parse_request(payload):
    if len(payload) < 3:
        raise ProtocolError("short request")
    path_size = struct.unpack_from("!H", payload)[0]
    if not 1 <= path_size <= 4096 or len(payload) < 2 + path_size + 1:
        raise ProtocolError("invalid path length")
    try:
        path = payload[2:2 + path_size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("path is not UTF-8") from exc
    if not path.startswith("/") or any(ord(c) < 32 for c in path):
        raise ProtocolError("invalid path")
    if any(c in path for c in ("\\", "?", "#")):
        raise ProtocolError("invalid path")
    count_offset = 2 + path_size
    count = payload[count_offset]
    end = parse_headers(payload, count_offset + 1, count)
    if end != len(payload):
        raise ProtocolError("trailing request bytes")
    return path


def encode_headers(headers):
    if len(headers) > 255:
        raise ValueError("too many headers")
    out = bytearray((len(headers),))
    for name, value in headers:
        raw = value.encode("utf-8")
        if len(raw) > 1024:
            raise ValueError("header value too long")
        out.extend(struct.pack("!BH", IDS[name], len(raw)))
        out.extend(raw)
    return bytes(out)


def response_frame(request_id, status, body, content_type, keep_open=True):
    headers = [
        ("connection", "keep-alive" if keep_open else "close"),
        ("content-type", content_type),
        ("content-length", str(len(body))),
        ("server", "bserve/1"),
        ("cache-control", "no-store"),
        ("accept-ranges", "none"),
    ]
    metadata = struct.pack("!H", status) + encode_headers(headers)
    size = len(metadata) + len(body)
    if size > MAX_PAYLOAD:
        raise ValueError("response exceeds protocol limit")
    return FRAME.pack(MAGIC, VERSION, RESPONSE, 0, 0, request_id, size) + metadata + body


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(self.server.connection_timeout)
        while True:
            try:
                raw_header = read_exact(self.request, FRAME.size)
                if raw_header is None:
                    return
                magic, version, kind, flags, reserved, request_id, size = FRAME.unpack(raw_header)
                if (magic != MAGIC or version != VERSION or flags or reserved
                        or size > MAX_PAYLOAD):
                    self.send(request_id, 400, b"Malformed frame\n", keep_open=False)
                    return
                if kind not in (REQUEST, RESPONSE):
                    discard_exact(self.request, size)
                    continue
                payload = read_exact(self.request, size)
                if payload is None:
                    raise EOFError("truncated frame")
                if kind != REQUEST or request_id == 0:
                    self.send(request_id, 400, b"Malformed request\n")
                    continue
                try:
                    path = parse_request(payload)
                except ProtocolError:
                    self.send(request_id, 400, b"Malformed request\n")
                    continue
                self.serve_path(request_id, path)
            except (EOFError, OSError):
                return

    def send(self, request_id, status, body, content_type="text/plain; charset=utf-8", keep_open=True):
        self.request.sendall(response_frame(request_id, status, body, content_type, keep_open))

    def serve_path(self, request_id, path):
        root = self.server.root
        relative = path.lstrip("/")
        if not relative or path.endswith("/"):
            relative += "index.html"
        try:
            target = (root / relative).resolve()
        except (OSError, RuntimeError):
            self.send(request_id, 400, b"Invalid path\n")
            return
        if not target.is_relative_to(root):
            self.send(request_id, 400, b"Invalid path\n")
            return
        if not target.is_file():
            self.send(request_id, 404, b"Not found\n")
            return
        try:
            with target.open("rb") as file:
                body = file.read(MAX_PAYLOAD + 1)
        except OSError:
            self.send(request_id, 500, b"Read error\n")
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        try:
            self.send(request_id, 200, body, content_type)
        except ValueError:
            self.send(request_id, 500, b"File too large\n")


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    connection_timeout = DEFAULT_TIMEOUT


class IPv6Server(Server):
    address_family = socket.AF_INET6


def main(argv=None):
    parser = argparse.ArgumentParser(description="BHTP/1 static file server")
    parser.add_argument("root", type=Path, help="directory to serve")
    parser.add_argument("port", type=int, help="TCP port")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="idle connection timeout in seconds (default: 30)")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("root must be an existing directory")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be a positive finite number")
    try:
        server_type = IPv6Server if ":" in args.host else Server
        with server_type((args.host, args.port), Handler) as server:
            server.root = root
            server.connection_timeout = args.timeout
            print(f"Serving {root} on {args.host}:{args.port}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"bserve: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
