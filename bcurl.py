#!/usr/bin/env python3
"""Fetch one file over one BHTP/1 TCP connection."""

import argparse
import math
import socket
import struct
import sys
from urllib.parse import urlsplit


MAGIC = b"BHTP"
VERSION = 1
REQUEST = 1
RESPONSE = 2
MAX_PAYLOAD = 16 * 1024 * 1024
DEFAULT_PORT = 9000
DEFAULT_TIMEOUT = 30.0
FRAME = struct.Struct("!4sBBBBII")
NAMES = {
    1: "host", 2: "user-agent", 3: "accept", 4: "accept-encoding",
    5: "connection", 6: "content-type", 7: "content-length",
    8: "server", 9: "cache-control", 10: "accept-ranges",
}
IDS = {name: number for number, name in NAMES.items()}


class ProtocolError(Exception):
    """A response violates the protocol or ends early."""


def hexdump(label, data):
    print(f"{label}: {len(data)} bytes", file=sys.stderr)
    for offset in range(0, len(data), 16):
        row = data[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in row)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
        print(f"  {offset:04x}  {hex_part:<47}  |{ascii_part}|", file=sys.stderr)


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProtocolError("connection closed before the frame was complete")
        data.extend(chunk)
    return bytes(data)


def encode_headers(headers):
    out = bytearray((len(headers),))
    for name, value in headers:
        raw = value.encode("utf-8")
        if len(raw) > 1024:
            raise ValueError("header value too long")
        out.extend(struct.pack("!BH", IDS[name], len(raw)))
        out.extend(raw)
    return bytes(out)


def make_request(host, port, path):
    raw_path = path.encode("utf-8")
    if not 1 <= len(raw_path) <= 4096:
        raise ValueError("path must be 1 to 4096 UTF-8 bytes")
    host_value = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    headers = [
        ("host", host_value),
        ("user-agent", "bcurl/1"),
        ("accept", "*/*"),
        ("accept-encoding", "identity"),
        ("connection", "keep-alive"),
    ]
    payload = struct.pack("!H", len(raw_path)) + raw_path + encode_headers(headers)
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("request exceeds protocol limit")
    return FRAME.pack(MAGIC, VERSION, REQUEST, 0, 0, 1, len(payload)) + payload


def parse_headers(payload, offset, count):
    headers = {}
    for _ in range(count):
        if len(payload) - offset < 3:
            raise ProtocolError("short response header")
        name_id, size = struct.unpack_from("!BH", payload, offset)
        offset += 3
        if size > 1024 or len(payload) - offset < size:
            raise ProtocolError("invalid response header length")
        raw = payload[offset:offset + size]
        offset += size
        if b"\r" in raw or b"\n" in raw or b"\x00" in raw:
            raise ProtocolError("invalid response header value")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("response header is not UTF-8") from exc
        name = NAMES.get(name_id)
        if name is not None:
            if name in headers:
                raise ProtocolError("duplicate response header")
            headers[name] = value
    return headers, offset


def parse_response(payload):
    if len(payload) < 3:
        raise ProtocolError("short response")
    status = struct.unpack_from("!H", payload)[0]
    if not 100 <= status <= 599:
        raise ProtocolError("invalid status")
    headers, body_start = parse_headers(payload, 3, payload[2])
    body = payload[body_start:]
    length = headers.get("content-length")
    if length is None or not length.isascii() or not length.isdecimal():
        raise ProtocolError("missing or invalid content-length")
    if int(length) != len(body):
        raise ProtocolError("content-length does not match body")
    return status, headers, body


def parse_target(target):
    if not target or target[0].isspace() or target[-1].isspace() or any(ord(c) < 32 for c in target):
        raise ValueError("target contains whitespace or control characters")
    if "://" in target:
        parts = urlsplit(target)
        if parts.scheme != "bhttp":
            raise ValueError("only bhttp:// URLs are supported")
    else:
        parts = urlsplit("//" + target)
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("target must be host[:port]/path")
    if "?" in target or "#" in target:
        raise ValueError("query strings and fragments are not supported")
    if parts.netloc.endswith(":"):
        raise ValueError("port cannot be empty")
    try:
        port = parts.port if parts.port is not None else DEFAULT_PORT
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    path = parts.path or "/"
    return parts.hostname, port, path


def connect_once(host, port, timeout):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError("host resolved to no TCP addresses")
    family, kind, proto, _, address = next(
        (item for item in addresses if item[0] == socket.AF_INET), addresses[0]
    )
    sock = socket.socket(family, kind, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(address)
    except OSError:
        sock.close()
        raise
    return sock


def fetch(target, verbose=False, timeout=DEFAULT_TIMEOUT):
    host, port, path = parse_target(target)
    request = make_request(host, port, path)
    with connect_once(host, port, timeout) as sock:
        if verbose:
            hexdump("send request frame", request)
        sock.sendall(request)
        while True:
            raw_header = read_exact(sock, FRAME.size)
            magic, version, kind, flags, reserved, request_id, size = FRAME.unpack(raw_header)
            if magic != MAGIC or version != VERSION or flags or reserved or size > MAX_PAYLOAD:
                raise ProtocolError("invalid response frame header")
            payload = read_exact(sock, size)
            if verbose:
                hexdump("receive frame", raw_header + payload)
            if kind == REQUEST:
                raise ProtocolError("server sent a request frame")
            if kind != RESPONSE:
                continue  # Unknown frame types are fully consumed above.
            if request_id != 1:
                raise ProtocolError("response request ID does not match")
            status, _headers, body = parse_response(payload)
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()
            return 0 if 200 <= status <= 299 else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="BHTP/1 binary client")
    parser.add_argument("-v", "--verbose", action="store_true", help="hexdump every sent and received frame")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="connection timeout in seconds (default: 30)")
    parser.add_argument("target", help="host[:port]/path or bhttp://host[:port]/path (default port: 9000)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be a positive finite number")
    try:
        return fetch(args.target, args.verbose, args.timeout)
    except (ValueError, ProtocolError, OSError) as exc:
        print(f"bcurl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
