"""End-to-end protocol checks using a real local TCP server."""

import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import bcurl
import bserve


PROJECT = Path(__file__).resolve().parents[1]


def receive_response(sock):
    raw = bcurl.read_exact(sock, bcurl.FRAME.size)
    magic, version, kind, flags, reserved, request_id, size = bcurl.FRAME.unpack(raw)
    assert (magic, version, kind, flags, reserved) == (b"BHTP", 1, 2, 0, 0)
    payload = bcurl.read_exact(sock, size)
    status, headers, body = bcurl.parse_response(payload)
    return request_id, status, headers, body


class BHTPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.html = b"<!doctype html><title>BHTP</title><h1>Hello, binary HTTP!</h1>\n"
        (cls.root / "index.html").write_bytes(cls.html)
        (cls.root / "blob.bin").write_bytes(b"\x00\xff\x10")
        cls.server = bserve.Server(("127.0.0.1", 0), bserve.Handler)
        cls.server.root = cls.root.resolve()
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temporary.cleanup()

    def client(self, path, *options):
        return subprocess.run(
            [sys.executable, str(PROJECT / "bcurl.py"), *options,
             f"127.0.0.1:{self.port}{path}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            check=False,
        )

    def client_with_scripted_response(self, frames):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]

            def reply():
                with listener.accept()[0] as conn:
                    header = bcurl.read_exact(conn, bcurl.FRAME.size)
                    length = bcurl.FRAME.unpack(header)[-1]
                    bcurl.read_exact(conn, length)
                    conn.sendall(frames)

            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            result = subprocess.run(
                [sys.executable, str(PROJECT / "bcurl.py"), f"127.0.0.1:{port}/"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
            )
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            return result

    def test_client_server_and_verbose_dump(self):
        result = self.client("/index.html", "-v")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.html)
        self.assertIn(b"send request frame", result.stderr)
        self.assertIn(b"receive frame", result.stderr)

    def test_binary_body_and_missing_file_exit(self):
        binary = self.client("/blob.bin")
        self.assertEqual(binary.returncode, 0, binary.stderr)
        self.assertEqual(binary.stdout, b"\x00\xff\x10")
        missing = self.client("/missing.txt")
        self.assertEqual(missing.returncode, 1, missing.stderr)
        self.assertEqual(missing.stdout, b"Not found\n")

    def test_multiple_fragmented_requests_share_one_connection(self):
        first = bcurl.make_request("127.0.0.1", self.port, "/index.html")
        second = bcurl.make_request("127.0.0.1", self.port, "/blob.bin")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            for fragment in (first[:3], first[3:16], first[16:19], first[19:]):
                sock.sendall(fragment)
            one = receive_response(sock)
            sock.sendall(second)
            two = receive_response(sock)
        self.assertEqual((one[1], one[2]["content-type"], one[3]), (200, "text/html", self.html))
        self.assertEqual((two[1], two[2]["content-type"], two[3]),
                         (200, "application/octet-stream", b"\x00\xff\x10"))

    def test_unknown_frame_is_skipped_without_closing_connection(self):
        unknown = bserve.FRAME.pack(b"BHTP", 1, 99, 0, 0, 9, 3) + b"xyz"
        request = bcurl.make_request("127.0.0.1", self.port, "/index.html")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(unknown + request)
            request_id, status, _, body = receive_response(sock)
        self.assertEqual((request_id, status, body), (1, 200, self.html))

    def test_bad_request_then_valid_request_on_one_connection(self):
        malformed = bserve.FRAME.pack(b"BHTP", 1, 1, 0, 0, 7, 1) + b"\x00"
        valid = bcurl.make_request("127.0.0.1", self.port, "/")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(malformed + valid)
            first = receive_response(sock)
            second = receive_response(sock)
        self.assertEqual((first[0], first[1]), (7, 400))
        self.assertEqual((second[0], second[1], second[3]), (1, 200, self.html))

    def test_root_escape_is_rejected(self):
        request = bcurl.make_request("127.0.0.1", self.port, "/../secret.txt")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(request)
            _, status, _, _ = receive_response(sock)
        self.assertEqual(status, 400)

    def test_unknown_header_is_skipped_and_duplicate_header_is_bad(self):
        payloads = (
            b"\x00\x01/\x01\xfa\x00\x01x",
            b"\x00\x01/\x02\x01\x00\x01a\x01\x00\x01b",
            b"\x00\x01/\x01\x01\x00\x01\xff",
        )
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            statuses = []
            for request_id, payload in enumerate(payloads, 1):
                sock.sendall(bserve.FRAME.pack(b"BHTP", 1, 1, 0, 0, request_id, len(payload)) + payload)
                statuses.append(receive_response(sock)[1])
        self.assertEqual(statuses, [200, 400, 400])

    def test_bad_frame_header_gets_400_then_closes(self):
        malformed = bserve.FRAME.pack(b"XXXX", 1, 1, 0, 0, 5, 0)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(malformed)
            _, status, headers, _ = receive_response(sock)
            closed = sock.recv(1)
        self.assertEqual(status, 400)
        self.assertEqual(headers["connection"], "close")
        self.assertEqual(closed, b"")

    def test_file_exceeding_frame_limit_returns_500(self):
        large = self.root / "large.bin"
        try:
            with large.open("wb") as file:
                file.truncate(bserve.MAX_PAYLOAD + 1)
            result = self.client("/large.bin")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, b"File too large\n")
        finally:
            large.unlink(missing_ok=True)

    def test_client_skips_unknown_frame_and_rejects_bad_response(self):
        unknown = bserve.FRAME.pack(b"BHTP", 1, 77, 0, 0, 0, 3) + b"xyz"
        success = bserve.response_frame(1, 200, b"OK", "text/plain")
        result = self.client_with_scripted_response(unknown + success)
        self.assertEqual((result.returncode, result.stdout), (0, b"OK"))
        wrong_length = success.replace(b"\x07\x00\x01" + b"2", b"\x07\x00\x01" + b"3", 1)
        result = self.client_with_scripted_response(wrong_length)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"content-length does not match", result.stderr)
        wrong_direction = bserve.FRAME.pack(b"BHTP", 1, 1, 0, 0, 1, 0)
        result = self.client_with_scripted_response(wrong_direction)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"server sent a request", result.stderr)

    def test_target_validation_and_ipv6_host_header(self):
        for target in ("localhost:0/", "localhost:/", "http://localhost/",
                       "localhost/x?", " localhost/", "localhost/\n"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                bcurl.parse_target(target)
        self.assertEqual(bcurl.parse_target("localhost"), ("localhost", 9000, "/"))
        self.assertEqual(bcurl.parse_target("[::1]:123/x"), ("::1", 123, "/x"))
        request = bcurl.make_request("::1", 123, "/")
        self.assertIn(b"[::1]:123", request)

    def test_server_cli_uses_supplied_root_port_host_and_timeout(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, str(PROJECT / "bserve.py"), str(self.root), str(port),
             "--host", "127.0.0.1", "--timeout", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    self.fail(f"server exited: {process.stderr.read().decode(errors='replace')}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        self.fail("server did not start")
                    time.sleep(0.05)
            result = subprocess.run(
                [sys.executable, str(PROJECT / "bcurl.py"), "--timeout", "1",
                 f"127.0.0.1:{port}/index.html"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
            )
            self.assertEqual((result.returncode, result.stdout), (0, self.html), result.stderr)
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_documented_hexdumps_match_encoded_frames(self):
        self.assertEqual((PROJECT / "www" / "index.html").read_bytes(), self.html)
        spec = (PROJECT / "SPEC.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```text\n(.*?)```", spec, re.DOTALL)
        self.assertEqual(len(blocks), 2)

        def bytes_in(block):
            return bytes.fromhex(" ".join(line.split(": ", 1)[1] for line in block.splitlines()))

        self.assertEqual(bytes_in(blocks[0]), bcurl.make_request("localhost", 9000, "/index.html"))
        self.assertEqual(bytes_in(blocks[1]), bserve.response_frame(
            1, 200, self.html, "text/html"
        ))


if __name__ == "__main__":
    unittest.main()
