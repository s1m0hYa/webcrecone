"""Local-only test server and deterministic rate-limiter clock."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import socket
import threading
import time
import unittest
from unittest.mock import patch


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@contextmanager
def local_server(routes, *, tls=None, last_byte_times=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, time.monotonic(), dict(self.headers)))
            status, headers, body = routes.get(self.path, (404, {}, b"missing"))
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                if last_byte_times is not None and body:
                    # 마지막 바이트를 늦게 보낸다. 요청 시작 간격만 제한하는 구현을 구별할 수 있다.
                    self.wfile.write(body[:-1])
                    time.sleep(0.12)
                    last_byte_times.append(time.monotonic())
                    body = body[-1:]
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format, *args):
            pass

    try:
        server = HTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        raise unittest.SkipTest("환경 정책이 루프백 소켓을 차단함: 실제 HTTP 통합 미검증") from None
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scheme = "https" if tls else "http"
        yield f"{scheme}://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


ROBOTS = (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /private\n")


@contextmanager
def simulated_server(routes):
    """Explicit socket simulation, exercising actual HTTPConnection/HTTPResponse parsing."""
    requests = []

    class MemorySocket:
        def __init__(self, *args):
            self.sent = b""

        def connect(self, address):
            if address != ("127.0.0.1", 8123):
                raise AssertionError("Unexpected simulated destination")

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            self.sent += bytes(data)

        def makefile(self, *args):
            lines = self.sent.decode("iso-8859-1").split("\r\n")
            method, path, version = lines[0].split(" ")
            if method != "GET":
                raise AssertionError("Only GET allowed")
            headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            requests.append((path, time.monotonic(), headers))
            status, response_headers, body = routes.get(path, (404, {}, b"missing"))
            if isinstance(body, str):
                body = body.encode("utf-8")
            response_headers = {**response_headers, "Connection": "close"}
            # 전송이 중간에 끊긴 경우도 실제 HTTPResponse로 검증할 수 있게 선언 길이를 보존한다.
            if "Transfer-Encoding" not in response_headers:
                response_headers.setdefault("Content-Length", str(len(body)))
            head = f"HTTP/1.1 {status} Test\r\n" + "".join(f"{name}: {value}\r\n" for name, value in response_headers.items()) + "\r\n"
            return io.BytesIO(head.encode("iso-8859-1") + body)

        def close(self):
            pass

    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8123))]
    with patch("webrecon.http_client.socket.socket", MemorySocket), patch("webrecon.scope.socket.getaddrinfo", return_value=records):
        yield "http://127.0.0.1:8123", requests
