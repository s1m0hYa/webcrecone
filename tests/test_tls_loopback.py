"""임시 인증서로 실제 루프백 TLS의 기본 거부와 신뢰한 인증서 검증을 확인한다."""
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from helpers import ROBOTS, local_server
from test_recon import crawl


class LocalTLSTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "임시 인증서를 발급할 로컬 OpenSSL 명령 없음")
    def test_trust_and_hostname_are_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder, "key.pem")
            cert = Path(folder, "cert.pem")
            for subject, matches in (("127.0.0.1", True), ("127.0.0.2", False)):
                # 키·인증서는 매번 새로 만들며 저장소와 운영체제 신뢰 저장소에 남기지 않는다.
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                                "-subj", "/CN=fixture", "-addext", "subjectAltName=IP:" + subject,
                                "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=30)
                server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_tls.load_cert_chain(cert, key)
                client_tls = ssl.create_default_context(cafile=str(cert))
                routes = {"/robots.txt": ROBOTS, "/": (200, {"Content-Type": "text/html"}, "<title>TLS</title>")}
                with local_server(routes, tls=server_tls) as (origin, received):
                    untrusted, _, _ = crawl(origin)
                    self.assertEqual(untrusted["requests"][0]["tls_verification"], "failed")
                    with patch("webrecon.http_client.ssl.create_default_context", return_value=client_tls):
                        trusted, _, _ = crawl(origin)
                    if matches:
                        self.assertEqual([r["tls_verification"] for r in trusted["requests"]], ["verified", "verified"])
                        self.assertEqual(trusted["pages"][0]["title"], "TLS")
                    else:
                        self.assertEqual(trusted["requests"][0]["tls_verification"], "failed")
                        self.assertEqual(received, [])
