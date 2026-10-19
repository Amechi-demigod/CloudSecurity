"""--ca-file / SENSOR_CA_FILE / CNAPP_CA_FILE: trust a private (on-prem) CA without
ever disabling certificate verification."""
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from runtime_sensor.config import load_config
from runtime_sensor.schema import ProcessInfo, RuntimeEvent
from runtime_sensor.shipper import Shipper, build_opener

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway root CA and a server certificate for 127.0.0.1 / localhost signed by it."""
    d = tmp_path_factory.mktemp("pki")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
             "-days", "2", "-subj", "/CN=Test Internal Root CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             cwd=d)
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr",
             "-subj", "/CN=localhost", cwd=d)
    (d / "ext.cnf").write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n"
                               "subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    _openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", "srv.pem", "-days", "2", "-extfile", "ext.cnf", cwd=d)
    return d


@pytest.fixture()
def tls_server(pki):
    received = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "srv.pem", pki / "srv.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{srv.server_address[1]}/api/runtime/events", received
    srv.shutdown()
    srv.server_close()


def _ev():
    return RuntimeEvent(event_type="process_exec", sensor_id="s", host="h", process=ProcessInfo(pid=1))


def test_private_ca_rejected_without_ca_file(tls_server):
    url, received = tls_server
    s = Shipper(api_url=url, token="t", max_retries=0, sleep=lambda _: None)
    s.enqueue(_ev())
    s.flush()
    assert received == [] and s.stats["dropped_send_failed"] == 1


def test_private_ca_trusted_with_ca_file(tls_server, pki):
    url, received = tls_server
    s = Shipper(api_url=url, token="t", max_retries=0, ca_file=str(pki / "ca.pem"), sleep=lambda _: None)
    s.enqueue(_ev())
    s.flush()
    assert s.stats["sent"] == 1 and len(received) == 1


def test_bad_ca_file_is_a_clear_error(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ValueError, match="cannot load CA file"):
        build_opener(str(bad))
    with pytest.raises(ValueError, match="cannot load CA file"):
        build_opener(str(tmp_path / "missing.pem"))


def test_ca_file_from_env_and_flag(monkeypatch):
    monkeypatch.delenv("SENSOR_CA_FILE", raising=False)
    monkeypatch.delenv("CNAPP_CA_FILE", raising=False)
    assert load_config([]).ca_file is None
    monkeypatch.setenv("CNAPP_CA_FILE", "/etc/cnapp/ca.pem")
    assert load_config([]).ca_file == "/etc/cnapp/ca.pem"
    monkeypatch.setenv("SENSOR_CA_FILE", "/etc/runtime-sensor/ca.pem")
    assert load_config([]).ca_file == "/etc/runtime-sensor/ca.pem"
    assert load_config(["--ca-file", "/x.pem"]).ca_file == "/x.pem"
