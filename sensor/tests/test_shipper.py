import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from runtime_sensor.schema import ProcessInfo, RuntimeEvent
from runtime_sensor.shipper import SendError, Shipper, http_post


def ev(i=0):
    return RuntimeEvent(event_type="process_exec", sensor_id="s", host="h", process=ProcessInfo(pid=i))


class FakePost:
    def __init__(self, failures=()):
        self.failures = list(failures)
        self.calls = []

    def __call__(self, url, body, headers, timeout):
        self.calls.append((url, json.loads(body), headers))
        if self.failures:
            raise self.failures.pop(0)
        return 200


def test_batches_and_headers():
    post = FakePost()
    s = Shipper(api_url="http://x/api/runtime/events", token="tok", sensor_id="s1", batch_size=2, post=post,
                payload_format="envelope")
    for i in range(5):
        s.enqueue(ev(i))
    s.flush()
    assert [len(c[1]["events"]) for c in post.calls] == [2, 2, 1]
    url, payload, headers = post.calls[0]
    assert url == "http://x/api/runtime/events"
    assert headers["Authorization"] == "Bearer tok" and headers["X-Sensor-Id"] == "s1"
    assert payload["sensor_id"] == "s1" and "sent_at" in payload
    assert s.stats["sent"] == 5


def test_default_format_is_native_list():
    post = FakePost()
    s = Shipper(post=post)
    s.enqueue(RuntimeEvent(event_type="network_connect", sensor_id="s", host="h"))
    s.flush()
    sent = post.calls[0][1][0]
    assert sent["event_type"] == "network_connect" and sent["schema_version"] == "1.0"


def test_compat_format_translates_event_types():
    post = FakePost()
    s = Shipper(post=post, payload_format="cnapp-mvp")
    s.enqueue(RuntimeEvent(event_type="network_connect", sensor_id="s", host="h"))
    s.flush()
    assert post.calls[0][1][0]["event_type"] == "network_connection"


def test_library_events_are_sent_in_native_mode():
    from runtime_sensor.schema import LibraryInfo
    post = FakePost()
    s = Shipper(post=post)
    s.enqueue(RuntimeEvent(event_type="library_loaded", library=LibraryInfo(path="/lib/libz.so.1")))
    s.flush()
    assert post.calls[0][1][0]["event_type"] == "library_loaded"


def test_library_only_batch_is_skipped_in_compat_mode():
    from runtime_sensor.schema import LibraryInfo
    post = FakePost()
    s = Shipper(post=post, payload_format="cnapp-mvp")
    s.enqueue(RuntimeEvent(event_type="library_loaded", library=LibraryInfo(path="/lib/libz.so.1")))
    s.flush()
    assert post.calls == [] and s.stats["skipped_unsupported"] == 1


def test_list_payload_format():
    post = FakePost()
    s = Shipper(payload_format="list", post=post)
    s.enqueue(ev())
    s.flush()
    assert isinstance(post.calls[0][1], list)


def test_no_auth_header_without_token():
    post = FakePost()
    s = Shipper(post=post)
    s.enqueue(ev())
    s.flush()
    assert "Authorization" not in post.calls[0][2]


def test_retry_with_backoff_then_success():
    sleeps = []
    post = FakePost(failures=[SendError("503", True), SendError("net", True)])
    s = Shipper(post=post, sleep=sleeps.append, backoff_base=1.0)
    s.enqueue(ev())
    s.flush()
    assert len(post.calls) == 3 and s.stats["sent"] == 1
    assert len(sleeps) == 2 and 0.5 <= sleeps[0] <= 1.0 and 1.0 <= sleeps[1] <= 2.0


def test_non_retryable_dropped():
    post = FakePost(failures=[SendError("400", False)])
    s = Shipper(post=post, sleep=lambda _: None)
    s.enqueue(ev())
    s.flush()
    assert len(post.calls) == 1 and s.stats["dropped_send_failed"] == 1


def test_gives_up_after_max_retries():
    post = FakePost(failures=[SendError("503", True)] * 10)
    s = Shipper(post=post, sleep=lambda _: None, max_retries=3)
    s.enqueue(ev())
    s.flush()
    assert len(post.calls) == 4 and s.stats["dropped_send_failed"] == 1


def test_bounded_queue_drops_oldest():
    s = Shipper(max_queue=3, post=FakePost())
    for i in range(5):
        s.enqueue(ev(i))
    assert s.queue_len() == 3 and s.stats["dropped_queue_full"] == 2
    batch = s._take_batch()
    assert [e["process"]["pid"] for e in batch] == [2, 3, 4]


def test_dry_run_writes_json_lines():
    out = io.StringIO()
    post = FakePost()
    s = Shipper(dry_run=True, out=out, post=post)
    s.enqueue(ev(1))
    s.enqueue(ev(2))
    s.flush()
    lines = out.getvalue().splitlines()
    assert [json.loads(line)["process"]["pid"] for line in lines] == [1, 2]
    assert post.calls == []


def test_background_thread_flushes_on_stop():
    post = FakePost()
    s = Shipper(post=post, flush_interval=60)
    s.start()
    s.enqueue(ev())
    s.stop()
    assert s.stats["sent"] == 1


class _Handler(BaseHTTPRequestHandler):
    received = []
    status = 202

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.received.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(_Handler.status)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_real_http_post_against_local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/runtime/events"
        s = Shipper(api_url=url, token="abc", sensor_id="s", payload_format="envelope")
        s.enqueue(ev(7))
        s.flush()
        path, headers, payload = _Handler.received[-1]
        assert path == "/api/runtime/events"
        assert headers["Authorization"] == "Bearer abc"
        assert payload["events"][0]["process"]["pid"] == 7
        _Handler.status = 500
        try:
            http_post(url, b"{}", {"Content-Type": "application/json"}, 5)
            assert False, "expected SendError"
        except SendError as exc:
            assert exc.retryable
        _Handler.status = 401
        try:
            http_post(url, b"{}", {"Content-Type": "application/json"}, 5)
            assert False, "expected SendError"
        except SendError as exc:
            assert not exc.retryable
    finally:
        server.shutdown()
