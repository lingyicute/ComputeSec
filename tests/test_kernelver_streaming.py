"""Exercise real HTTPResponse buffering without network or wall-clock delays."""

import http.client
import io

import pytest

from computesec import kernelver as kv


@pytest.mark.parametrize("headers", [b"Content-Length: 128\r\n", b"Connection: close\r\n"])
def test_trickle_body_returns_to_deadline_between_socket_reads(monkeypatch, headers):
    clock = [0.0]

    class Trickle(io.RawIOBase):
        def __init__(self):
            self.headers = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n"
            self.remaining = 128
            self.body_reads = 0

        def readable(self):
            return True

        def readinto(self, buffer):
            if self.headers:
                chunk, self.headers = self.headers[:len(buffer)], self.headers[len(buffer):]
            elif self.remaining:
                self.remaining -= 1
                self.body_reads += 1
                clock[0] += 0.25
                chunk = b"x"
            else:
                return 0
            buffer[:len(chunk)] = chunk
            return len(chunk)

    raw = Trickle()

    class FakeSocket:
        def makefile(self, _mode):
            return io.BufferedReader(raw)

    response = http.client.HTTPResponse(FakeSocket())
    response.url = kv.RELEASES_URL
    response.begin()
    monkeypatch.setattr(kv, "_urlopen", lambda *_: response)
    monkeypatch.setattr(kv.time, "monotonic", lambda: clock[0])
    with pytest.raises(ValueError, match="秒"):
        kv._default_fetcher(kv.RELEASES_URL, 1)
    assert raw.body_reads <= 5
    assert response.closed
