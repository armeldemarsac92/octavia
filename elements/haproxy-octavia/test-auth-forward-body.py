#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the native octavia-auth action with a positive body limit."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event
from threading import Thread
import time
import unittest

from h2.connection import H2Connection
from h2.events import ResponseReceived


LIMIT = 65536
BODY = bytes(range(256)) * 256
LARGE = BODY * 64


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.started.append(self.path)
        if self.server.authorizer and self.path == '/hints':
            self.wfile.write(b'HTTP/1.1 103 Early Hints\r\n'
                             b'Link: </style.css>; rel=preload\r\n\r\n')
            self.wfile.flush()
            # Give the client a chance to process the interim headers while
            # the receiving peer is still applying backpressure.
            time.sleep(.05)
        trailers = []
        if self.headers.get('Transfer-Encoding') == 'chunked':
            chunks = []
            while size := int(self.rfile.readline(), 16):
                chunks.append(self.rfile.read(size))
                assert self.rfile.read(2) == b'\r\n'
            while line := self.rfile.readline().strip():
                trailers.append(line)
            body = b''.join(chunks)
        else:
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.received.append((self.headers.get('Content-Length'),
                                     body, trailers))
        if self.server.authorizer:
            self.server.checked.set()
            self.server.release.wait(5)
        self.send_response(403 if self.path == '/deny' else 200)
        self.send_header('Content-Length', '0')
        self.end_headers()


class TestForwardBody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        run = Path(stack.enter_context(TemporaryDirectory()))
        for authorizer in (True, False):
            peer = stack.enter_context(
                ThreadingHTTPServer(('127.0.0.1', 0), Peer))
            peer.authorizer = authorizer
            peer.received, peer.started = [], []
            peer.checked, peer.release = Event(), Event()
            peer.release.set()
            thread = Thread(target=peer.serve_forever, daemon=True)
            thread.start()
            stack.callback(peer.shutdown)
            if authorizer:
                cls.auth = peer
            else:
                cls.origin = peer

        def port():
            with socket.socket() as unused:
                unused.bind(('127.0.0.1', 0))
                return unused.getsockname()[1]

        cls.port, cls.h2, cls.collect = port(), port(), port()
        sock = run / 'auth.sock'
        lua = run / 'check-body.lua'
        lua.write_text("""local bytes = {}
for i = 0, 255 do bytes[i + 1] = string.char(i) end
local expected = string.rep(table.concat(bytes), 256)
core.register_action("check-body", {"http-req"}, function(txn)
    txn:set_var("txn.equal", txn.f:octavia_auth_body() == expected)
end)
""")
        cfg = run / 'haproxy.cfg'
        action = f'http-request octavia-auth {sock} - - -'
        cfg.write_text(f"""global
    nbthread 2
    tune.octavia-auth-body-max-memory {len(LARGE)}
    lua-load-per-thread {lua}
defaults
    mode http
    retries 0
    timeout connect 2s
    timeout client 8s
    timeout server 8s
    timeout http-request 6s
frontend gateway
    bind 127.0.0.1:{cls.port}
    bind 127.0.0.1:{cls.h2} proto h2
    filter octavia-auth
    {action} if {{ path /legacy }}
    {action} 0 if {{ path /zero }}
    {action} {len(LARGE)} if {{ path /hints }}
    {action} {LIMIT} unless {{ path /legacy /zero /public /hints }}
    default_backend origin
frontend standalone-collect
    bind 127.0.0.1:{cls.collect}
    acl sample path /capture
    http-request octavia-collect-body {LIMIT} if sample
    http-request octavia-collect-body {len(LARGE)} if {{ path /large }}
    http-request lua.check-body if sample
    http-request return status 500 if sample !{{ var(txn.equal) -m bool }}
    default_backend origin
listen private-check
    bind {sock} mode 600 octavia-auth-socket
    server auth 127.0.0.1:{cls.auth.server_port}
backend origin
    server origin 127.0.0.1:{cls.origin.server_port}
""")
        proc = stack.enter_context(
            subprocess.Popen([BINARY, '-db', '-f', cfg]))
        stack.callback(proc.terminate)
        for _ in range(200):
            if sock.exists():
                return
            if proc.poll() is not None:
                break
            time.sleep(.025)
        assert sock.exists(), 'HAProxy did not start'

    def setUp(self):
        for peer in (self.auth, self.origin):
            peer.started.clear()
            peer.received.clear()
        self.auth.release.set()
        self.auth.checked.clear()

    def send(self, path, body, chunked=False, port=None):
        with closing(HTTPConnection('127.0.0.1', port or self.port,
                                    timeout=8)) as c:
            c.putrequest('POST', path)
            if chunked:
                c.putheader('Transfer-Encoding', 'chunked')
                c.putheader('Trailer', 'X-Checksum')
            else:
                c.putheader('Content-Length', str(len(body)))
            c.putheader('X-Large-Header', 'x' * 10000)
            c.endheaders()
            if chunked:
                for start in range(0, len(body), 2047):
                    part = body[start:start + 2047]
                    c.send(f'{len(part):x}\r\n'.encode() + part + b'\r\n')
                c.send(b'0\r\nx-checksum: present\r\n\r\n')
            else:
                c.send(body)
            return c.getresponse().status

    def test_allow_waits_for_decision_and_preserves_chunked_trailers(self):
        self.auth.release.clear()
        with ThreadPoolExecutor(1) as pool:
            status = pool.submit(self.send, '/allow', BODY, True)
            try:
                self.assertTrue(self.auth.checked.wait(4))
                self.assertEqual([], self.origin.started)
                self.assertEqual([(str(LIMIT), BODY, [])], self.auth.received)
            finally:
                self.auth.release.set()
            self.assertEqual(200, status.result())
        self.assertEqual([(None, BODY, [b'x-checksum: present'])],
                         self.origin.received)

    def test_exact_limit_and_small_binary(self):
        for body in (b'\x00\xfftest', BODY, b''):
            self.assertEqual(200, self.send('/allow', body))
            self.assertEqual((str(len(body)), body, []),
                             self.auth.received[-1])
            self.assertEqual(body, self.origin.received[-1][1])

    def test_overflow_stops_before_both_peers(self):
        for chunked in (False, True):
            self.assertEqual(413, self.send('/allow', BODY + b'x', chunked))
        self.assertEqual([], self.auth.started)
        self.assertEqual([], self.origin.started)

    def test_chunk_overflow_before_end_of_request(self):
        with closing(HTTPConnection('127.0.0.1', self.port, timeout=4)) as c:
            c.putrequest('POST', '/allow')
            c.putheader('Transfer-Encoding', 'chunked')
            c.endheaders()
            c.send(f'{LIMIT:x}\r\n'.encode() + BODY + b'\r\n')
            self.assertFalse(self.auth.checked.wait(.1))
            c.send(b'1\r\nx\r\n')
            self.assertEqual(413, c.getresponse().status)
        self.assertEqual([], self.auth.started)
        self.assertEqual([], self.origin.started)

    def test_deny_keeps_origin_untouched(self):
        self.assertEqual(403, self.send('/deny', BODY))
        self.assertEqual([(str(LIMIT), BODY, [])], self.auth.received)
        self.assertEqual([], self.origin.started)

    def test_body_fetch_exposes_all_bytes_to_next_action(self):
        self.assertEqual(200, self.send('/capture', BODY, True, self.collect))
        self.assertEqual(413, self.send('/capture', BODY + b'x', True,
                                        self.collect))
        self.assertEqual([], self.auth.started)
        self.assertEqual([(None, BODY, [b'x-checksum: present'])],
                         self.origin.received)

    def test_zero_absent_and_unfiltered_routes(self):
        for path in ('/legacy', '/zero', '/public'):
            self.assertEqual(200, self.send(path, BODY + b'x'))
        self.assertEqual([('0', b'', [])] * 2, self.auth.received)
        self.assertEqual([BODY + b'x'] * 3,
                         [record[1] for record in self.origin.received])

    def test_informational_response_during_upload(self):
        self.assertEqual(200, self.send('/hints', LARGE))
        self.assertEqual([(str(len(LARGE)), LARGE, [])], self.auth.received)
        self.assertEqual([LARGE], [row[1] for row in self.origin.received])

    def test_process_byte_budget_is_released(self):
        # A peer waiting for its decision owns a small part of the budget.
        # The standalone collector competes for bytes, independently of HTTP
        # check slots. Its 503 leaves both peers untouched.
        self.auth.release.clear()
        with ThreadPoolExecutor(1) as pool:
            held = pool.submit(self.send, '/allow', BODY)
            try:
                self.assertTrue(self.auth.checked.wait(4))
                answer = self.send('/large', LARGE, port=self.collect)
                self.assertEqual(503, answer)
                self.assertEqual(['/allow'], self.auth.started)
                self.assertEqual([], self.origin.started)
            finally:
                self.auth.release.set()
            self.assertEqual(200, held.result())
        self.assertEqual(200, self.send('/large', LARGE, port=self.collect))
        self.assertEqual([BODY, LARGE], [r[1] for r in self.origin.received])

    def test_http_check_slots_are_reserved_after_collection(self):
        with closing(HTTPConnection('127.0.0.1', self.port, timeout=5)) as c:
            c.putrequest('POST', '/allow')
            c.putheader('Content-Length', '2')
            c.putheader('Expect', '100-continue')
            c.endheaders()
            # The interim response proves the rule is collecting this body.
            with c.sock.makefile('rb') as reader:
                self.assertIn(b' 100 ', reader.readline())
                self.assertEqual(b'\r\n', reader.readline())
            self.assertEqual(200, self.send('/legacy', b'small'))
            c.send(b'ok')
            self.assertEqual(200, c.getresponse().status)
        self.assertEqual([b'', b'ok'], [r[1] for r in self.auth.received])

        # With the one-slot test binary, confirm admission is saturated
        # before verifying that the declared overflow still gets its 413.
        self.auth.checked.clear()
        self.auth.release.clear()
        with ThreadPoolExecutor(1) as pool:
            held = pool.submit(self.send, '/allow', b'small')
            try:
                self.assertTrue(self.auth.checked.wait(4))
                if SINGLE_CHECK:
                    self.assertEqual(503, self.send('/legacy', b'small'))
                self.assertEqual(413, self.send('/allow', BODY + b'x'))
            finally:
                self.auth.release.set()
            self.assertEqual(200, held.result())

    def test_http2_content_length_with_request_trailers(self):
        body = BODY[:32768]
        h2 = H2Connection()
        h2.initiate_connection()
        h2.send_headers(1, [
            (':method', 'POST'), (':scheme', 'http'),
            (':authority', 'route.example'), (':path', '/allow'),
            ('content-length', str(len(body))),
        ])
        for start in range(0, len(body), h2.max_outbound_frame_size):
            h2.send_data(1, body[start:start + h2.max_outbound_frame_size])
        h2.send_headers(1, [('x-checksum', 'present')], end_stream=True)
        with socket.create_connection(('127.0.0.1', self.h2),
                                      timeout=5) as sock:
            sock.sendall(h2.data_to_send())
            response = None
            while response is None:
                data = sock.recv(65536)
                self.assertTrue(data)
                for event in h2.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        response = dict(event.headers)[b':status']
        self.assertEqual(b'200', response)
        self.assertEqual([(str(len(body)), body, [])], self.auth.received)
        self.assertEqual([(None, body, [b'x-checksum: present'])],
                         self.origin.received)

    def test_http2_without_content_length(self):
        for body, expected in ((BODY, 200), (BODY + b'x', 413)):
            response = subprocess.run([
                'curl', '--noproxy', '*', '--silent', '--show-error',
                '--http2-prior-knowledge', '--max-time', '8', '-X', 'POST',
                '--header', 'Content-Length:', '--upload-file', '-',
                '--write-out', '%{http_version} %{http_code}',
                '--output', '/dev/null', f'http://127.0.0.1:{self.h2}/h2',
            ], input=body, check=True, capture_output=True)
            self.assertEqual(f'2 {expected}'.encode(), response.stdout)
        self.assertEqual([(str(LIMIT), BODY, [])], self.auth.received)
        self.assertEqual([BODY],
                         [record[1] for record in self.origin.received])


if __name__ == '__main__':
    BINARY = str(Path(sys.argv.pop(1)).resolve())
    SINGLE_CHECK = '--single-check' in sys.argv
    if SINGLE_CHECK:
        # Build HAProxy with make DEFINE=-DAUTH_ACTIVE_LIMIT=1.
        sys.argv.remove('--single-check')
    unittest.main()
