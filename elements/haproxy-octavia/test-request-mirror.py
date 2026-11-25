#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the Amphora binary over loopback and private UNIX sockets."""

import argparse
from concurrent import futures
import http.client
import http.server
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived
from h2.events import RequestReceived
from h2.events import ResponseReceived
from h2.events import StreamEnded


POOL_A = '00000000-0000-4000-8000-000000000001'
POOL_B = '00000000-0000-4000-8000-000000000002'
POOL_OFFLINE = '00000000-0000-4000-8000-000000000003'
POOL_H2C = '00000000-0000-4000-8000-000000000004'
POOL_TLS = '00000000-0000-4000-8000-000000000005'
POOL_TLS_VERIFIED = '00000000-0000-4000-8000-000000000006'


class Recorder(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def __init__(self, status, reply, tls=None):
        super().__init__(('127.0.0.1', 0), RecordRequest)
        if tls:
            self.socket = tls.wrap_socket(self.socket, server_side=True)
        self.status = status
        self.reply = reply
        self.records = {}
        self.snis = {}
        self.incomplete = set()
        self.started = set()
        self.release = threading.Event()
        self.release.set()
        self.block_read = False
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class RecordRequest(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def handle(self):
        try:
            self.connection.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            super().handle()
        except ConnectionError:
            pass

    def read_body(self):
        if self.headers.get('Transfer-Encoding', '').endswith('chunked'):
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b';', 1)[0], 16)
                if not size:
                    break
                chunk = self.rfile.read(size)
                if len(chunk) != size or self.rfile.read(2) != b'\r\n':
                    raise ValueError('incomplete chunk')  # noqa: O342
                chunks.append(chunk)
            trailers = []
            while (trailer := self.rfile.readline()) != b'\r\n':
                if not trailer:
                    raise ValueError('missing end of trailers')  # noqa: O342
                name, value = trailer.decode().split(':', 1)
                trailers.append((name.lower(), value.strip()))
            return b''.join(chunks), trailers
        size = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError('incomplete body')  # noqa: O342
        return body, []

    def record(self):
        self.server.started.add(self.path)
        if self.server.block_read:
            self.server.release.wait(10)
        try:
            body, trailers = self.read_body()
        except (OSError, ValueError):
            self.server.incomplete.add(self.path)
            return
        self.server.snis[self.path] = getattr(self.connection, 'sni', None)
        self.server.records[self.path] = (
            self.command, self.headers.get('Host'),
            self.headers.get_all('X-Repeat'), self.headers.get('X-Order'),
            self.headers.get('X-Hop'), body, trailers,
        )
        self.server.release.wait(10)
        try:
            self.send_response(self.server.status)
            self.send_header('X-From', self.server.reply.decode())
            self.send_header('Content-Length', str(len(self.server.reply)))
            self.end_headers()
            self.wfile.write(self.server.reply)
        except OSError:
            pass

    do_GET = do_POST = record


class RecordH2Request(socketserver.BaseRequestHandler):
    def handle(self):
        connection = H2Connection(H2Configuration(
            client_side=False, header_encoding='utf-8'))
        connection.initiate_connection()
        self.request.settimeout(5)
        try:
            self.request.sendall(connection.data_to_send())
            while data := self.request.recv(65536):
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        headers = dict(event.headers)
                        self.server.records[headers[':path']] = (
                            headers[':scheme'], headers.get(
                                ':authority', headers.get('host')))
                        connection.send_headers(
                            event.stream_id, [(':status', '204')],
                            end_stream=True)
                self.request.sendall(connection.data_to_send())
        except ConnectionError:
            pass


class H2Recorder(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), RecordH2Request)
        self.records = {}
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()


def wait_for(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            message = 'operation did not finish before deadline'
            raise AssertionError(message)
        time.sleep(.01)


class WireTest(unittest.TestCase):
    @classmethod
    def create_tls(cls):
        cls.cert = cls.root / 'wire.crt'
        key = cls.root / 'wire.key'
        cls.pem = cls.root / 'wire.pem'
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-subj', '/CN=verified.example', '-days', '1',
             '-addext', 'subjectAltName=DNS:verified.example',
             '-keyout', key, '-out', cls.cert],
            check=True, capture_output=True,
        )
        cls.pem.write_bytes(cls.cert.read_bytes() + key.read_bytes())
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cls.cert, key)

        def record_sni(connection, name, context):
            connection.sni = name

        tls.sni_callback = record_sni
        return tls

    @classmethod
    def setUpClass(cls):
        root = tempfile.TemporaryDirectory(prefix='om-')
        cls.addClassCleanup(root.cleanup)
        cls.root = Path(root.name)
        cls.primary = Recorder(203, b'primary')
        cls.selected = Recorder(203, b'selected')
        cls.a = Recorder(418, b'mirror-a')
        cls.b = Recorder(421, b'mirror-b')
        cls.h2_backend = H2Recorder()
        tls = cls.create_tls()
        cls.tls_primary = Recorder(203, b'primary', tls)
        cls.tls_mirror = Recorder(418, b'mirror', tls)
        for recorder in (cls.primary, cls.selected, cls.a, cls.b,
                         cls.h2_backend, cls.tls_primary, cls.tls_mirror):
            cls.addClassCleanup(recorder.close)

        # Reserve and release a loopback address to exercise a refused connect.
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0))
            offline_port = unused.getsockname()[1]

        cls.front = cls.root / 'http.sock'
        cls.h2_port = cls.root / 'h2.sock'
        cls.tls_port = cls.root / 'tls.sock'
        cls.stats = cls.root / 'stats.sock'
        cls.config = cls.root / 'haproxy.cfg'
        mirror_a = f'http-request octavia-mirror {POOL_A}'
        mirror_b = f'http-request octavia-mirror {POOL_B}'
        verified = f'http-request octavia-mirror {POOL_TLS_VERIFIED}'
        set_policy = 'http-request set-var(txn.octavia_l7_policy)'
        set_draw = 'http-request set-var(txn.octavia_weighted_draw)'
        selected = '{ var(txn.octavia_l7_policy) -m str selected }'
        second = '{ var(txn.octavia_weighted_draw) -m int 1 }'
        client_sni = 'ssl verify none sni ssl_fc_sni'
        cls.config.write_text(f"""global
    nbthread 2
    maxconn 16
    stats socket {cls.stats} mode 600 level user
    tune.bufsize 16384

defaults
    mode http
    timeout connect 1s
    timeout client 10s
    timeout server 10s

frontend public
    bind {cls.front}
    bind {cls.h2_port} proto h2
    bind {cls.tls_port} ssl crt {cls.pem} alpn h2,http/1.1
    filter octavia-mirror {cls.root}
    http-request set-header X-Order before-a
    {mirror_a} 1 1 if {{ path_beg /both /abort /cap /pressure /h2-trailer }}
    http-request set-header X-Order before-b
    {mirror_b} 1 1 if {{ path_beg /both /pressure /h2-trailer }}
    http-request octavia-mirror {POOL_OFFLINE} 1 1 if {{ path_beg /both }}
    {mirror_a} 0 100 if {{ path_beg /zero/ }}
    {mirror_a} 100 100 if {{ path_beg /full/ }}
    {mirror_a} 20 100 if {{ path_beg /sample/ }}
    {mirror_b} 1073741824 2147483647 if {{ path_beg /sample/ }}
    http-request octavia-mirror {POOL_H2C} 1 1 if {{ path_beg /scheme/ }}
    http-request octavia-mirror {POOL_TLS} 1 1 if {{ path_beg /sni/plain }}
    {verified} 1 1 if {{ path /sni/fixed }}
    http-request set-header X-Order primary
    {set_policy} str(selected) if {{ path_beg /selected/ }}
    {set_draw} int(0) if {{ path /selected/a }}
    {set_draw} int(1) if {{ path /selected/b }}
    {set_policy} str(fixed) if {{ path /fixed }}
    use_backend selected if {{ path_beg /selected/ /adjacent/ }}
    use_backend fixed if {{ path /fixed }}
    use_backend tls-primary if {{ path_beg /sni/ }}
    default_backend primary

backend primary
    server primary 127.0.0.1:{cls.primary.server_port}

backend tls-primary
    server primary 127.0.0.1:{cls.tls_primary.server_port} {client_sni}

backend selected
    http-request set-header X-Order rule if {selected}
    {mirror_a} 1 1 if {selected}
    http-request set-header X-Order selected if {selected} {second}
    {mirror_b} 1 1 if {selected} {second}
    http-request set-header X-Order primary
    use-server second if {selected} {second}
    server first 127.0.0.1:{cls.primary.server_port}
    server second 127.0.0.1:{cls.selected.server_port} backup

backend fixed
    http-request set-header X-Order fixed
    {mirror_a} 1 1 if {{ var(txn.octavia_l7_policy) -m str fixed }}
    http-request return status 202 content-type text/plain string local
""" + ''.join(
            f"""
listen delivery-{pool}
    bind {cls.root}/{pool}.sock mode 600 octavia-mirror-socket
    option abortonclose
    retries 0
    http-request disable-l7-retry
    server mirror 127.0.0.1:{port}{options}
"""
            for pool, port, options in (
                (POOL_A, cls.a.server_port, ''),
                (POOL_B, cls.b.server_port, ''),
                (POOL_OFFLINE, offline_port, ''),
                (POOL_H2C, cls.h2_backend.server_address[1], ' proto h2'),
                (POOL_TLS, cls.tls_mirror.server_port, ' ' + client_sni),
                (POOL_TLS_VERIFIED, cls.tls_mirror.server_port,
                 f' ssl verify required ca-file {cls.cert}'
                 ' sni str(verified.example)'
                 ' verifyhost-strict verified.example'),
            )
        ))
        check = cls.check_config(cls.config)
        if check.returncode:
            raise AssertionError(check.stderr)
        cls.log = cls.root / 'haproxy.log'
        cls.process = cls.start(cls.config)
        cls.addClassCleanup(cls.stop)
        wait_for(lambda: cls.stats.exists() or cls.process.poll() is not None)
        if cls.process.poll() is not None:
            raise AssertionError(cls.log.read_text())

    @classmethod
    def check_config(cls, config):
        return subprocess.run([BINARY, '-c', '-f', config],
                              capture_output=True, text=True)

    @classmethod
    def start(cls, config, *more):
        with cls.log.open('ab') as log:
            return subprocess.Popen(
                [BINARY, '-db', '-f', config, *more], stdout=log, stderr=log)

    @classmethod
    def stop(cls):
        if cls.process.poll() is None:
            cls.process.terminate()
        cls.process.wait(timeout=5)
        if cls.process.returncode not in (0, -15):
            raise AssertionError(cls.log.read_text())

    def connect(self, endpoint=None):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(5)
        sock.connect(str(endpoint or self.front))
        return sock

    def tls_connect(self, name, alpn='http/1.1'):
        context = ssl.create_default_context(cafile=self.cert)
        context.check_hostname = False
        context.set_alpn_protocols([alpn])
        return context.wrap_socket(
            self.connect(self.tls_port), server_hostname=name)

    def counters(self):
        with self.connect(self.stats) as sock:
            sock.sendall(b'show octavia mirrors\n')
            with sock.makefile() as response:
                return {key: int(value) for key, value in
                        (line.split() for line in response if line.strip())}

    def tearDown(self):
        self.a.block_read = False
        self.a.release.set()
        self.b.release.set()
        wait_for(lambda: self.counters()['active'] == 0)
        self.assertIsNone(self.process.poll(), self.log.read_text())

    def assert_primary(self, response, reply='primary'):
        self.assertEqual(
            (203, reply, reply.encode()),
            (response.status, response.getheader('X-From'), response.read()),
        )

    def get(self, *paths):
        with self.connect() as sock:
            conn = http.client.HTTPConnection('test.example')
            conn.sock = sock
            for path in paths:
                conn.request('GET', path)
                self.assert_primary(conn.getresponse())

    def chunked(self, path, body, trailers=(), pace=0):
        with self.connect() as sock:
            sock.sendall(
                f'POST {path} HTTP/1.1\r\nHost: test.example\r\n'
                'X-Repeat: one\r\nX-Repeat: two\r\n'
                'Connection: X-Hop\r\nX-Hop: private\r\n'
                'Transfer-Encoding: chunked\r\nTrailer: X-Digest\r\n'
                '\r\n'.encode()
            )
            for start in range(0, len(body), 4096):
                chunk = body[start:start + 4096]
                sock.sendall(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                if pace:
                    time.sleep(pace)
            sock.sendall(b'0\r\n' + b''.join(trailers) + b'\r\n')
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assert_primary(response)

    def test_chunked_http1_streams_to_two_pools(self):
        path = '/both/http1?x=%2F&x=foo'
        body = bytes(range(256)) * 1200
        self.a.release.clear()
        self.b.release.clear()
        started = self.counters()['started']
        self.chunked(path, body, [b'X-Digest: example\r\n'], pace=.001)
        self.assertEqual(started + 3, self.counters()['started'])
        wait_for(lambda: path in self.a.records and path in self.b.records)
        for recorder, header in ((self.a, 'before-a'), (self.b, 'before-b')):
            self.assertEqual(
                ('POST', 'test.example', ['one', 'two'], header, None,
                 body, [('x-digest', 'example')]),
                recorder.records[path],
            )

    def test_http2_content_length_and_trailers_stream_to_two_pools(self):
        path = '/both/http2?x=%2f&x=%20'
        body = bytes(range(256)) * 1600
        self.a.release.clear()
        self.b.release.clear()
        client = H2Connection(H2Configuration(header_encoding='utf-8'))
        with self.connect(self.h2_port) as sock:
            client.initiate_connection()
            client.send_headers(1, [
                (':method', 'POST'), (':scheme', 'http'),
                (':authority', 'test.example'), (':path', path),
                ('content-length', str(len(body))), ('trailer', 'x-digest'),
                ('x-repeat', 'one'), ('x-repeat', 'two'),
            ])
            sock.sendall(client.data_to_send())
            offset = 0
            while offset < len(body):
                count = min(4096, client.local_flow_control_window(1))
                if count <= 0:
                    data = sock.recv(65536)
                    self.assertTrue(data)
                    client.receive_data(data)
                    sock.sendall(client.data_to_send())
                    continue
                client.send_data(1, body[offset:offset + count])
                sock.sendall(client.data_to_send())
                offset += count
                time.sleep(.001)
            client.send_headers(1, [('x-digest', 'example')], end_stream=True)
            sock.sendall(client.data_to_send())

            finished = False
            response_headers = {}
            response_body = b''
            while not finished:
                data = sock.recv(65536)
                self.assertTrue(data)
                for event in client.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        response_headers.update(event.headers)
                    elif isinstance(event, DataReceived):
                        response_body += event.data
                        client.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        finished = True
                sock.sendall(client.data_to_send())
        self.assertEqual(('203', 'primary', b'primary'),
                         (response_headers[':status'],
                          response_headers['x-from'], response_body))
        wait_for(lambda: path in self.a.records and path in self.b.records)
        for recorder, header in ((self.a, 'before-a'), (self.b, 'before-b')):
            self.assertEqual(
                ('POST', 'test.example', ['one', 'two'], header, None,
                 body, [('x-digest', 'example')]),
                recorder.records[path],
            )

    def assert_backend_scheme(self, sock, scheme, path):
        client = H2Connection(H2Configuration(header_encoding='utf-8'))
        client.initiate_connection()
        client.send_headers(1, [
            (':method', 'GET'), (':scheme', scheme),
            (':authority', 'request.example'), (':path', path),
        ], end_stream=True)
        sock.sendall(client.data_to_send())
        while data := sock.recv(65536):
            for event in client.receive_data(data):
                if isinstance(event, ResponseReceived):
                    headers = dict(event.headers)
                    self.assertEqual('203', headers[':status'])
                    wait_for(lambda: path in self.h2_backend.records)
                    self.assertEqual(
                        (scheme, 'request.example'),
                        self.h2_backend.records[path],
                    )
                    return
            sock.sendall(client.data_to_send())
        self.fail('primary returned no HTTP/2 response')

    def test_http2_scheme_survives_private_http1_hop(self):
        with self.connect(self.h2_port) as sock:
            self.assert_backend_scheme(sock, 'http', '/scheme/h2c')
        with self.tls_connect('frontend.example', 'h2') as sock:
            self.assert_backend_scheme(sock, 'https', '/scheme/tls')
        with self.tls_connect('frontend.example', 'h2') as sock:
            self.assert_backend_scheme(sock, 'http', '/scheme/http-over-tls')

    def test_tls_mirror_sni_comes_from_tls_and_preserves_host(self):
        test_cases = (
            ('/sni/plain-tls', 'frontend.example', 'frontend.example'),
            ('/sni/plain-no-sni', None, None),
            ('/sni/fixed', 'frontend.example', 'verified.example'),
        )
        for path, frontend_sni, mirror_sni in test_cases:
            with self.subTest(path=path):
                with self.tls_connect(frontend_sni) as sock:
                    client = http.client.HTTPConnection('request.example')
                    client.sock = sock
                    client.request('GET', path, headers={
                        'Host': 'request.example',
                        'X-Forwarded-Host': 'header.example',
                        'X-Forwarded-Sni': 'header.example',
                    })
                    self.assert_primary(client.getresponse())
                wait_for(lambda: path in self.tls_mirror.records)
                for backend, expected_sni in (
                    (self.tls_primary, frontend_sni),
                    (self.tls_mirror, mirror_sni),
                ):
                    self.assertEqual(expected_sni, backend.snis[path])
                    self.assertEqual('request.example',
                                     backend.records[path][1])

    def test_zero_full_and_fraction_rates(self):
        zeros = [f'/zero/{i}' for i in range(40)]
        full = [f'/full/{i}' for i in range(40)]
        sample = [f'/sample/{i}' for i in range(600)]
        self.get(*zeros, *full, *sample)
        wait_for(lambda: self.counters()['active'] == 0)
        self.assertTrue(set(full).issubset(self.a.records))
        self.assertTrue(set(zeros).isdisjoint(self.a.records))
        for cardinality, lower, upper in (
            (len(set(sample) & self.a.records.keys()), 75, 165),
            (len(set(sample) & self.b.records.keys()), 245, 355),
        ):
            self.assertTrue(lower <= cardinality <= upper, cardinality)
        both = set(sample) & self.a.records.keys() & self.b.records.keys()
        self.assertGreater(len(both), 25)

    def test_incomplete_upload_is_cancelled(self):
        path = '/abort/upload'
        previous = self.counters()['incomplete_uploads']
        with self.connect() as sock:
            sock.sendall(
                f'POST {path} HTTP/1.1\r\nHost: test.example\r\n'
                'Transfer-Encoding: chunked\r\n\r\n'
                '8\r\npartial!\r\n'.encode()
            )
            wait_for(lambda: path in self.a.started)
        wait_for(lambda: self.counters()['incomplete_uploads'] == previous + 1)
        wait_for(lambda: path in self.a.incomplete)
        self.assertNotIn(path, self.a.records)

    def test_a_blocked_reader_does_not_fill_other_copy_queues(self):
        path = '/pressure/upload'
        body = bytes(range(256)) * 24576
        self.a.block_read = True
        self.a.release.clear()
        before = self.counters()['queue_drops']
        self.chunked(path, body, pace=.0005)
        wait_for(lambda: path in self.b.records)
        self.assertEqual(body, self.b.records[path][-2])
        self.assertEqual(before + 1, self.counters()['queue_drops'])
        self.a.release.set()
        wait_for(lambda: path in self.a.incomplete)
        self.assertNotIn(path, self.a.records)

    def test_active_copy_budget_is_reclaimed(self):
        self.a.release.clear()
        before = self.counters()
        paths = [f'/cap/{i}' for i in range(136)]
        with futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(
                lambda offset: self.get(*paths[offset::8]), range(8)))
        after = self.counters()
        self.assertEqual(128, after['active'])
        self.assertEqual(8, after['capacity_drops'] - before['capacity_drops'])
        self.a.release.set()
        wait_for(lambda: self.counters()['active'] == 0)
        self.get('/cap/recovered')
        wait_for(lambda: '/cap/recovered' in self.a.records)

    def test_config_requires_a_private_delivery_listener(self):
        check_path = self.root / 'missing-pool.cfg'
        path = f'{self.root}/{POOL_A}.sock mode 600 octavia-mirror-socket'
        check_path.write_text(self.config.read_text().replace(
            path, f'{self.root}/{POOL_A}.sock mode 600'))
        check = self.check_config(check_path)
        self.assertNotEqual(0, check.returncode)
        self.assertIn('no private delivery listener', check.stderr)

    def test_backend_rule_and_selected_server_use_frontend_filter(self):
        first = '/selected/a'
        second = '/selected/b'
        adjacent = '/adjacent/no-rule'
        body = b'backend selection\n' * 10000
        started = self.counters()['started']
        self.get(first, adjacent)
        with self.connect() as sock:
            sock.sendall(
                f'POST {second} HTTP/1.1\r\nHost: test.example\r\n'
                f'Content-Length: {len(body)}\r\n\r\n'.encode()
            )
            for offset in range(0, len(body), 4096):
                sock.sendall(body[offset:offset + 4096])
                time.sleep(.001)
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assert_primary(response, 'selected')
        wait_for(lambda: first in self.a.records and
                 second in self.a.records and second in self.b.records)
        self.assertEqual(started + 3, self.counters()['started'])
        self.assertIn(first, self.primary.records)
        self.assertNotIn(first, self.b.records)
        self.assertEqual(('rule', None, body, []), self.a.records[second][-4:])
        self.assertEqual(('selected', None, body, []),
                         self.b.records[second][-4:])
        self.assertEqual(('primary', None, body, []),
                         self.selected.records[second][-4:])
        self.assertNotIn(adjacent, self.a.records)
        self.assertNotIn(adjacent, self.b.records)

    def test_fixed_reply_keeps_complete_request_copy(self):
        path = '/fixed'
        body = b'complete request'
        self.a.release.clear()
        with self.connect() as sock:
            sock.sendall(
                f'POST {path} HTTP/1.1\r\nHost: test.example\r\n'
                f'Content-Length: {len(body)}\r\n\r\n'.encode() + body
            )
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual((202, b'local'),
                             (response.status, response.read()))
        wait_for(lambda: path in self.a.records)
        self.assertEqual(('fixed', None, body, []),
                         self.a.records[path][-4:])

    def test_zz_removed_filters_stop_new_copies_after_reload(self):
        self.a.release.clear()
        self.get('/cap/in-flight-on-reload')
        wait_for(lambda: '/cap/in-flight-on-reload' in self.a.records)
        self.assertEqual(1, self.counters()['active'])

        new_config = self.root / 'new.cfg'
        public_config = self.config.read_text().split('\nlisten delivery-')[0]
        new_config.write_text('\n'.join(
            line for line in public_config.splitlines()
            if 'filter octavia-mirror' not in line and
            'http-request octavia-mirror' not in line
        ) + '\n')
        cls = type(self)
        old_process = cls.process
        self.addCleanup(old_process.kill)
        new_process = cls.start(new_config, '-sf', str(old_process.pid))
        cls.process = new_process

        def reloaded():
            try:
                return self.counters()['started'] == 0
            except (ConnectionRefusedError, FileNotFoundError):
                return False

        wait_for(reloaded)
        self.get('/cap/after-reload')
        self.assertNotIn('/cap/after-reload', self.a.records)
        self.assertEqual(0, self.counters()['started'])
        self.a.release.set()
        self.assertEqual(0, old_process.wait(timeout=5))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy', type=Path)
    args, unittest_args = parser.parse_known_args()
    BINARY = str(args.haproxy.resolve())
    unittest.main(argv=['test-request-mirror.py', *unittest_args])
