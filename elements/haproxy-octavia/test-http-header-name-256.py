#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise exact HTTP header matching, forwarding and cache hits."""

import argparse
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest


NAMES = {length: 'x-' + 'a' * (length - 2) for length in (255, 256, 257)}


class Origin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(200)
        for name in NAMES.values():
            value = self.headers.get(name)
            if value is not None:
                self.send_header(name, value)
        if self.path.startswith('/cache/'):
            self.send_header(NAMES[256], 'cached')
            self.send_header('Cache-Control', 'public, max-age=60')
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()

    def log_message(self, *_):
        pass


class HeaderNameTest(unittest.TestCase):
    def setUp(self):
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        self.addCleanup(origin.server_close)
        origin.requests = []
        Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.shutdown)
        self.origin = origin

    def start_proxy(self, enabled):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = Path(tmp.name) / 'haproxy.cfg'
        with socket.socket() as http1, socket.socket() as http2:
            for listener in (http1, http2):
                listener.bind(('127.0.0.1', 0))
            self.ports = {
                '1.1': http1.getsockname()[1], '2': http2.getsockname()[1],
            }
        tuning = '  tune.octavia.http-header-name-256' if enabled else ''
        config.write_text(f'''global
  nbthread 1
{tuning}
defaults
  mode http
  timeout connect 2s
  timeout client 2s
  timeout server 2s
frontend edge
  bind 127.0.0.1:{self.ports['1.1']}
  bind 127.0.0.1:{self.ports['2']} proto h2
  acl cached path_beg /cache/
  acl matches req.fhdr({NAMES[255]}) -m bin 796573
  acl matches req.fhdr({NAMES[256]}) -m bin 796573
  http-request deny deny_status 404 unless matches or cached
  http-request replace-header {NAMES[255]} ^yes$ forwarded
  http-request replace-header {NAMES[256]} ^yes$ forwarded
  use_backend cached if cached
  default_backend live
backend live
  server origin 127.0.0.1:{self.origin.server_port}
backend cached
  http-request cache-use header_cache
  http-response cache-store header_cache
  server origin 127.0.0.1:{self.origin.server_port}
cache header_cache
  total-max-size 1
  max-object-size 4096
  max-age 60
''', encoding='ascii')
        subprocess.run([BINARY, '-c', '-f', config], check=True)
        process = subprocess.Popen([BINARY, '-db', '-f', config])
        self.addCleanup(process.wait, timeout=5)
        self.addCleanup(process.terminate)
        for _ in range(100):
            if process.poll() is not None:
                self.fail(f'HAProxy exited with {process.returncode}')
            try:
                with socket.create_connection(
                        ('127.0.0.1', self.ports['1.1']), timeout=0.1):
                    return
            except ConnectionRefusedError:
                time.sleep(0.02)
        self.fail('HAProxy did not start')

    def request(self, protocol, name=None, value=None, path='/route'):
        options = {'1.1': '--http1.1', '2': '--http2-prior-knowledge'}
        command = [
            'curl', options[protocol], '--silent', '--show-error',
            '--noproxy', '*',
            '--max-time', '3', '--dump-header', '-', '--output', '/dev/null',
            '--write-out', '%{http_version} %{http_code}',
            '--header', 'Host: example.test',
        ]
        if name is not None:
            command.extend(('--header', f'{name}: {value}'))
        response = subprocess.run(
            [*command, f'http://127.0.0.1:{self.ports[protocol]}{path}'],
            text=True, capture_output=True, timeout=5,
        )
        headers, _, outcome = response.stdout.rpartition('\n')
        return response, headers.splitlines(), outcome

    def check_routes(self, enabled):
        for protocol in self.ports:
            for length, name in NAMES.items():
                values = ('yes',) if length == 257 else ('yes', 'Yes')
                for value in values:
                    with self.subTest(protocol=protocol, length=length,
                                      value=value):
                        hits = len(self.origin.requests)
                        res, headers, outcome = self.request(
                            protocol, name, value)
                        admitted = length <= 255 or (length == 256 and enabled)
                        if not admitted and protocol == '2':
                            self.assertEqual(92, res.returncode, res.stderr)
                            self.assertEqual('000', outcome.split()[-1])
                        else:
                            expected = 200 if value == 'yes' else 404
                            if not admitted:
                                expected = 400
                            self.assertEqual(0, res.returncode, res.stderr)
                            self.assertEqual(f'{protocol} {expected}', outcome)
                            if expected == 200:
                                self.assertIn(f'{name}: forwarded', headers)
                        expected_hits = int(admitted and value == 'yes')
                        self.assertEqual(hits + expected_hits,
                                         len(self.origin.requests))

    def test_default(self):
        self.start_proxy(enabled=False)
        self.check_routes(enabled=False)

    def test_opt_in(self):
        self.start_proxy(enabled=True)
        self.check_routes(enabled=True)

    def test_cached_header(self):
        self.start_proxy(enabled=True)
        for protocol in self.ports:
            with self.subTest(protocol=protocol):
                path = f'/cache/{protocol}'
                for _ in range(2):
                    res, headers, outcome = self.request(protocol, path=path)
                    self.assertEqual(0, res.returncode, res.stderr)
                    self.assertEqual(f'{protocol} 200', outcome)
                    self.assertIn(f'{NAMES[256]}: cached', headers)
                    self.assertEqual(1, self.origin.requests.count(path))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy', type=Path)
    args, unittest_args = parser.parse_known_args()
    BINARY = str(args.haproxy.resolve())
    unittest.main(argv=[__file__, *unittest_args])
