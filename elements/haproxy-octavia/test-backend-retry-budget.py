#!/usr/bin/env python3
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Exercise shared retry admission with HTTP traffic on loopback."""

from collections import Counter
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest


class Origin(BaseHTTPRequestHandler):
    calls = Counter()

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.calls[self.path] += 1
        status = 200 if self.path.startswith('/ok-') else 500
        self.send_response(status)
        self.end_headers()


class BackendRetryBudgetTest(unittest.TestCase):
    def setUp(self):
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        worker = Thread(target=origin.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)
        Origin.calls.clear()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            self.port = reserved.getsockname()[1]

        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        config = Path(directory.name) / 'haproxy.cfg'
        config.write_text(f"""global
    nbthread 2

defaults
    mode http
    timeout client 2s
    timeout server 2s
    timeout connect 1s

frontend ingress
    bind 127.0.0.1:{self.port}
    use_backend shared_a if {{ path_beg /a- }}
    use_backend shared_b if {{ path_beg /b- }}
    use_backend other if {{ path_beg /other- }}
    use_backend ordinary if {{ path_beg /ordinary- }}
    default_backend percentage
""" + ''.join(
            f'\nbackend {pool}\n{budget}'
            '    http-request octavia-http-policy default default 3 500\n'
            f'    server origin 127.0.0.1:{origin.server_port}\n'
            for pool, budget in (
                ('shared_a', self.budget('same-service', 0, 2)),
                ('shared_b', self.budget('same-service', 0, 2)),
                ('other', self.budget('another-service', 0, 2)),
                ('percentage', self.budget('percent-service', 20, 1)),
                ('ordinary', ''))), encoding='utf-8')
        subprocess.run([HAPROXY, '-c', '-f', config], check=True,
                       stdout=subprocess.DEVNULL)
        self.proxy = subprocess.Popen([HAPROXY, '-db', '-f', config])
        self.addCleanup(self.stop_proxy)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', self.port), 0.1):
                    return
            except OSError:
                if self.proxy.poll() is not None:
                    break
                time.sleep(0.01)
        self.fail('HAProxy did not start')

    @staticmethod
    def budget(service, percent, minimum):
        return (f'    http-request octavia-retry-budget {service} {percent} '
                f'5000 {minimum} 1000\n')

    def stop_proxy(self):
        self.proxy.terminate()
        self.proxy.wait(timeout=3)

    def get(self, path):
        connection = HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            connection.request('GET', path)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_pools_share_successive_retries_and_recover_independently(self):
        for path, expected_status, upstream_attempts in (
                ('/a-fail', 503, 3), ('/b-fail', 503, 1),
                ('/other-fail', 503, 3), ('/ordinary-fail', 500, 4)):
            with self.subTest(path=path):
                self.assertEqual(expected_status, self.get(path))
                self.assertEqual(upstream_attempts, Origin.calls[path])
        time.sleep(1.05)
        self.assertEqual(503, self.get('/b-recovered'))
        self.assertEqual(3, Origin.calls['/b-recovered'])

    def test_percentage_includes_healthy_original_requests(self):
        for index in range(8):
            self.assertEqual(200, self.get(f'/ok-{index}'))
        # Nine originals and two retries are below 20 percent. A third
        # retry would make three of the twelve attempts retries.
        self.assertEqual(503, self.get('/percent-fail'))
        self.assertEqual(3, Origin.calls['/percent-fail'])


if __name__ == '__main__':
    HAPROXY = str(Path(sys.argv.pop(1)).resolve())
    unittest.main()
