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
from concurrent.futures import ThreadPoolExecutor
import csv
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


class Origin(BaseHTTPRequestHandler):
    calls = Counter()
    mirror_delivered = Event()
    delayed_response = Event()

    def log_message(self, *args):
        pass

    def do_GET(self):
        mirrored = self.headers.get('X-Test-Delivery') == 'mirror'
        key = ('mirrored', self.path) if mirrored else self.path
        self.calls[key] += 1
        origin = self.headers.get('X-Test-Origin')
        if origin:
            self.calls[origin, self.path] += 1
        status = 200 if self.path.startswith('/ok-') else 500
        if self.path == '/wait' and self.calls[key] > 1:
            status = 200
        self.send_response(status)
        self.end_headers()
        if self.path == '/wait' and status == 500:
            self.delayed_response.set()
        if mirrored:
            self.mirror_delivered.set()


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
        self.stats_socket = Path(directory.name) / 'stats.sock'
        mirror_pool = '8f388635-d55a-4f89-9937-a7550b72e710'
        config = Path(directory.name) / 'haproxy.cfg'
        mirror_budget = self.budget('mirror-service', 20, 1)
        config.write_text(f"""global
    nbthread 2
    stats socket {self.stats_socket}

defaults
    mode http
    timeout client 2s
    timeout server 2s
    timeout connect 1s

frontend ingress
    bind 127.0.0.1:{self.port}
    filter octavia-mirror {directory.name}
    http-request octavia-mirror {mirror_pool} 1 1 if {{ path_beg /copy- }}
    use_backend delayed if {{ path /wait /cancel /ok-neighbor }}
    use_backend redispatch if {{ path /redispatch-wait }}
    use_backend wide if {{ path_beg /ok- /wide- }}
    use_backend copy_target if {{ path_beg /mirror-target }}
    use_backend source if {{ path_beg /copy- }}
    use_backend shared_a if {{ path_beg /a- }}
    use_backend shared_b if {{ path_beg /b- }}
    use_backend other if {{ path_beg /other- }}
    use_backend ordinary if {{ path_beg /ordinary- }}
    default_backend percentage

listen octavia-mirror-{mirror_pool}
    bind {directory.name}/{mirror_pool}.sock mode 600 octavia-mirror-socket
    retries 0
    no option redispatch
    http-request disable-l7-retry
{mirror_budget}    http-request set-header X-Test-Delivery mirror
    server origin 127.0.0.1:{origin.server_port}

backend source
    retries 0
    server origin 127.0.0.1:{origin.server_port}

backend delayed
    timeout queue 200ms
    http-request octavia-http-policy 1800 500 1 500 600 if {{ path /wait }}
    http-request octavia-http-policy 250 150 1 500 600 if {{ path /cancel }}
    server origin 127.0.0.1:{origin.server_port} maxconn 1

backend redispatch
    option redispatch 1
    http-request octavia-http-policy 1800 500 1 500 600
    http-send-name-header X-Test-Origin
    use-server origin if {{ path /redispatch-wait }}
    server origin 127.0.0.1:{origin.server_port}
    server alternate 127.0.0.1:{origin.server_port}
""" + ''.join(
            f'\nbackend {pool}\n{budget}'
            '    http-request octavia-http-policy default default 3 500\n'
            f'    server origin 127.0.0.1:{origin.server_port}\n'
            for pool, budget in (
                ('shared_a', self.budget('same-service', 0, 2)),
                ('shared_b', self.budget('same-service', 0, 2)),
                ('other', self.budget('another-service', 0, 2)),
                ('wide', self.budget('percent-service', 100, 1)),
                ('percentage', self.budget('percent-service', 20, 1)),
                ('copy_target', mirror_budget),
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

    def retry_counters(self, backend):
        with socket.socket(socket.AF_UNIX) as stats:
            stats.settimeout(2)
            stats.connect(str(self.stats_socket))
            stats.sendall(b'show stat\n')
            with stats.makefile(encoding='utf-8') as rows:
                return {
                    row['svname']: (int(row['wretr']), int(row['wredis']))
                    for row in csv.DictReader(rows)
                    if row['# pxname'] == backend
                }

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
        # Originals reaching the 100 percent pool still count in the
        # sibling pool's 20 percent window.
        # Nine originals and two retries are below 20 percent. A third
        # retry would make three of the twelve attempts retries.
        self.assertEqual(503, self.get('/percent-fail'))
        self.assertEqual(3, Origin.calls['/percent-fail'])

    def test_retries_from_a_pool_with_no_percentage_limit_count_for_siblings(
            self):
        self.assertEqual(500, self.get('/wide-fail'))
        self.assertEqual(4, Origin.calls['/wide-fail'])
        self.assertEqual(503, self.get('/percent-fail'))
        self.assertEqual(1, Origin.calls['/percent-fail'])

    def test_mirror_delivery_counts_toward_the_destination_budget(self):
        paths = [f'/copy-{index}' for index in range(7)]
        for path in paths:
            Origin.mirror_delivered.clear()
            self.assertEqual(500, self.get(path))
            self.assertTrue(Origin.mirror_delivered.wait(timeout=1))
        # Seven mirror originals plus one direct request allow exactly
        # two retries at 20 percent, even though the minimum is one.
        self.assertEqual(503, self.get('/mirror-target'))
        self.assertEqual(3, Origin.calls['/mirror-target'])
        for path in paths:
            self.assertEqual(1, Origin.calls['mirrored', path])

    def test_retry_wait_releases_server_for_neighbor(self):
        Origin.delayed_response.clear()
        with ThreadPoolExecutor(max_workers=1) as requests:
            retried = requests.submit(self.get, '/wait')
            self.assertTrue(Origin.delayed_response.wait(timeout=1))
            self.assertEqual(200, self.get('/ok-neighbor'))
            self.assertEqual(200, retried.result(timeout=2))
        self.assertEqual(1, Origin.calls['/ok-neighbor'])
        self.assertEqual(2, Origin.calls['/wait'])

    def test_retry_wait_counts_only_admitted_http_retries(self):
        self.assertEqual({'BACKEND': (0, 0), 'origin': (0, 0)},
                         self.retry_counters('delayed'))
        self.assertEqual(504, self.get('/cancel'))
        self.assertEqual(1, Origin.calls['/cancel'])
        self.assertEqual({'BACKEND': (0, 0), 'origin': (0, 0)},
                         self.retry_counters('delayed'))

        self.assertEqual(200, self.get('/wait'))
        self.assertEqual(2, Origin.calls['/wait'])
        self.assertEqual(1, Origin.calls['/cancel'])
        # HAProxy counts the HTTP replay and the retry on the same server.
        self.assertEqual({'BACKEND': (2, 0), 'origin': (2, 0)},
                         self.retry_counters('delayed'))

    def test_retry_wait_attributes_http_redispatch_to_original_server(self):
        self.assertEqual(500, self.get('/redispatch-wait'))
        self.assertEqual(1, Origin.calls['origin', '/redispatch-wait'])
        self.assertEqual(1, Origin.calls['alternate', '/redispatch-wait'])
        self.assertEqual({'BACKEND': (1, 1), 'origin': (1, 1),
                          'alternate': (0, 0)},
                         self.retry_counters('redispatch'))


if __name__ == '__main__':
    HAPROXY = str(Path(sys.argv.pop(1)).resolve())
    unittest.main()
