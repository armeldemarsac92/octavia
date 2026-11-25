#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the rendered Amphora listener auth config against HAProxy."""

from contextlib import closing
from contextlib import ExitStack
from contextlib import suppress
import getpass
import http.client
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

from oslo_config import cfg

from octavia.amphorae.backends.agent.api_server import haproxy_compatibility
from octavia.amphorae.driver_exceptions import exceptions
from octavia.common import constants as c
from octavia.common import data_models as dm
from octavia.common.jinja.haproxy.combined_listeners import jinja_cfg


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_PATCH(self):
        request = {
            'method': self.command,
            'path': self.path,
            'headers': {name.lower(): value
                        for name, value in self.headers.items()},
            'body': self.rfile.read(
                int(self.headers.get('content-length', '0'))).decode(),
        }
        self.server.requests.append(request)
        if self.server.label != 'auth':
            request['route'] = self.server.label
            payload = json.dumps(request).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == '/first/slow':
            time.sleep(4)
        self.send_response(401 if self.path == '/first/deny' else 200)
        self.send_header('Host', 'other.example')
        self.send_header('X-Hidden', 'do-not-copy')
        self.send_header('X-Identity', 'verified' if
                         self.path.startswith('/second/') else 'first')
        self.send_header('Content-Length', '0')
        # A timed-out authorization has already closed this socket.
        with suppress(ConnectionResetError, BrokenPipeError):
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class TestListenerAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.path = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        cls.project = str(uuid.uuid4())
        cls.lb = dm.LoadBalancer(
            id='lb', project_id=cls.project, enabled=True,
            vip=dm.Vip(ip_address='127.0.0.1'),
            topology=c.TOPOLOGY_SINGLE)
        cls.amp = dm.Amphora(id='test', status=c.AMPHORA_ALLOCATED)
        cls.auth = cls.pool(stack, 'auth', auth=True)
        cls.fallback = cls.pool(stack, 'fallback')
        cls.selected = cls.pool(stack, 'selected')
        cls.empty = cls.pool(stack, 'empty', auth=True, running=False)

        def step(pool, prefix, request_headers=None):
            return dict(type='ExternalAuth', http=dict(
                pool_id=pool, path_prefix=prefix,
                allowed_request_headers=request_headers or [],
                allowed_response_headers=['x-identity', 'host',
                                          'content-length']))

        chain = [step(cls.auth.id, '/first', ['x-client']),
                 step(cls.auth.id, '/second', ['x-identity'])]
        sections = [
            {'hostname': '*', 'requests': chain},
            {'hostname': '*.example', 'reject': True},
            {'hostname': '*.public.example'},
            {'hostname': 'auth.example', 'requests': chain},
            {'hostname': 'public.example'},
            {'hostname': 'missing.example',
             'requests': [step(str(uuid.uuid4()), '/missing')]},
            {'hostname': 'empty.example',
             'requests': [step(cls.empty.id, '/empty')]},
        ]
        http = cls.listener('web', c.PROTOCOL_HTTP)
        http.request_filter_sections = sections
        tls = cls.listener('tls', c.PROTOCOL_TERMINATED_HTTPS)
        tls.tls_certificate_id = 'test-cert'
        tls.request_filter_sections = [
            section for section in sections if section['hostname'] != '*']
        ordinary = cls.listener('ordinary', c.PROTOCOL_HTTP)
        cls.lb.listeners = [http, tls, ordinary]
        cls.lb.pools = [cls.auth, cls.selected, cls.fallback, cls.empty]
        cls.web, cls.tls, cls.ordinary = (
            listener.protocol_port for listener in cls.lb.listeners)
        config = cfg.CONF
        config.set_override('base_cert_dir', str(cls.path),
                            group='haproxy_amphora')
        stack.callback(config.clear_override, 'base_cert_dir',
                       group='haproxy_amphora')
        cls.cert()

        cfg_path = cls.path / 'haproxy.cfg'
        templater = jinja_cfg.JinjaTemplater(
            base_amp_path=str(cls.path), connection_logging=False)
        render = dict(tls_certs=None, socket_path=str(cls.path / 'stats.sock'),
                      haproxy_versions=['3', '0', '19'])
        config.set_override('haproxy_cmd', HAPROXY, group='haproxy_amphora')
        stack.callback(config.clear_override, 'haproxy_cmd',
                       group='haproxy_amphora')
        details = haproxy_compatibility.get_haproxy_capabilities()
        assert details.get(c.GATEWAY_CAPABILITY_LISTENER_REQUEST_FILTERS)
        try:
            templater.build_config(cls.amp, cls.lb.listeners,
                                   amp_details={}, **render)
        except exceptions.AmpVersionUnsupported:
            pass
        else:
            message = 'a listener with auth requires the Amphora capability'
            raise AssertionError(message)
        templater.build_config(cls.amp, [ordinary], amp_details={}, **render)

        exact = templater.build_config(
            cls.amp, cls.lb.listeners, amp_details=details, **render)
        cfg_path.write_text(exact)
        subprocess.run([HAPROXY, '-c', '-f', str(cfg_path)], check=True)
        cfg_path.write_text(exact.replace(
            '/run/octavia/listener-auth', str(cls.path)).replace(
                'user nobody', f'user {getpass.getuser()}'))
        proxy = stack.enter_context(subprocess.Popen(
            [HAPROXY, '-db', '-f', str(cfg_path)]))
        stack.callback(proxy.terminate)
        deadline = time.monotonic() + 5
        while not (cls.path / f'{cls.auth.id}.sock').exists():
            if proxy.poll() is not None or time.monotonic() > deadline:
                message = 'HAProxy did not start'
                raise AssertionError(message)
            time.sleep(0.05)

    @classmethod
    def pool(cls, stack, label, auth=False, running=True):
        pool_id = str(uuid.uuid4())
        members = []
        if running:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.label = label
            server.requests = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
            if auth:
                cls.auth_requests = server.requests
            members.append(dm.Member(
                id=str(uuid.uuid4()), pool_id=pool_id, weight=1, enabled=True,
                ip_address='127.0.0.1', protocol_port=server.server_port))
        return dm.Pool(
            id=pool_id, load_balancer_id=cls.lb.id, project_id=cls.project,
            protocol=c.PROTOCOL_HTTP, lb_algorithm=c.LB_ALGORITHM_ROUND_ROBIN,
            enabled=True, members=members, tls_enabled=False,
            tags=[c.GATEWAY_LISTENER_AUTH_POOL_TAG] if auth else [])

    @classmethod
    def listener(cls, listener_id, protocol):
        return dm.Listener(
            id=listener_id, protocol=protocol, protocol_port=unused_port(),
            project_id=cls.project, enabled=True, load_balancer=cls.lb,
            load_balancer_id=cls.lb.id, pools=[cls.fallback, cls.selected],
            default_pool=cls.fallback, default_pool_id=cls.fallback.id,
            l7policies=[dm.L7Policy(
                id=f'{listener_id}-route', enabled=True,
                action=c.L7POLICY_ACTION_REDIRECT_TO_POOL,
                redirect_pool=cls.selected, redirect_pool_id=cls.selected.id,
                l7rules=[dm.L7Rule(
                    id=f'{listener_id}-identity', enabled=True, invert=False,
                    type=c.L7RULE_TYPE_HTTP_HEADER_EXACT,
                    compare_type=c.L7RULE_COMPARE_TYPE_EQUAL_TO,
                    key='x-identity', value='verified')])])

    @classmethod
    def cert(cls):
        cert_dir = cls.path / cls.lb.id
        cert_dir.mkdir()
        key, cert = cert_dir / 'key', cert_dir / 'cert'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'ec',
            '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
            '-subj', '/CN=auth.example', '-keyout', str(key), '-out', str(cert)
        ], capture_output=True, check=True)
        combined = cert_dir / 'server.pem'
        combined.write_bytes(key.read_bytes() + cert.read_bytes())
        (cert_dir / 'tls.pem').write_text(str(combined) + '\n')

    def request(self, host, path='/catalog?kind=1', port=None, tls=False):
        port = port or self.web
        if tls:
            connection = http.client.HTTPSConnection(
                'auth.example', port, context=ssl._create_unverified_context(),
                timeout=6)
            connection._create_connection = (
                lambda address, timeout, source_address:
                socket.create_connection(('127.0.0.1', port), timeout))
        else:
            connection = http.client.HTTPConnection(
                '127.0.0.1', port, timeout=6)
        with closing(connection):
            connection.request('PATCH', path, body=b'body', headers={
                'Host': host, 'Authorization': 'Bearer sample',
                'X-Client': 'forward-me', 'X-Not-Allowed': 'not-forwarded'})
            response = connection.getresponse()
            payload = response.read()
        return (response.status,
                json.loads(payload) if response.status == 200 else None)

    def test_authorization_chain_precedes_route_and_preserves_request(self):
        self.auth_requests.clear()
        status, app = self.request('auth.example:80')
        self.assertEqual(200, status)
        self.assertEqual('selected', app['route'])
        self.assertEqual('/catalog?kind=1', app['path'])
        self.assertEqual('body', app['body'])
        self.assertEqual('auth.example:80', app['headers']['host'])
        self.assertNotIn('x-hidden', app['headers'])

        first, second = self.auth_requests
        self.assertEqual(['/first/catalog?kind=1', '/second/catalog?kind=1'],
                         [item['path'] for item in (first, second)])
        for item in (first, second):
            self.assertEqual('PATCH', item['method'])
            self.assertEqual('auth.example:80', item['headers']['host'])
            self.assertEqual('Bearer sample', item['headers']['authorization'])
            self.assertEqual('0', item['headers']['content-length'])
            self.assertEqual('', item['body'])
            self.assertNotIn('x-not-allowed', item['headers'])
        self.assertEqual('forward-me', first['headers']['x-client'])
        self.assertEqual('first', second['headers']['x-identity'])
        self.assertNotIn('x-client', second['headers'])

    def test_priority_and_unfiltered_sections(self):
        self.auth_requests.clear()
        self.assertEqual(403, self.request('blocked.example')[0])
        self.assertEqual('fallback',
                         self.request('public.example')[1]['route'])
        self.assertEqual('fallback',
                         self.request('deep.public.example')[1]['route'])
        self.assertEqual('fallback', self.request(
            'blocked.example', port=self.ordinary)[1]['route'])
        self.assertEqual([], self.auth_requests)
        self.assertEqual('selected', self.request('default.test')[1]['route'])
        self.assertEqual('selected', self.request(
            'public.example', port=self.tls, tls=True)[1]['route'])

    def test_named_tls_sections_require_selection_before_routing(self):
        text = (self.path / 'haproxy.cfg').read_text()
        frontend = text.split('\nfrontend tls\n', 1)[1].split(
            '\nfrontend ', 1)[0]
        guard = frontend.index(
            'http-request return status 421 unless '
            '{ var(txn.octavia_auth_section) -m found }')
        self.assertLess(frontend.index('set-var(txn.octavia_auth_section)'),
                        guard)
        self.assertLess(guard, frontend.index('http-request octavia-auth '))
        self.assertLess(guard, frontend.index('use_backend '))

    def test_https_h2_preserves_original_authority(self):
        self.auth_requests.clear()
        result = subprocess.run([
            'curl', '--silent', '--show-error', '--fail', '--insecure',
            '--noproxy', '*', '--http2', '--request', 'PATCH',
            '--header', 'Host: public.example',
            '--resolve', f'auth.example:{self.tls}:127.0.0.1',
            '--write-out', '\n%{http_version}',
            f'https://auth.example:{self.tls}/catalog',
        ], capture_output=True, text=True, check=True)
        payload, version = result.stdout.rsplit('\n', 1)
        self.assertEqual('2', version)
        app = json.loads(payload)
        self.assertEqual('selected', app['route'])
        self.assertEqual('public.example', app['headers']['host'])
        self.assertEqual(['public.example', 'public.example'], [
            item['headers']['host'] for item in self.auth_requests])

    def test_failures_stop_before_routing(self):
        self.auth_requests.clear()
        self.assertEqual(401, self.request('auth.example', '/deny')[0])
        self.assertEqual(['/first/deny'],
                         [item['path'] for item in self.auth_requests])
        self.assertEqual(503, self.request('missing.example')[0])
        self.assertEqual(503, self.request('empty.example')[0])
        self.assertEqual(503, self.request('auth.example', '/slow')[0])


if __name__ == '__main__':
    HAPROXY = str(Path(sys.argv.pop(1)).resolve())
    unittest.main()
