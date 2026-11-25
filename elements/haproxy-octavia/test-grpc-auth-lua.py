#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the gRPC authorization Lua actions with native HAProxy."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
from socketserver import ThreadingUnixStreamServer
import subprocess
from tempfile import TemporaryDirectory
from threading import Event
from threading import Thread
import time
from urllib.parse import parse_qs
from urllib.parse import urlencode


POOL = '67e0fff4-9150-4a96-a1dd-9d0208bc6d24'
FORM_TYPE = 'application/x-www-form-urlencoded'
SCRIPT = Path(__file__).with_name('octavia-grpc-auth.lua')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status, body, headers=(), *, length=None):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body) if length is None
                                               else length))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def request_body(self):
        if self.headers.get('Transfer-Encoding') != 'chunked':
            return self.rfile.read(int(self.headers['Content-Length']))
        chunks = []
        while size := int(self.rfile.readline(), 16):
            chunks.append(self.rfile.read(size))
            assert self.rfile.read(2) == b'\r\n'
        assert self.rfile.read(2) == b'\r\n'
        return b''.join(chunks)


def start_server(stack, server):
    stack.enter_context(server)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(thread.join, 5)
    stack.callback(server.shutdown)
    return server


def request(port, target, body=b'', *, method='POST'):
    conn = HTTPConnection('127.0.0.1', port, timeout=6)
    try:
        conn.putrequest(method, target, skip_host=True,
                        skip_accept_encoding=True)
        conn.putheader('Host', 'route.example:8443')
        conn.putheader('Content-Length', str(len(body)))
        conn.putheader('X-Selected', 'space + plus% percent')
        conn.putheader('X-Selected', 'two')
        conn.putheader('X-Selected!', 'punctuation')
        conn.putheader('X-Private', 'private')
        conn.putheader('X-Delete', 'delete')
        conn.endheaders(body)
        response = conn.getresponse()
        return response.status, response.headers, response.read()
    finally:
        conn.close()


def haproxy_config(frontend, h2_port, origin, adapter):
    selected = b'x-selected,x-selected!'.hex()
    authority = b':authority'.hex()
    return f"""
global
    nbthread 2
    httpclient.retries 0
    httpclient.timeout.connect 3s
    lua-load-per-thread {SCRIPT} {adapter}
defaults
    mode http
    timeout connect 1s
    timeout client 8s
    timeout server 8s
listen gateway
    bind 127.0.0.1:{frontend}
    bind 127.0.0.1:{h2_port} proto h2
    acl full path /all-headers
    acl auth path /authority
    acl allowed var(txn.octavia_grpc_auth_allowed) -m bool
    acl denied var(txn.octavia_grpc_auth_denied) -m bool
    acl applied var(txn.octavia_grpc_auth_response_applied) -m bool
    http-request lua.octavia-grpc-auth {POOL} - if full
    http-request lua.octavia-grpc-auth {POOL} {authority} if auth
    http-request lua.octavia-grpc-auth {POOL} {selected} unless full or auth
    http-request use-service lua.octavia-grpc-auth-denial if denied
    http-request return status 503 unless allowed
    http-request return status 500 if {{ path /local }}
    http-response lua.octavia-grpc-auth-response if allowed
    http-response return status 503 if allowed !applied
    http-after-response lua.octavia-grpc-auth-response if allowed !applied
    http-after-response set-status 503 if allowed !applied
    server origin 127.0.0.1:{origin}
"""


def run(binary):
    checks = []
    upstream = []
    slow_received = Event()
    release_slow = Event()
    denial_body = b'Access denied.\n' * 3000
    form_headers = [('Content-Type', FORM_TYPE)]

    class Adapter(Handler):
        def do_POST(self):
            assert self.path == f'/v1/check/{POOL}'
            assert self.headers['Content-Type'] == FORM_TYPE
            raw = self.request_body()
            check = parse_qs(raw, keep_blank_values=True, strict_parsing=True)
            checks.append(check)
            path = check[b'path'][0]
            if path == b'/slow':
                slow_received.set()
                release_slow.wait(6)
                return
            if path == b'/deny':
                fields = [
                    ('decision', 'deny'), ('status', '401'),
                    ('body', denial_body), ('set.www-authenticate', 'Bearer'),
                    ('add.set-cookie', 'error=1'),
                    ('add.set-cookie', 'attempt=2'),
                ]
            elif path == b'/malformed':
                self.reply(200, b'decision=allow&response.set.x-bad=%0d%0a',
                           form_headers)
                return
            elif path == b'/truncated':
                self.reply(200, b'decision=allow', form_headers, length=128)
                return
            else:
                query = ('k=one+two&raw=%2F'
                         if path != b'/all-headers?sole' else '')
                fields = [
                    ('decision', 'allow'), ('remove', 'x-delete'),
                    ('ifpresent.x-delete', 'still-absent'),
                    ('set.x-auth', 'first'), ('ifabsent.x-auth', 'ignored'),
                    ('add.x-auth', 'second'), ('ifabsent.x-new', 'fresh'),
                    ('ifpresent.x-new', 'updated'),
                    ('query', query),
                    ('response.ifpresent.x-origin', 'replaced'),
                    ('response.add.set-cookie', 'access=1'),
                    ('response.add.set-cookie', 'source=2'),
                ]
            self.reply(200, urlencode(fields).encode(), form_headers)

    class Origin(Handler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            upstream.append((self.path, self.headers, body))
            self.reply(200, body, [('X-Origin', 'original')])

    with ExitStack() as stack:
        stage = Path(stack.enter_context(TemporaryDirectory(prefix='ga-')))
        adapter_path = stage / 'adapter.sock'
        start_server(stack,
                     ThreadingUnixStreamServer(str(adapter_path), Adapter))
        origin = start_server(
            stack, ThreadingHTTPServer(('127.0.0.1', 0), Origin))
        with (socket.create_server(('127.0.0.1', 0)) as listener,
              socket.create_server(('127.0.0.1', 0)) as h2_listener):
            port = listener.getsockname()[1]
            h2_port = h2_listener.getsockname()[1]
        cfg = stage / 'haproxy.cfg'
        cfg.write_text(haproxy_config(port, h2_port, origin.server_port,
                                      adapter_path))

        with (stage / 'haproxy.log').open('w+') as log:
            proxy = subprocess.Popen([binary, '-db', '-f', cfg],
                                     stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    assert proxy.poll() is None, proxy.returncode
                    try:
                        with socket.create_connection(('127.0.0.1', port),
                                                      timeout=0.1):
                            break
                    except ConnectionRefusedError:
                        time.sleep(0.02)
                else:
                    raise TimeoutError(('127.0.0.1', port))

                body = b'primary binary request\0\xff'
                status, headers, echoed = request(
                    port, '/allow?q=literal%2B+', body)
                assert status == 200 and echoed == body, status
                assert headers.get_all('Set-Cookie') == [
                    'access=1', 'source=2']
                assert headers['X-Origin'] == 'replaced'
                assert checks[0] == {
                    b'method': [b'POST'], b'path': [b'/allow?q=literal%2B+'],
                    b'host': [b'route.example:8443'], b'scheme': [b'http'],
                    b'protocol': [b'HTTP/1.1'],
                    b'h.x-selected': [b'space + plus% percent', b'two'],
                    b'h.x-selected!': [b'punctuation'],
                }, checks[0]
                path, sent_headers, sent_body = upstream[0]
                assert path == '/allow?k=one+two&raw=%2F' and sent_body == body
                assert sent_headers.get_all('X-Auth') == ['first', 'second']
                assert sent_headers['X-New'] == 'updated'
                assert sent_headers['X-Delete'] is None

                assert request(port, '/all-headers?sole')[0] == 200
                assert checks[1][b'h.x-private'] == [b'private']
                assert checks[1][b'h.host'] == [b'route.example:8443']
                assert upstream[1][0] == '/all-headers'

                status, headers, denied = request(port, '/deny')
                assert status == 401 and denied == denial_body
                assert headers['WWW-Authenticate'] == 'Bearer'
                assert headers.get_all('Set-Cookie') == [
                    'error=1', 'attempt=2']
                status, headers, denied = request(port, '/deny', method='HEAD')
                assert status == 401 and not denied
                assert headers['Content-Length'] == str(len(denial_body))
                assert request(port, '/malformed')[0] == 503
                assert request(port, '/truncated')[0] == 503
                assert len(upstream) == 2

                with ThreadPoolExecutor(max_workers=1) as executor:
                    started = time.monotonic()
                    stalled = executor.submit(request, port, '/slow')
                    try:
                        assert slow_received.wait(1)
                        assert request(port, '/all-headers?sole')[0] == 200
                        assert not stalled.done()
                        assert stalled.result(timeout=4)[0] == 503
                        elapsed = time.monotonic() - started
                        assert 2.5 <= elapsed <= 3.8, elapsed
                    finally:
                        release_slow.set()
                status, headers, _ = request(port, '/local')
                assert status == 500
                assert headers.get_all('Set-Cookie') == [
                    'access=1', 'source=2']
                h2_reply = subprocess.check_output([
                    'curl', '--http2-prior-knowledge', '--max-time', '6',
                    '-sS', '-o', '/dev/null', '-w',
                    '%{http_version} %{http_code}',
                    '-H', 'Host: route.example:8443', '--data', '',
                    f'http://127.0.0.1:{h2_port}/authority'], text=True)
                assert h2_reply == '2 200', h2_reply
                actual = {k: v for k, v in checks[-1].items()
                          if k.startswith(b'h.')}
                assert actual == {b'h.:authority': [b'route.example:8443']}
                assert request(port, '/authority')[0] == 200
                assert not any(k.startswith(b'h.') for k in checks[-1])
                adapter_path.unlink()
                assert request(port, '/unavailable')[0] == 503
                assert len(upstream) == 5 and len(checks) == 11
                print(f'Async read timed out in {elapsed:.2f}s. '
                      f'Origin received {len(upstream)} requests.')
            except Exception:
                log.seek(0)
                print(log.read(), end='')
                raise
            finally:
                proxy.terminate()
                proxy.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy', type=Path)
    args = parser.parse_args()
    run(args.haproxy.resolve())
