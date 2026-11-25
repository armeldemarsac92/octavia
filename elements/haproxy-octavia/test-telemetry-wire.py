#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run with a Lua-enabled Amphora HAProxy and OpenTelemetry Collector."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
from threading import Thread
import time
import uuid

from oslo_config import cfg

from octavia.common import config as octavia_config
from octavia.common import constants
from octavia.common import data_models
from octavia.common.jinja.haproxy.combined_listeners import jinja_cfg


TRACE_ID = '0123456789abcdef0123456789abcdef'
PARENT_ID = '0123456789abcdef'
TRACEPARENT = f'00-{TRACE_ID}-{PARENT_ID}-01'


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'normal application response'
        self.send_response(418 if self.path == '/child' else 200)
        self.send_header('Content-Length', str(len(body)))
        if 'traceparent' in self.headers:
            self.send_header('X-Backend-Traceparent',
                             self.headers['traceparent'])
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@contextmanager
def running(args, logfile):
    with logfile.open('w') as output:
        proc = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_port(port, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(
                f'{proc.args[0]} stopped with {proc.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.05):
                return
        except ConnectionRefusedError:
            time.sleep(0.05)
    raise TimeoutError(f'No listener on port {port}')


def app_request(port, path, headers=None, tls=None):
    if tls:
        with_response = http.client.HTTPSConnection(
            '127.0.0.1', port, timeout=3, context=tls)
    else:
        with_response = http.client.HTTPConnection(
            '127.0.0.1', port, timeout=3)
    start = time.time_ns()
    try:
        with_response.request('GET', path, headers=headers or {})
        response = with_response.getresponse()
        assert response.read() == b'normal application response'
        return (response.status, response.getheader('X-Backend-Traceparent'),
                start, time.time_ns())
    finally:
        with_response.close()


def record_spans(path):
    if not path.exists():
        return []
    lines = path.read_text().splitlines(keepends=True)
    resources = [resource for line in lines
                 if line.endswith('\n')
                 for resource in json.loads(line)['resourceSpans']]
    return [(resource['resource']['attributes'], span)
            for resource in resources
            for scope in resource['scopeSpans']
            for span in scope['spans']]


def wait_spans(path, count):
    for _ in range(120):
        spans = record_spans(path)
        if len(spans) >= count:
            assert len(spans) == count
            return spans
        time.sleep(0.05)
    raise TimeoutError(f'Expected {count} collected spans, got {len(spans)}')


def check_span(observed, app, trace_id=None, parent_id=None):
    attributes, span = observed
    code, traceparent, start, end = app
    assert attributes == [{'key': 'service.name',
                           'value': {'stringValue': 'hibiscus-local-gateway'}}]
    assert span['name'] == 'Gateway HTTP' and span['kind'] == 2
    assert span.get('parentSpanId') == parent_id
    assert span['flags'] == (0x301 if parent_id else 1)
    trace_id_bytes = bytes.fromhex(span['traceId'])
    assert len(trace_id_bytes) == 16 and any(trace_id_bytes)
    assert len(bytes.fromhex(span['spanId'])) == 8 and int(span['spanId'], 16)
    if trace_id is not None:
        assert span['traceId'] == trace_id and span['spanId'] != parent_id
    assert traceparent == f"00-{span['traceId']}-{span['spanId']}-01"
    span_start = int(span['startTimeUnixNano'])
    span_end = int(span['endTimeUnixNano'])
    assert start <= span_start <= span_end <= end
    assert span['attributes'] == [{'key': 'http.response.status_code',
                                   'value': {'intValue': str(code)}}]
    return span


def collector_config(directory, receiver_port, name, tls=None):
    spans = directory / f'{name}.jsonl'
    config = directory / f'{name}.yaml'
    transport = ''
    if tls:
        cert, key = tls
        transport = f'''
        tls:
          cert_file: {cert}
          key_file: {key}'''
    config.write_text(f'''receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{receiver_port}{transport}
exporters:
  file:
    path: {spans}
service:
  telemetry:
    metrics:
      level: none
      readers: []
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
''')
    return config, spans


def create_local_certificate(directory):
    cert, key = directory / 'localhost.crt', directory / 'localhost.key'
    subprocess.run([
        'openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048',
        '-nodes', '-days', '1', '-subj', '/CN=collector.test',
        '-addext', 'subjectAltName=DNS:collector.test,IP:127.0.0.1',
        '-keyout', key, '-out', cert,
    ], check=True, capture_output=True)
    return cert, key


def render_config(directory, socket_dir, app_port, listener_ports,
                  collector_ports, cert, key):
    cfg.CONF.set_override('base_cert_dir', str(directory),
                          group='haproxy_amphora')

    def pool(port, **options):
        member = data_models.Member(
            id=str(uuid.uuid4()), ip_address='127.0.0.1',
            protocol_port=port, enabled=True, weight=1,
            provisioning_status=constants.ACTIVE)
        return data_models.Pool(
            id=str(uuid.uuid4()), protocol=constants.PROTOCOL_HTTP,
            lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN, members=[member],
            enabled=True, provisioning_status=constants.ACTIVE, **options)

    app = pool(app_port)
    http_collector = pool(collector_ports[0])
    tls_collector = pool(
        collector_ports[1], tls_enabled=True, ca_tls_certificate_id='local-ca',
        backend_tls_hostname='collector.test', alpn_protocols=['http/1.1'])
    lb = data_models.LoadBalancer(
        id=str(uuid.uuid4()), project_id='wire', enabled=True,
        topology=constants.TOPOLOGY_SINGLE,
        vip=data_models.Vip(ip_address='127.0.0.1'),
        pools=[app, http_collector, tls_collector])
    amphora = data_models.Amphora(
        id=str(uuid.uuid4()), status=constants.ACTIVE)
    lb.amphorae = [amphora]
    for port, collector in zip(listener_ports,
                               (http_collector, tls_collector, None)):
        tracing = (dict(collector_pool_id=collector.id,
                        service_name='hibiscus-local-gateway',
                        span_name='Gateway HTTP') if collector else None)
        https = collector is tls_collector
        lb.listeners.append(data_models.Listener(
            id=str(uuid.uuid4()), load_balancer=lb, protocol_port=port,
            protocol=(constants.PROTOCOL_TERMINATED_HTTPS
                      if https else constants.PROTOCOL_HTTP),
            tls_certificate_id='local-cert' if https else None,
            enabled=True, provisioning_status=constants.ACTIVE,
            default_pool_id=app.id, default_pool=app, pools=[app],
            otlp_tracing=tracing))
    ssl_dir = directory / lb.id
    ssl_dir.mkdir()
    bundle = ssl_dir / 'bundle.pem'
    bundle.write_bytes(cert.read_bytes() + key.read_bytes())
    (ssl_dir / f'{lb.listeners[1].id}.pem').write_text(f'{bundle}\n')

    templater = jinja_cfg.JinjaTemplater(
        base_amp_path=str(directory), base_crt_dir=str(directory))
    lua = Path(__file__).with_name('octavia-telemetry.lua').resolve()

    def render(name):
        config = templater.build_config(
            amphora, lb.listeners, tls_certs={}, haproxy_versions=('3', '0'),
            amp_details={constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING:
                         True, 'active_tuned_profiles': 'amphora',
                         'cpu_count': 5},
            socket_path=str(socket_dir / 'stats.sock'),
            otlp_tls_certs={tls_collector.id: {'ca_cert': str(cert)}})
        # Use the harness account and temporary paths in the local process.
        config = (config
                  .replace(constants.HAPROXY_OTLP_TRACING_SCRIPT, str(lua))
                  .replace(constants.HAPROXY_OTLP_TRACING_SOCKET_DIR,
                           str(socket_dir))
                  .replace('    user nobody\n', '')
                  .replace(' user nobody mode 600', ' mode 600')
                  .replace('    cpu-map auto:1/1-4 1-4\n', ''))
        path = directory / name
        path.write_text(config)
        return path

    traced = render('haproxy.cfg')
    lb.listeners[0].otlp_tracing = None
    cleared = render('haproxy-cleared.cfg')
    tls_collector.backend_tls_hostname = 'wrong.test'
    return traced, cleared, render('haproxy-wrong-identity.cfg')


def prove(args, directory, socket_dir, app_port):
    enabled, neighbor, disabled, receiver_port, tls_port = (
        free_port() for _ in range(5))
    cert, key = create_local_certificate(directory)
    tls = ssl.create_default_context(cafile=cert)
    config, cleared, wrong_identity = render_config(
        directory, socket_dir, app_port, (enabled, neighbor, disabled),
        (receiver_port, tls_port), cert, key)
    for path in (config, cleared, wrong_identity):
        subprocess.run([args.haproxy, '-c', '-f', path], check=True)
    first, spans = collector_config(directory, receiver_port, 'initial')
    after, recovered_spans = collector_config(
        directory, receiver_port, 'recovered')
    tls_config, tls_spans = collector_config(
        directory, tls_port, 'neighbor', tls=(cert, key))

    with (
        running([args.haproxy, '-db', '-f', config],
                directory / 'haproxy.log') as proxy,
        running([args.otelcol, '--config', tls_config],
                directory / 'collector-tls.log') as tls_collector,
    ):
        wait_port(enabled, proxy)
        wait_port(tls_port, tls_collector)
        with running([args.otelcol, '--config', first],
                     directory / 'collector.log') as collector:
            wait_port(receiver_port, collector)
            root = app_request(enabled, '/root', {
                'X-OTLP-Endpoint': 'http://127.0.0.1:1'})
            assert root[0] == 200
            root_span = check_span(wait_spans(spans, 1)[0], root)
            child = app_request(
                enabled, '/child', {'traceparent': TRACEPARENT})
            assert child[0] == 418
            child_span = check_span(
                wait_spans(spans, 2)[1], child, TRACE_ID, PARENT_ID)
            assert child_span['spanId'] != root_span['spanId']
            print(f"root SERVER {root_span['spanId']} http={root[0]}, "
                  f"child SERVER {child_span['spanId']} "
                  f"parent={PARENT_ID} http={child[0]}")

            off = app_request(
                disabled, '/disabled', {'traceparent': TRACEPARENT})
            assert off[0:2] == (200, TRACEPARENT)
            time.sleep(0.3)
            assert len(record_spans(spans)) == 2
            print('off http=200, preserved inbound context, no extra spans')

            collector.send_signal(signal.SIGSTOP)
            try:
                _, wait_status = os.waitpid(collector.pid, os.WUNTRACED)
                assert os.WIFSTOPPED(wait_status)
                stalled = app_request(enabled, '/stalled')
                latency_s = (stalled[-1] - stalled[-2]) / 1e9
                assert stalled[0] == 200 and latency_s < 0.8
                print(f'stalled collector http=200 in '
                      f'{latency_s * 1000:.1f} ms')
                child = app_request(
                    neighbor, '/child', {'traceparent': TRACEPARENT}, tls=tls)
                check_span(
                    wait_spans(tls_spans, 1)[0], child, TRACE_ID, PARENT_ID)
                print('neighbor HTTPS request and its TLS collector succeeded')
                time.sleep(1.2)
                assert len(record_spans(spans)) == 2
            finally:
                collector.send_signal(signal.SIGCONT)

        absent = app_request(enabled, '/absent')
        latency_s = (absent[-1] - absent[-2]) / 1e9
        assert absent[0] == 200 and latency_s < 0.8
        print(f'absent collector http=200 in {latency_s * 1000:.1f} ms')
        time.sleep(1.2)
        with running([args.otelcol, '--config', after],
                     directory / 'recovered.log') as collector:
            wait_port(receiver_port, collector)
            recovered = app_request(enabled, '/recovered')
            check_span(wait_spans(recovered_spans, 1)[0], recovered)
            print('recovered collector accepted 1 new SERVER span')

            with running(
                [args.haproxy, '-db', '-f', cleared, '-sf', str(proxy.pid)],
                directory / 'haproxy-cleared.log',
            ) as replacement:
                proxy.wait(timeout=5)
                wait_port(enabled, replacement)
                response = app_request(
                    enabled, '/removed', {'traceparent': TRACEPARENT})
                assert response[:2] == (200, TRACEPARENT)
                traced_neighbor = app_request(neighbor, '/root', tls=tls)
                check_span(wait_spans(tls_spans, 2)[1], traced_neighbor)
                assert len(record_spans(recovered_spans)) == 1
                print('reload removed tracing and kept the neighbor active')

                with running(
                    [args.haproxy, '-db', '-f', wrong_identity,
                     '-sf', str(replacement.pid)],
                    directory / 'haproxy-wrong-identity.log',
                ) as mismatch:
                    replacement.wait(timeout=5)
                    wait_port(neighbor, mismatch)
                    assert app_request(neighbor, '/root', tls=tls)[0] == 200
                    time.sleep(1.2)
                    assert len(record_spans(tls_spans)) == 2
                    print('TLS identity mismatch stopped export. HTTPS was '
                          'still available.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy')
    parser.add_argument('otelcol')
    parser.add_argument('evidence_dir', type=Path)
    args = parser.parse_args()
    octavia_config.init([])
    directory = Path(tempfile.mkdtemp(
        prefix='wire-', dir=args.evidence_dir.resolve()))
    print(f'Evidence at {directory}', flush=True)
    with (tempfile.TemporaryDirectory(prefix='octavia-otlp-') as sockets,
          ThreadingHTTPServer(('127.0.0.1', 0), App) as app):
        Thread(target=app.serve_forever, daemon=True).start()
        try:
            prove(args, directory, Path(sockets), app.server_port)
        finally:
            app.shutdown()


if __name__ == '__main__':
    main()
