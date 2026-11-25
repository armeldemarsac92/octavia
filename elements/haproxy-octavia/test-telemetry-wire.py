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

from octavia.amphorae.backends.utils import haproxy_query
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
        self.send_response(418 if self.path.split('?')[0] == '/child' else 200)
        self.send_header('Content-Length', str(len(body)))
        if 'traceparent' in self.headers:
            self.send_header('X-Backend-Traceparent',
                             self.headers['traceparent'])
        if self.path.endswith('?demo=attributes'):
            self.send_header('X-Demo-Request', 'response-fallback')
            self.send_header('X-Demo-Response', 'response-only')
            if 'X-Demo-Request' in self.headers:
                self.send_header('X-Demo-Echo', self.headers['X-Demo-Request'])
        self.end_headers()
        self.wfile.write(body)

    do_PROPFIND = do_GET
    do_QUERY = do_GET

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


def app_request(port, path, headers=None, tls=None, expected_headers=None,
                method='GET'):
    if tls:
        with_response = http.client.HTTPSConnection(
            '127.0.0.1', port, timeout=3, context=tls)
    else:
        with_response = http.client.HTTPConnection(
            '127.0.0.1', port, timeout=3)
    start = time.time_ns()
    try:
        with_response.request(method, path, headers=headers or {})
        response = with_response.getresponse()
        assert response.read() == b'normal application response'
        for name, value in (expected_headers or {}).items():
            assert response.getheader(name) == value
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


def assert_publication(config, socket_dir):
    description = next(
        line.strip().split()[1] for line in config.read_text().splitlines()
        if line.startswith('    description octavia-otlp-'))
    query = haproxy_query.HAProxyQuery(
        str(socket_dir / 'stats.sock'), timeout=0.3)
    info = query.show_info()
    assert info['description'] == description and info['Stopping'] == '0'


def check_span(observed, app, trace_id=None, parent_id=None, parent_flags=1,
               custom_attributes=None):
    attributes, span = observed
    code, traceparent, start, end = app
    assert attributes == [{'key': 'service.name',
                           'value': {'stringValue': 'hibiscus-local-gateway'}}]
    assert span['name'] == 'Gateway HTTP' and span['kind'] == 2
    assert span.get('parentSpanId') == parent_id
    flags = (parent_flags & 2) | 1 if parent_id else 3
    assert span['flags'] == (flags | 0x300 if parent_id else flags)
    trace_id_bytes = bytes.fromhex(span['traceId'])
    assert len(trace_id_bytes) == 16 and any(trace_id_bytes)
    assert len(bytes.fromhex(span['spanId'])) == 8 and int(span['spanId'], 16)
    if trace_id is not None:
        assert span['traceId'] == trace_id and span['spanId'] != parent_id
    assert traceparent == f"00-{span['traceId']}-{span['spanId']}-{flags:02x}"
    span_start = int(span['startTimeUnixNano'])
    span_end = int(span['endTimeUnixNano'])
    assert start <= span_start <= span_end <= end
    expected = {'http.response.status_code': {'intValue': str(code)}}
    expected.update(custom_attributes or {})
    assert len(span['attributes']) == len(expected)
    assert {a['key']: a['value'] for a in span['attributes']} == expected
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


def render_config(args, directory, socket_dir, app_port, listener_ports,
                  collector_ports, cert, key, sampling_listeners=(),
                  span_attributes=None):
    cfg.CONF.set_override('base_cert_dir', str(directory),
                          group='haproxy_amphora')
    for profile, enabled in (
            ('tracing', sampling_listeners or span_attributes),
            ('sampling', sampling_listeners),
            ('span_attributes', span_attributes)):
        if enabled:
            cfg.CONF.set_override(f'enabled_listener_otlp_{profile}_providers',
                                  ['amphora'], group='api_settings')

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
        provider='amphora',
        topology=constants.TOPOLOGY_SINGLE,
        vip=data_models.Vip(ip_address='127.0.0.1'),
        pools=[app, http_collector, tls_collector])
    amphora = data_models.Amphora(
        id=str(uuid.uuid4()), status=constants.ACTIVE)
    lb.amphorae = [amphora]
    listeners = [(port, collector, None) for port, collector in zip(
        listener_ports, (http_collector, tls_collector, None))]
    listeners.extend((port, http_collector, sampling)
                     for port, sampling in sampling_listeners)
    for port, collector, sampling in listeners:
        tracing = (dict(collector_pool_id=collector.id,
                        service_name='hibiscus-local-gateway',
                        span_name='Gateway HTTP') if collector else None)
        if sampling:
            tracing['sampling'] = sampling
        if span_attributes and port in span_attributes:
            tracing['attributes'] = span_attributes[port]
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
    sampling_lua = args.sampling_lua.resolve() if args.sampling_lua else lua
    if args.sampling_first:
        lb.listeners.sort(key=lambda listener: bool(
            listener.otlp_tracing and 'attributes' in listener.otlp_tracing))

    def render(name, sampling_capable, tracing_capable=True,
               attributes_capable=False):
        publication = (uuid.uuid4().hex
                       if sampling_listeners or span_attributes else None)
        attributes_cap = (
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SPAN_ATTRIBUTES)
        config = templater.build_config(
            amphora, lb.listeners, tls_certs={}, haproxy_versions=('3', '0'),
            amp_details={constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING:
                         tracing_capable,
                         constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING:
                         sampling_capable,
                         attributes_cap: attributes_capable,
                         'active_tuned_profiles': 'amphora',
                         'cpu_count': 5},
            socket_path=str(socket_dir / 'stats.sock'),
            otlp_tls_certs={tls_collector.id: {'ca_cert': str(cert)}},
            otlp_publication=publication)
        # Use the harness account and temporary paths in the local process.
        config = (config
                  .replace(constants.HAPROXY_OTLP_TRACING_SCRIPT, str(lua))
                  .replace(constants.HAPROXY_OTLP_SAMPLING_SCRIPT,
                           str(sampling_lua))
                  .replace(constants.HAPROXY_OTLP_SPAN_ATTRIBUTES_SCRIPT,
                           str(lua))
                  .replace(constants.HAPROXY_OTLP_TRACING_SOCKET_DIR,
                           str(socket_dir))
                  .replace('    user nobody\n', '')
                  .replace(' user nobody mode 600', ' mode 600')
                  .replace('    cpu-map auto:1/1-4 1-4\n', ''))
        path = directory / name
        path.write_text(config)
        return path

    traced = render('haproxy.cfg', bool(sampling_listeners),
                    attributes_capable=bool(span_attributes))
    if span_attributes:
        cleared = render('haproxy-cleared.cfg', bool(sampling_listeners))
    else:
        if not sampling_listeners:
            lb.listeners[0].otlp_tracing = None
        cleared = render('haproxy-cleared.cfg', False, not sampling_listeners)
    tls_collector.backend_tls_hostname = 'wrong.test'
    return traced, cleared, render('haproxy-wrong-identity.cfg', False)


def prove(args, directory, socket_dir, app_port):
    enabled, neighbor, disabled, receiver_port, tls_port = (
        free_port() for _ in range(5))
    cert, key = create_local_certificate(directory)
    tls = ssl.create_default_context(cafile=cert)
    config, cleared, wrong_identity = render_config(
        args, directory, socket_dir, app_port, (enabled, neighbor, disabled),
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
            print(f'root SERVER http={root[0]}, child SERVER http={child[0]}')

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


def prove_sampling(args, directory, socket_dir, app_port):
    (legacy, neighbor, disabled, receiver, tls_port, zero, full, partial,
     parent) = (free_port() for _ in range(9))
    cert, key = create_local_certificate(directory)
    never = {'numerator': 0, 'denominator': 1}
    always = {'numerator': 1, 'denominator': 1}
    half = {'numerator': 1, 'denominator': 2}
    config, withdrawn, _ = render_config(
        args, directory, socket_dir, app_port, (legacy, neighbor, disabled),
        (receiver, tls_port), cert, key, sampling_listeners=(
            (zero, {'base': never}),
            (full, {'base': always, 'parent': always}),
            (partial, {'base': half}),
            (parent, {'base': never, 'parent': half})))
    subprocess.run([args.haproxy, '-c', '-f', config], check=True)
    subprocess.run([args.haproxy, '-c', '-f', withdrawn], check=True)
    collector_path, spans = collector_config(directory, receiver, 'sampling')
    expected = {}

    def request(port, sampled, incoming=None, valid_parent=False):
        headers = {'traceparent': incoming} if incoming else None
        response = app_request(port, '/sampling', headers)
        assert response[0] == 200
        version, trace, span, flags = response[1].split('-')
        assert version == '00' and flags in ('00', '01', '02', '03')
        assert int(trace, 16) and int(span, 16) and span != PARENT_ID
        assert (trace == TRACE_ID) == valid_parent
        parent_flags = int(incoming[-2:], 16) if valid_parent else 2
        assert int(flags, 16) & 2 == parent_flags & 2
        decision = bool(int(flags, 16) & 1)
        if sampled is not None:
            assert decision == sampled
        if decision:
            assert span not in expected
            expected[span] = (response, TRACE_ID if valid_parent else None,
                              PARENT_ID if valid_parent else None,
                              parent_flags)
        return decision

    with (running([args.haproxy, '-db', '-f', config],
                  directory / 'haproxy.log') as proxy,
          running([args.otelcol, '--config', collector_path],
                  directory / 'collector.log') as collector):
        wait_port(legacy, proxy)
        wait_port(receiver, collector)
        assert_publication(config, socket_dir)
        not_sampled = f'00-{TRACE_ID}-{PARENT_ID}-02'
        sampled_parent = f'00-{TRACE_ID}-{PARENT_ID}-03'
        invalid = f'00-{TRACE_ID}-{"0" * 16}-01'
        request(legacy, True, not_sampled, valid_parent=True)
        request(zero, False)
        request(zero, False, TRACEPARENT, valid_parent=True)
        request(full, True)
        request(full, True, sampled_parent, valid_parent=True)
        request(full, False, not_sampled, valid_parent=True)
        request(full, True, invalid)
        request(parent, False)
        request(parent, False, not_sampled, valid_parent=True)
        base_count = sum(request(partial, None) for _ in range(64))
        parent_count = sum(
            request(parent, None, sampled_parent, valid_parent=True)
            for _ in range(64))
        assert 12 <= base_count <= 52 and 12 <= parent_count <= 52
        wait_spans(spans, len(expected))
        time.sleep(0.3)
        observed = record_spans(spans)
        assert len(observed) == len(expected)
        for item in observed:
            check_span(item, *expected.pop(item[1]['spanId']))
        print('0/1 base: 0 of 2, 1/1 base or sampled parent: 3 of 3, '
              'unsampled parent with parent mode: 0 of 2')
        print(f'1/2 base: {base_count} of 64, '
              f'1/2 sampled parent: {parent_count} of 64, '
              f'{len(observed)} total exports matched the propagated context')
        with running(
            [args.haproxy, '-db', '-f', withdrawn, '-sf', str(proxy.pid)],
            directory / 'haproxy-withdrawn.log',
        ) as replacement:
            proxy.wait(timeout=5)
            wait_port(full, replacement)
            assert_publication(withdrawn, socket_dir)
            for port in (full, legacy):
                response = app_request(
                    port, '/withdrawn', {'traceparent': sampled_parent})
                assert response[:2] == (200, sampled_parent)
            time.sleep(0.3)
            assert len(record_spans(spans)) == len(observed)
        print('Loss of both capabilities: active HAProxy confirmed the '
              'withdrawal config, HTTP 200 and original context with zero '
              'additional exports on legacy and sampled listeners')


def prove_span_attributes(args, directory, socket_dir, app_port):
    (enabled, neighbor, disabled, combined, sampling_only, receiver,
     tls_port) = (free_port() for _ in range(7))
    cert, key = create_local_certificate(directory)
    tls = ssl.create_default_context(cafile=cert)
    literal = '測試🍋\n"a\\b"\x00\t$' '{fake-value} # ;'
    literal += '🍋' * (1024 - len(literal))
    configured = [
        dict(name='demo.literal', source_type='Literal',
             literal_value=literal),
        dict(name='demo.header', source_type='Header',
             header_name='X-DEMO-REQUEST'),
        dict(name='demo.response', source_type='Header',
             header_name='X-Demo-Response'),
        dict(name='demo.absent', source_type='Header',
             header_name='X-Demo-Absent'),
        dict(name='demo.method', source_type='Attribute',
             attribute_key='http.request.method'),
        dict(name='demo.status', source_type='Attribute',
             attribute_key='http.response.status_code'),
        dict(name='http.response.status_code', source_type='Attribute',
             attribute_key='http.response.status_code'),
        dict(name='demo.path', source_type='Attribute',
             attribute_key='url.path'),
        dict(name='demo.scheme', source_type='Attribute',
             attribute_key='url.scheme'),
    ]
    always = {'numerator': 1, 'denominator': 1}
    never = {'numerator': 0, 'denominator': 1}
    config, suspended, _ = render_config(
        args, directory, socket_dir, app_port, (enabled, neighbor, disabled),
        (receiver, tls_port), cert, key,
        sampling_listeners=((combined, {'base': always, 'parent': always}),
                            (sampling_only, {'base': never})),
        span_attributes={enabled: configured, combined: configured})
    for path in (config, suspended):
        subprocess.run([args.haproxy, '-c', '-f', path], check=True)
    collector_path, spans = collector_config(directory, receiver, 'attributes')
    tls_config, tls_spans = collector_config(
        directory, tls_port, 'neighbor', tls=(cert, key))

    with (
        running([args.haproxy, '-db', '-f', config],
                directory / 'haproxy.log') as proxy,
        running([args.otelcol, '--config', collector_path],
                directory / 'collector.log') as collector,
        running([args.otelcol, '--config', tls_config],
                directory / 'collector-tls.log') as tls_collector,
    ):
        wait_port(enabled, proxy)
        wait_port(receiver, collector)
        wait_port(tls_port, tls_collector)
        assert_publication(config, socket_dir)
        known_methods = os.getenv('OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS',
                                  'GET,QUERY').split(',')
        cases = ((enabled, 'GET', '/child', 418, 'request, whole "field"'),
                 (combined, 'PROPFIND', '/root', 200, None),
                 (combined, 'QUERY', '/root', 200, None))
        for count, (port, method, path, code, demo_header) in enumerate(
                cases, start=1):
            sent = {'traceparent': TRACEPARENT}
            unchanged = {'X-Demo-Request': 'response-fallback',
                         'X-Demo-Response': 'response-only'}
            if demo_header is not None:
                sent['X-Demo-Request'] = demo_header
                unchanged['X-Demo-Echo'] = demo_header
            response = app_request(port, path + '?demo=attributes',
                                   sent, expected_headers=unchanged,
                                   method=method)
            assert response[0] == code
            method_value = method if method in known_methods else '_OTHER'
            custom = {
                'demo.literal': {'stringValue': literal},
                'demo.header': {
                    'stringValue': demo_header or 'response-fallback'},
                'demo.response': {'stringValue': 'response-only'},
                'demo.method': {'stringValue': method_value},
                'demo.status': {'intValue': str(code)},
                'demo.path': {'stringValue': path},
                'demo.scheme': {'stringValue': 'http'},
            }
            check_span(wait_spans(spans, count)[-1], response, TRACE_ID,
                       PARENT_ID, custom_attributes=custom)
            print(f'{method} exported as {method_value}')
        sampled_response = app_request(
            sampling_only, '/sampling', {'traceparent': TRACEPARENT})
        version, trace, span, flags = sampled_response[1].split('-')
        assert sampled_response[0] == 200
        assert (version, trace, flags) == ('00', TRACE_ID, '00')
        assert span != PARENT_ID and int(span, 16)
        neighbor_response = app_request(neighbor, '/root', tls=tls)
        check_span(wait_spans(tls_spans, 1)[0], neighbor_response)
        print('HTTP 418 and 200: typed attributes verified, including a '
              '1024-character literal, request and response headers, '
              'missing-field omission and the existing status attribute')
        print('The sampling-only listener propagated the unsampled context '
              'and the HTTPS neighbor exported a standard span')
        with running(
            [args.haproxy, '-db', '-f', suspended, '-sf', str(proxy.pid)],
            directory / 'haproxy-suspended.log',
        ) as replacement:
            proxy.wait(timeout=5)
            wait_port(enabled, replacement)
            assert_publication(suspended, socket_dir)
            response = app_request(
                enabled, '/child', {'traceparent': TRACEPARENT})
            assert response[:2] == (418, TRACEPARENT)
            response = app_request(neighbor, '/root', tls=tls)
            check_span(wait_spans(tls_spans, 2)[1], response)
            time.sleep(0.3)
            assert len(record_spans(spans)) == len(cases)
        print('Missing attributes capability: HTTP 418 and inbound trace '
              'context preserved without further exports, legacy HTTPS '
              'neighbor still exported a standard span')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy')
    parser.add_argument('otelcol')
    parser.add_argument('evidence_dir', type=Path)
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument('--sampling', action='store_true')
    profile.add_argument('--attributes', action='store_true')
    parser.add_argument('--sampling-lua', type=Path,
                        help='use a previously installed sampling script')
    parser.add_argument('--sampling-first', action='store_true',
                        help='load sampling actions before attribute actions')
    args = parser.parse_args()
    octavia_config.init([])
    directory = Path(tempfile.mkdtemp(
        prefix='wire-', dir=args.evidence_dir.resolve()))
    print(f'Evidence at {directory}', flush=True)
    with (tempfile.TemporaryDirectory(prefix='octavia-otlp-') as sockets,
          ThreadingHTTPServer(('127.0.0.1', 0), App) as app):
        Thread(target=app.serve_forever, daemon=True).start()
        try:
            check = prove
            if args.sampling:
                check = prove_sampling
            elif args.attributes:
                check = prove_span_attributes
            check(args, directory, Path(sockets), app.server_port)
        finally:
            app.shutdown()


if __name__ == '__main__':
    main()
