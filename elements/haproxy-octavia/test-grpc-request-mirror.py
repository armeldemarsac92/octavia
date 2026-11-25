#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a long gRPC copy and a blocked copy with loopback traffic."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Event
import time

import grpc
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived
from h2.events import StreamEnded
from h2.events import StreamReset


POOL = '67e0fff4-9150-4a96-a1dd-9d0208bc6d24'
RPC = '/example.Mirror/Stream'


def start_grpc(stack, handler):
    executor = stack.enter_context(ThreadPoolExecutor(max_workers=2))
    server = grpc.server(executor)
    server.add_generic_rpc_handlers((
        grpc.method_handlers_generic_handler('example.Mirror', {
            'Stream': grpc.stream_stream_rpc_method_handler(handler)}),
    ))
    port = server.add_insecure_port('127.0.0.1:0')
    server.start()
    stack.callback(lambda: server.stop(0).wait(3))
    return port


def start_blocked_h2(stack, received, closed, observed):
    listener = stack.enter_context(socket.create_server(('127.0.0.1', 0)))
    listener.settimeout(12)
    executor = stack.enter_context(ThreadPoolExecutor(max_workers=1))

    def wait_for_cancellation():
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(12)
            transport = H2Connection(
                config=H2Configuration(client_side=False,
                                       header_encoding='ascii'))
            transport.initiate_connection()
            peer.sendall(transport.data_to_send())
            # Never replenish the window. The receiver stops accepting DATA
            # once the peer has sent the initial HTTP/2 flow-control budget.
            while data := peer.recv(65536):
                for event in transport.receive_data(data):
                    if isinstance(event, RequestReceived):
                        assert (':path', RPC) in event.headers
                        assert ('te', 'trailers') in event.headers
                        received.set()
                    assert not isinstance(event, StreamEnded)
                    if isinstance(event, StreamReset):
                        observed['shadow_cancelled_at'] = time.monotonic()
                        closed.set()
                        return
                peer.sendall(transport.data_to_send())
            observed['shadow_cancelled_at'] = time.monotonic()
            closed.set()

    return listener.getsockname()[1], executor.submit(wait_for_cancellation)


def proxy_config(stage, frontend, primary, shadow):
    return f"""
global
    stats socket {stage}/stats.sock level admin
defaults
    mode http
    timeout connect 1s
    timeout client 45s
    timeout server 45s
listen primary
    bind 127.0.0.1:{frontend} proto h2
    filter octavia-mirror {stage}
    http-request octavia-grpc-mirror {POOL} 1 1
    server primary 127.0.0.1:{primary} proto h2
listen shadow
    bind {stage}/{POOL}.sock mode 600 octavia-mirror-socket
    timeout client 5s
    timeout server 5s
    option abortonclose
    retries 0
    http-request disable-l7-retry
    http-request set-header te trailers
    server shadow 127.0.0.1:{shadow} proto h2
"""


def counters(stage):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(stage / 'stats.sock'))
        client.sendall(b'show octavia mirrors\n')
        lines = client.makefile('r').read().splitlines()
    return {name: int(value) for name, value in
            (line.split() for line in lines if line.strip())}


def run(binary, blocked):
    observations = {}
    primary_seen = []
    shadow_seen = []
    shadow_ready = Event()
    shadow_done = Event()

    def primary(messages, context):
        for message in messages:
            primary_seen.append(message)
            yield message[:2]
        context.set_trailing_metadata((('terminus', 'primary'),))

    def shadow(messages, context):
        try:
            for message in messages:
                shadow_seen.append(message)
                yield b'shadow response'
            context.set_trailing_metadata((('terminus', 'shadow'),))
            observations['shadow_completed'] = True
            observations['shadow_completed_at'] = time.monotonic()
        except grpc.RpcError:
            observations['shadow_completed'] = False
        finally:
            shadow_done.set()

    with ExitStack() as stack:
        stage = Path(stack.enter_context(TemporaryDirectory(prefix='gm-')))
        primary_port = start_grpc(stack, primary)
        if blocked:
            shadow_port, peer = start_blocked_h2(
                stack, shadow_ready, shadow_done, observations)
        else:
            shadow_port = start_grpc(stack, shadow)
        with socket.create_server(('127.0.0.1', 0)) as frontend:
            port = frontend.getsockname()[1]
        config = stage / 'haproxy.cfg'
        config.write_text(proxy_config(stage, port, primary_port, shadow_port))
        proxy = stack.enter_context(subprocess.Popen(
            [str(binary), '-db', '-f', str(config)],
            stdout=subprocess.DEVNULL))
        stack.callback(proxy.terminate)
        channel = stack.enter_context(
            grpc.insecure_channel(f'127.0.0.1:{port}'))
        grpc.channel_ready_future(channel).result(timeout=5)
        started = time.monotonic()
        period, count = (0.05, 180) if blocked else (0.9, 38)
        body = b'x' * 8192 if blocked else b''
        expected = [index.to_bytes(2, 'big') + body for index in range(count)]

        def request_messages():
            for index, message in enumerate(expected):
                yield message
                if blocked and index == 0 and not shadow_ready.wait(3):
                    return
                time.sleep(period)

        call = channel.stream_stream(RPC)(request_messages(), timeout=45)
        assert list(call) == [message[:2] for message in expected]
        primary_end = time.monotonic()
        assert call.code() == grpc.StatusCode.OK
        assert call.trailing_metadata() == (('terminus', 'primary'),)
        assert primary_seen == expected
        if blocked:
            peer.result(timeout=3)
            assert shadow_ready.is_set() and shadow_done.is_set()
            assert observations['shadow_cancelled_at'] < primary_end
            observations['shadow_cancelled_seconds'] = round(
                observations.pop('shadow_cancelled_at') - started, 2)
        else:
            assert shadow_done.wait(3)
            assert observations['shadow_completed']
            assert shadow_seen == expected
            observations['shadow_completed_seconds'] = round(
                observations.pop('shadow_completed_at') - started, 2)
            observations['shadow_messages'] = len(shadow_seen)
            assert observations['shadow_completed_seconds'] > 30
        for _ in range(30):
            stats = counters(stage)
            if not stats['active']:
                break
            time.sleep(0.05)
        assert stats['active'] == 0 and stats['started'] == 1, stats
        if not blocked:
            assert not any(stats[name] for name in
                           ('expired', 'queue_drops', 'incomplete_uploads'))
        return dict(scenario='blocked' if blocked else 'active',
                    primary_status=call.code().name, primary_messages=count,
                    primary_seconds=round(primary_end - started, 2),
                    counters=stats, **observations)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('haproxy', type=Path)
    parser.add_argument('scenario', choices=('active', 'blocked'))
    args = parser.parse_args()
    print(json.dumps(run(args.haproxy.resolve(), args.scenario == 'blocked')))
