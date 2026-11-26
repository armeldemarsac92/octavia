# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Keep UDP listeners closed while their IPVS configuration changes."""

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import uuid

from octavia.amphorae.backends.agent.api_server import util
from octavia.amphorae.backends.utils import keepalivedlvs_query
from octavia.common import constants
from octavia.i18n import _


EXPIRE_NODEST = 'net.ipv4.vs.expire_nodest_conn'
CONVERGENCE_TIMEOUT = 5
STATE_SUFFIX = '.udp-guard.json'
CONFIRMATION_HEADER = 'X-Octavia-UDP-Guard'
DROP_IN = '50-octavia-udp-guard.conf'


def _integer(value, min_value, max_value):
    if type(value) is not int or not min_value <= value <= max_value:
        raise ValueError(_('Invalid UDP guard integer'))
    return value


def validate_spec(spec):
    fields = set(spec)
    extended_weights = spec.get('extended_member_weights') is True
    if extended_weights:
        fields.remove('extended_member_weights')
    if fields != {'vip', 'port', 'fraction', 'has_service', 'destinations'}:
        raise ValueError(_('Invalid UDP guard specification'))
    max_weight = (constants.MAX_UDP_EXTENDED_MEMBER_WEIGHT
                  if extended_weights else constants.MAX_WEIGHT)
    vip = str(ipaddress.IPv4Address(spec['vip']))
    port = _integer(spec['port'], 1, 65535)
    fraction = spec['fraction']
    if set(fraction) != {'numerator', 'denominator'}:
        raise ValueError(_('Invalid UDP guard fraction'))
    denominator = _integer(fraction['denominator'], 1, 16_000_000)
    numerator = _integer(fraction['numerator'], 0, denominator)
    has_service = spec['has_service']
    if type(has_service) is not bool or type(spec['destinations']) is not list:
        raise ValueError(_('Invalid UDP guard IPVS service'))
    destinations = []
    seen = set()
    for destination in spec['destinations']:
        if set(destination) != {'address', 'port', 'weight'}:
            raise ValueError(_('Invalid UDP guard destination'))
        address = str(ipaddress.IPv4Address(destination['address']))
        target_port = _integer(destination['port'], 1, 65535)
        weight = _integer(destination['weight'], constants.MIN_WEIGHT,
                          max_weight)
        if (address, target_port) in seen:
            raise ValueError(_('Duplicate UDP guard destination'))
        seen.add((address, target_port))
        destinations.append({'address': address, 'port': target_port,
                             'weight': weight})
    if has_service != bool(destinations):
        raise ValueError(_('UDP guard service and destinations disagree'))
    validated = {
        'vip': vip, 'port': port, 'has_service': has_service,
        'fraction': {'numerator': numerator, 'denominator': denominator},
        'destinations': destinations,
    }
    if extended_weights:
        # An older guard must also reject this state during activation,
        # including when the extended weights belong to disabled members.
        validated['extended_member_weights'] = True
    return validated


def write_file(path, body, mode=0o600):
    """Make both content and filename durable before dependent changes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp_path = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), mode)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
            temp_path.replace(path)
            _sync_dir(path.parent)
        finally:
            temp_path.unlink(missing_ok=True)


def _sync_dir(path):
    dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _in_namespace(*argv, **kwargs):
    return subprocess.run(
        ['ip', 'netns', 'exec', constants.AMPHORA_NAMESPACE, *argv],
        check=True, capture_output=True, text=True, **kwargs)


def _nft(rules, check=False):
    options = ['-c'] if check else []
    _in_namespace(constants.NFT_CMD, *options, '-f', '-', input=rules,
                  timeout=CONVERGENCE_TIMEOUT)


def _expect_expiration(enable=False):
    if enable:
        _in_namespace('sysctl', '-qw', f'{EXPIRE_NODEST}=1', timeout=5)
    actual = _in_namespace('sysctl', '-n', EXPIRE_NODEST, timeout=5)
    if actual.stdout.strip() != '1':
        raise RuntimeError(f'{EXPIRE_NODEST} must be enabled for UDP guards')


def check_support():
    _in_namespace('modprobe', 'ip_vs', timeout=5)
    _in_namespace('sysctl', '-n', EXPIRE_NODEST, timeout=5)
    # Check the real kernel expression without committing any rules.
    sample = {'vip': '192.0.2.1', 'port': 1}
    _nft(_rules('octavia_udp_guard_check', sample, 1, 2), check=True)


def _rules(table, spec, numerator, denominator):
    scope = (f'iifname "{constants.NETNS_PRIMARY_INTERFACE}" '
             f'ip daddr {spec["vip"]} udp dport {spec["port"]}')
    # Use a separate table for each listener. Replace it in one transaction.
    replace = f'table ip {table} {{}}\ndelete table ip {table}\n'
    reject = (
        f'numgen inc mod {denominator} < {numerator} '
        if numerator < denominator else '')
    prerouting_rule = (f'{scope} {reject}counter drop' if numerator else '')
    # IPVS/NAT consumes accepted requests at LOCAL_IN priority 99. A packet
    # still addressed to this socket later must not fall through to a local
    # process if Keepalived disappears unexpectedly.
    return replace + f'''table ip {table} {{
    chain ingress {{
        type filter hook prerouting priority mangle; policy accept;
        {scope} ct state invalid counter drop
        {prerouting_rule}
    }}
    chain no_local_delivery {{
        type filter hook input priority 101; policy accept;
        {scope} counter drop
    }}
}}
'''


def _kernel_address(address, port):
    return f'{int(ipaddress.IPv4Address(address)):08X}:{port:04X}'


def _ipvs_matches(spec):
    vip_port = _kernel_address(spec['vip'], spec['port'])
    contents = keepalivedlvs_query.read_kernel_file(
        constants.AMPHORA_NAMESPACE, keepalivedlvs_query.KERNEL_LVS_PATH)
    if not contents.startswith('IP Virtual Server version '):
        return False
    service = None
    destinations = {}
    scanning = False
    for line in contents.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] != '->':
            scanning = fields[:2] == ['UDP', vip_port]
            if scanning:
                # The remaining columns include one-packet scheduling and
                # persistence. Neither is in the guarded WRR service.
                service = fields[2:]
        elif scanning:
            destinations[fields[1]] = (fields[2], int(fields[3]))
    expected = {
        _kernel_address(dest['address'], dest['port']):
        ('Masq', dest['weight'])
        for dest in spec['destinations']
    }
    return (service == (['wrr'] if spec['has_service'] else None) and
            destinations == expected)


class Guard:
    def __init__(self, listener_id, state_dir=None):
        self.listener_id = str(uuid.UUID(listener_id))
        self.directory = Path(state_dir or util.keepalived_lvs_dir())
        self.path = self.directory / f'{self.listener_id}{STATE_SUFFIX}'
        self.table = 'octavia_udp_' + self.listener_id.replace('-', '')

    @contextlib.contextmanager
    def lock(self, kernel=False):
        # A systemctl caller holds the request lock across the operation; the
        # unit hooks take only the kernel lock and cannot deadlock that caller.
        self.directory.mkdir(parents=True, exist_ok=True)
        suffix = 'kernel' if kernel else 'request'
        lock_path = self.directory / f'{self.listener_id}.udp-guard.{suffix}'
        with lock_path.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def read(self):
        try:
            state = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return None
        state['spec'] = validate_spec(state['spec'])
        return state

    def _write(self, state):
        write_file(self.path, json.dumps(state).encode('utf-8'))

    def close(self, state):
        _nft(_rules(self.table, state['spec'], 1, 1))

    def prepare(self, spec, config, retiring=False):
        _expect_expiration(enable=True)
        previous = self.read()
        if previous and any(previous['spec'][key] != spec[key]
                            for key in ('vip', 'port')):
            raise ValueError(_('The scope of a UDP guard cannot change'))
        state = {'spec': spec,
                 'config_hash': hashlib.sha256(config).hexdigest(),
                 'committed': False, 'retiring': retiring}
        # The new config is not on disk yet. A crash here leaves either the
        # old, committed graph or an explicitly closed pending transition.
        self.close(state)
        self._write(state)
        return state

    def _converge(self, state):
        _expect_expiration()
        deadline = time.monotonic() + CONVERGENCE_TIMEOUT
        while not _ipvs_matches(state['spec']):
            if time.monotonic() >= deadline:
                raise RuntimeError(_('UDP listener IPVS did not converge'))
            time.sleep(0.1)

    def _open(self, state):
        spec = state['spec']
        fraction = spec['fraction']
        numerator, denominator = fraction['numerator'], fraction['denominator']
        if not any(dest['weight'] > 0 for dest in spec['destinations']):
            numerator = denominator
        _nft(_rules(self.table, spec, numerator, denominator))

    def check_config(self, state):
        config_name = f'octavia-keepalivedlvs-{self.listener_id}.conf'
        config_path = self.directory / config_name
        actual = hashlib.sha256(config_path.read_bytes()).hexdigest()
        if actual != state['config_hash']:
            raise RuntimeError(_('UDP guard awaits its Keepalived config'))

    def finish(self, state):
        self.check_config(state)
        self._converge(state)
        if state['retiring']:
            self.remove_service_hooks()
            self.remove()
        else:
            self._write({**state, 'committed': True})
            self._open(state)

    def restore(self, state):
        # Systemd calls this on an independent start. An uncommitted update
        # remains closed until the agent explicitly finishes it.
        if state['committed']:
            self.check_config(state)
            self._converge(state)
            self._open(state)

    def finish_delete(self, state):
        spec = {**state['spec'], 'has_service': False, 'destinations': []}
        self._converge({**state, 'spec': spec})
        self.remove_service_hooks()
        self.remove()

    def remove(self):
        _nft(f'table ip {self.table} {{}}\ndelete table ip {self.table}\n')
        self.path.unlink(missing_ok=True)
        _sync_dir(self.path.parent)

    def install_service_hooks(self, command):
        path = Path(util.keepalived_lvs_init_path(self.listener_id))
        path = path.with_name(path.name + '.d') / DROP_IN
        args = ' '.join(shlex.quote(str(arg)) for arg in
                        (self.directory, self.listener_id))
        lines = ['[Service]',
                 f'ExecStartPre=+{command} close {args}',
                 f'ExecStartPost=+{command} restore {args}',
                 f'ExecStop=+{command} close {args}',
                 f'ExecStopPost=+{command} close {args}', '']
        write_file(path, '\n'.join(lines).encode('utf-8'), mode=0o644)

    def remove_service_hooks(self):
        path = Path(util.keepalived_lvs_init_path(self.listener_id))
        (path.with_name(path.name + '.d') / DROP_IN).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['boot', 'close', 'restore'])
    parser.add_argument('state_dir', type=Path)
    parser.add_argument('listener_id', nargs='?')
    args = parser.parse_args()
    if args.action == 'boot':
        for path in args.state_dir.glob(f'*{STATE_SUFFIX}'):
            guard = Guard(path.name.removesuffix(STATE_SUFFIX), args.state_dir)
            with guard.lock(kernel=True):
                state = guard.read()
                if state is not None:
                    guard.close(state)
        return
    guard = Guard(args.listener_id, args.state_dir)
    with guard.lock(kernel=True):
        state = guard.read()
        if state is None:
            return
        if args.action == 'restore':
            guard.restore(state)
        else:
            guard.close(state)
