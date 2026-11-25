# Copyright 2011, VMware, Inc., 2014 A10 Networks
# All Rights Reserved.
#
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
#
# Borrowed from nova code base, more utilities will be added/borrowed as and
# when needed.

"""Utilities and helper functions."""

import base64
import hashlib
import ipaddress
import re
import socket
import typing

from cryptography import fernet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from stevedore import driver as stevedore_driver

from octavia.common import constants

if typing.TYPE_CHECKING:
    from octavia.network import base as network_base

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def get_hostname():
    return socket.gethostname()


def backend_tls_system_ca_pool_ids(loadbalancer):
    return {pool.id for pool in getattr(loadbalancer, 'pools', ())
            if (getattr(pool, 'backend_tls_system_ca', False) is True and
                pool.provisioning_status != constants.DELETED)}


def active_listener_pools(loadbalancer):
    if loadbalancer is None or not loadbalancer.enabled:
        return
    removed = (constants.PENDING_DELETE, constants.DELETED)
    for listener in loadbalancer.listeners:
        if (not listener.enabled or
                listener.provisioning_status in removed or
                listener.protocol in constants.LVS_PROTOCOLS):
            continue
        yield from (pool for pool in listener.pools if
                    pool.enabled and pool.provisioning_status not in removed)


def has_active_http_header_persistence(loadbalancer):
    return any(pool.session_persistence and pool.session_persistence.type ==
               constants.SESSION_PERSISTENCE_HTTP_HEADER
               for pool in active_listener_pools(loadbalancer))


def amphora_roles_match_topology(topology, roles):
    expected = {
        constants.TOPOLOGY_SINGLE: {constants.ROLE_STANDALONE},
        constants.TOPOLOGY_ACTIVE_STANDBY: {
            constants.ROLE_MASTER, constants.ROLE_BACKUP},
    }.get(topology)
    return expected is not None and len(roles) == len(expected) and (
        set(roles) == expected)


def is_protected_backend_tls_pool(pool):
    return (getattr(pool, 'backend_tls_hostname', None) is not None or
            getattr(pool, 'backend_tls_system_ca', False) is True or
            getattr(pool, 'backend_tls_require_h2', False) is True or
            bool(getattr(pool, 'backend_tls_subject_alt_names', None)))


def is_disabled_backend_tls_pool(pool):
    return not pool.enabled and (
        is_protected_backend_tls_pool(pool) or
        (pool.protocol == constants.PROTOCOL_HTTP and
         constants.GATEWAY_BACKEND_TLS_POOL_TAG in
         (getattr(pool, 'tags', None) or ())))


def has_http_retry_backoff(policy):
    request_policy = getattr(policy, 'http_request_policy', None)
    return (isinstance(request_policy, dict) and
            'backoff_ms' in request_policy.get('retry', {}))


def active_http_retry_backoff_policies(loadbalancer):
    if loadbalancer is None or not loadbalancer.enabled:
        return {}
    removed = (constants.PENDING_DELETE, constants.DELETED)
    protocols = (constants.PROTOCOL_HTTP, constants.PROTOCOL_TERMINATED_HTTPS)
    return {
        policy.id: policy
        for listener in loadbalancer.listeners
        if (listener.enabled and
            listener.provisioning_status not in removed and
            listener.protocol in protocols)
        for policy in listener.l7policies
        if (policy.enabled and policy.provisioning_status not in removed and
            has_http_retry_backoff(policy) and
            any(rule.enabled and rule.provisioning_status not in removed
                for rule in policy.l7rules))
    }


def has_tls_sni_passthrough_weighted_policies(loadbalancer, *, active=True):
    if loadbalancer is None or (active and not loadbalancer.enabled):
        return False
    removed = (constants.PENDING_DELETE, constants.DELETED)
    for listener in loadbalancer.listeners:
        if listener.protocol != constants.PROTOCOL_TCP:
            continue
        if active and (not listener.enabled or
                       listener.provisioning_status in removed):
            continue
        terminating = getattr(listener, 'tcp_tls_termination', False) is True
        mixed_mode = getattr(listener, 'tcp_tls_mixed_mode', False) is True
        for policy in listener.l7policies:
            if (policy.action != constants.L7POLICY_ACTION_WEIGHTED_TARGETS or
                    policy.provisioning_status == constants.DELETED):
                continue
            passthrough = getattr(policy, 'tcp_tls_passthrough', False) is True
            raw_tls = ((not terminating and not passthrough) or
                       (terminating and mixed_mode and passthrough))
            if not raw_tls:
                continue
            if not active or (
                    policy.enabled and
                    policy.provisioning_status not in removed and
                    any(rule.enabled and
                        rule.provisioning_status not in removed
                        for rule in policy.l7rules)):
                return True
    return False


def base64_sha1_string(string_to_hash):
    """Get a b64-encoded sha1 hash of a string. Not intended to be secure!"""
    # TODO(rm_work): applying nosec here because this is not intended to be
    # secure, it's just a way to get a consistent ID. Changing this would
    # break backwards compatibility with existing loadbalancers.
    hash_str = hashlib.sha1(string_to_hash.encode('utf-8')).digest()  # nosec
    b64_str = base64.b64encode(hash_str, str.encode('_-', 'ascii'))
    b64_sha1 = b64_str.decode('UTF-8')
    # https://github.com/haproxy/haproxy/issues/644
    return re.sub(r"^-", "x", b64_sha1)


def get_amphora_driver():
    amphora_driver = stevedore_driver.DriverManager(
        namespace='octavia.amphora.drivers',
        name=CONF.controller_worker.amphora_driver,
        invoke_on_load=True
    ).driver
    return amphora_driver


def get_network_driver() -> 'network_base.AbstractNetworkDriver':
    CONF.import_group('controller_worker', 'octavia.common.config')
    network_driver = stevedore_driver.DriverManager(
        namespace='octavia.network.drivers',
        name=CONF.controller_worker.network_driver,
        invoke_on_load=True
    ).driver
    return network_driver


def ip_version(ip_address):
    ip = ipaddress.ip_address(ip_address)
    return ip.version


def is_ipv4(ip_address):
    """Check if ip address is IPv4 address."""
    ip = ipaddress.ip_address(ip_address)
    return ip.version == 4


def is_ipv6(ip_address):
    """Check if ip address is IPv6 address."""
    ip = ipaddress.ip_address(ip_address)
    return ip.version == 6


def is_cidr_ipv6(cidr):
    """Check if CIDR is IPv6 address with subnet prefix."""
    ip = ipaddress.ip_network(cidr, strict=False)
    return ip.version == 6


def is_ipv6_lla(ip_address):
    """Check if ip address is IPv6 link local address."""
    ip = ipaddress.ip_address(ip_address)
    return ip.version == 6 and ip.is_link_local


def ip_port_str(ip_address, port):
    """Return IP port as string representation depending on address family."""
    ip = ipaddress.ip_address(ip_address)
    if ip.version == 4:
        return f"{ip}:{port}"
    return f"[{ip}]:{port}"


def netmask_to_prefix(netmask):
    return ipaddress.ip_network(f'0.0.0.0/{netmask}', strict=False).prefixlen


def ip_netmask_to_cidr(ip, netmask):
    return ipaddress.ip_network(f'{ip}/{netmask}', strict=False).with_prefixlen


def get_vip_security_group_name(loadbalancer_id):
    if loadbalancer_id:
        return constants.VIP_SECURITY_GROUP_PREFIX + loadbalancer_id
    return None


def get_compatible_value(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    return value


def _get_compatible_server_certs_key_passphrases():
    key_opts = CONF.certificates.server_certs_key_passphrase
    keys = []
    for key_opt in key_opts:
        key = str(key_opt)
        if isinstance(key, str):
            key = key.encode('utf-8')
        keys.append(
            base64.urlsafe_b64encode(key))
    return keys


def get_server_certs_key_passphrases_fernet() -> fernet.MultiFernet:
    """Get a cryptography.MultiFernet with loaded keys."""
    keys = [
        fernet.Fernet(x) for x in
        _get_compatible_server_certs_key_passphrases()]
    return fernet.MultiFernet(keys)


def subnet_ip_availability(nw_ip_avail, subnet_id, req_num_ips):
    for subnet in nw_ip_avail.subnet_ip_availability:
        if subnet['subnet_id'] == subnet_id:
            return subnet['total_ips'] - subnet['used_ips'] >= req_num_ips
    return None


def b(s):
    return s.encode('utf-8')


def expand_expected_codes(codes):
    """Expand the expected code string in set of codes.

    200-204 -> 200, 201, 202, 204
    200, 203 -> 200, 203
    """
    retval = set()
    codes = re.split(', *', codes)
    for code in codes:
        if not code:
            continue
        if '-' in code:
            low, hi = code.split('-')[:2]
            retval.update(
                str(i) for i in range(int(low), int(hi) + 1))
        else:
            retval.add(code)
    return retval


class exception_logger:
    """Wrap a function and log raised exception

    :param logger: the logger to log the exception default is LOG.exception

    :returns: origin value if no exception raised; re-raise the exception if
              any occurred

    """

    def __init__(self, logger=None):
        self.logger = logger

    def __call__(self, func):
        if self.logger is None:
            _LOG = logging.getLogger(func.__module__)
            self.logger = _LOG.exception

        def call(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    self.logger(e)
            return None
        return call


def map_protocol_to_nftable_protocol(rule_dict):
    rule_dict[constants.PROTOCOL] = (
        constants.L4_PROTOCOL_MAP[rule_dict[constants.PROTOCOL]])
    return rule_dict
