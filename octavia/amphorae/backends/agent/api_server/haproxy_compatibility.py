# Copyright 2017 Rackspace, US Inc.
#
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

import os
import re
import subprocess

from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

_HTTP_RETRY_BACKOFF_PROBE = """defaults
    mode http
    timeout connect 1s
    timeout client 1s
    timeout server 1s
frontend probe
    bind 127.0.0.1:1
    default_backend route
backend route
    http-request octavia-http-policy default default 1 503 1
    server destination 127.0.0.1:2
"""


def _supports_http_retry_backoff(haproxy_cmd):
    try:
        subprocess.check_output(
            [haproxy_cmd, '-c', '-q', '-f', '/dev/stdin'],
            input=_HTTP_RETRY_BACKOFF_PROBE, stderr=subprocess.STDOUT,
            encoding='utf-8', timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


_HTTP_COOKIE_PATH_PROBE = (
    """
defaults
    mode http
    timeout client 1s
    timeout connect 1s
    timeout server 1s
frontend cookie_path_probe
    bind 127.0.0.1:12345
    http-request set-var(txn.cookie_headers) req.fhdr(cookie)
    http-request set-var(txn.cookie_probe) req.hdrs,regsub(x,y,g)
    http-request return status 200
    http-after-response replace-header Set-Cookie """
    r"'^(SRV=.*; [Pp]ath=)/(; Max-Age=[0-9]+)?$' '\1%[str(L3g=),b64dec]\2'"
    "\n")


_HTTP_HEADER_PERSISTENCE_PROBE = (
    """defaults
    mode http
    timeout client 1s
    timeout connect 1s
    timeout server 1s
frontend in
    bind 127.0.0.1:12345
    default_backend out
backend out
    acl unique "req.fhdr_cnt(\\\"x-session'\\\")" eq 1
    acl authenticated """
    "var(txn.token),hmac(sha256,txn.key),ub64enc,secure_memcmp(txn.tag) "
    """-m bool
    http-request set-var(txn.key) str(cHJvYmU=)
    http-request set-var(txn.token) "req.fhdr(\\\"x-session'\\\")" if unique
    http-request set-var(txn.issued) var(txn.token),word(3,.)
    http-request set-var(txn.age) date(0,us),sub(txn.issued)
    http-request set-var(txn.tag) var(txn.token),word(4,.)
    acl valid_age var(txn.age) -m int ge 0
    use-server target if authenticated valid_age { srv_is_up(target) }
    http-response set-var(txn.member) srv_name
    http-after-response set-var-fmt(txn.issued) "%[date(0,us)]"
    http-after-response set-header x-session %[var(txn.issued)] """
    """if { var(txn.member) -m found }
    server target 127.0.0.1:2
""")


def _valid_haproxy_config(haproxy_cmd, config):
    try:
        subprocess.run(
            [haproxy_cmd, '-c', '-q', '-f', '/dev/stdin'],
            input=config, text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _supports_http_cookie_path(haproxy_cmd):
    return _valid_haproxy_config(haproxy_cmd, _HTTP_COOKIE_PATH_PROBE)


_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS_PROBE = (
    """global
    description octavia-probe
defaults
    mode tcp
    timeout client 1s
    timeout connect 1s
    timeout server 1s
frontend probe
    bind 127.0.0.1:12345
    tcp-request inspect-delay 1s
    acl route req.ssl_sni -i -m end .example.test
    tcp-request content set-var(sess.draw) rand(16000000) """
    """if { req.ssl_hello_type 1 } route
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend target if route { var(sess.draw) -m int 0:15999999 }
backend target
""")


def _supports_tls_sni_passthrough_weighted_pools(haproxy_cmd):
    try:
        subprocess.run(
            [haproxy_cmd, '-c', '-q', '-f', '/dev/stdin'],
            input=_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS_PROBE, text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def get_haproxy_capabilities():
    haproxy_cmd = CONF.haproxy_amphora.haproxy_cmd
    try:
        output = subprocess.check_output(
            [haproxy_cmd, '-vv'],
            stderr=subprocess.STDOUT, encoding='utf-8', timeout=5)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return {}
    capabilities = {}
    if _supports_http_cookie_path(haproxy_cmd):
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH] = True
    if _valid_haproxy_config(haproxy_cmd, _HTTP_HEADER_PERSISTENCE_PROBE):
        capability = constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        capabilities[capability] = True
    version = re.match(r'HAProxy version (\d+)\.(\d+)\.', output)
    if (version and tuple(map(int, version.groups())) >= (2, 2) and
            _supports_tls_sni_passthrough_weighted_pools(haproxy_cmd)):
        capabilities[
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS
        ] = True
    if (version and int(version.group(1)) >= 3 and
            '+OPENSSL' in output.split()):
        capabilities[
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK
        ] = True
        capabilities[
            constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT
        ] = True
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT] = True
    strict_dns = 'HAProxy version 3.0.19-ade9c1262-octavia-strict-dns-v1'
    backend_sans = f'{strict_dns}-h2-alpn-v1-backend-sans-v1'
    http_request_policy = f'{backend_sans}-http-policy-v1'
    http_request_mirror = f'{http_request_policy}-http-mirror-v1'
    listener_auth = f'{http_request_mirror}-listener-auth-v1'
    retry_budget = f'{listener_auth}-backend-retry-budget-v1'
    otlp_tracing = f'{retry_budget}-listener-otlp-v1'
    retry_budget_builds = (
        f'{retry_budget} ', f'{retry_budget}-route-retry-backoff-v1 ')
    otlp_tracing_builds = (
        f'{otlp_tracing} ', f'{otlp_tracing}-route-retry-backoff-v1 ')
    strict_dns_builds = (
        f'{strict_dns} ', f'{strict_dns}-h2-alpn-v1 ',
        f'{backend_sans} ', f'{http_request_policy} ',
        f'{http_request_mirror} ', f'{listener_auth} ',
        *retry_budget_builds, *otlp_tracing_builds,
    )
    if not output.startswith(strict_dns_builds):
        return capabilities
    capabilities[constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME] = True
    capabilities[constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA] = True
    capabilities[constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH] = True
    if output.startswith(strict_dns_builds[1:]):
        capabilities[constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN] = True
    if output.startswith(strict_dns_builds[2:]):
        capabilities[
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES] = True
    if output.startswith(strict_dns_builds[3:]):
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY] = True
        if _supports_http_retry_backoff(haproxy_cmd):
            capabilities[
                constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF] = True
    if output.startswith(strict_dns_builds[4:]):
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR] = True
    if (output.startswith(strict_dns_builds[5:]) and
            re.search(r'^\s*\[OCTAVIA\] octavia-auth\s*$', output, re.M)):
        capabilities[
            constants.GATEWAY_CAPABILITY_LISTENER_REQUEST_FILTERS
        ] = True
    if output.startswith(retry_budget_builds + otlp_tracing_builds):
        capabilities[constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET] = True
    if (output.startswith(otlp_tracing_builds) and
            '+LUA' in output.split() and
            os.path.isfile(constants.HAPROXY_OTLP_TRACING_SCRIPT)):
        capabilities[constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING] = True
        if os.path.isfile(constants.HAPROXY_OTLP_SAMPLING_SCRIPT):
            capabilities[
                constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING] = True
        if os.path.isfile(constants.HAPROXY_OTLP_SPAN_ATTRIBUTES_SCRIPT):
            capabilities[
                constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SPAN_ATTRIBUTES
            ] = True
    return capabilities


def supports_backend_tls_hostname():
    return (constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME in
            get_haproxy_capabilities())


def get_haproxy_versions():
    """Get major and minor version number from haproxy

    :returns major_version: The major version digit
    :returns minor_version: The minor version digit
    """
    cmd = "haproxy -v"

    version = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)

    version_re = re.search(r'.*version (.+?)\.(.+?)(\.|-dev).*',
                           version.decode('utf-8'))

    major_version = int(version_re.group(1))
    minor_version = int(version_re.group(2))

    return major_version, minor_version


def process_cfg_for_version_compat(haproxy_cfg):

    major, minor = get_haproxy_versions()

    # Versions less than 1.6 do not support external health checks
    # Removed those configuration times
    if major < 2 and minor < 6:
        LOG.warning("Found %(major)s.%(minor)s version of haproxy. "
                    "Disabling external checks. Health monitor of type "
                    "PING will revert to TCP.",
                    {'major': major, 'minor': minor})
        haproxy_cfg = re.sub(r" * ?.*external-check ?.*\s", "", haproxy_cfg)

    return haproxy_cfg
