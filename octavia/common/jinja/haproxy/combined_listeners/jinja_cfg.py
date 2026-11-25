#    Copyright (c) 2015 Rackspace
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

import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import typing as tp
from urllib.parse import quote

import jinja2
from octavia_lib.common import constants as lib_consts
from oslo_log import log as logging
from oslo_utils import versionutils

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.common.config import cfg
from octavia.common import constants
from octavia.common import exceptions
from octavia.common import listener_request_filters
from octavia.common import utils as octavia_utils
from octavia.common import validate
from octavia.db import models

LOG = logging.getLogger(__name__)

PROTOCOL_MAP = {
    constants.PROTOCOL_TCP: 'tcp',
    constants.PROTOCOL_HTTP: 'http',
    constants.PROTOCOL_HTTPS: 'tcp',
    constants.PROTOCOL_PROXY: 'proxy',
    lib_consts.PROTOCOL_PROXYV2: 'proxy',
    constants.PROTOCOL_TERMINATED_HTTPS: 'http',
    lib_consts.PROTOCOL_PROMETHEUS: 'http'
}

BALANCE_MAP = {
    constants.LB_ALGORITHM_ROUND_ROBIN: 'roundrobin',
    constants.LB_ALGORITHM_LEAST_CONNECTIONS: 'leastconn',
    constants.LB_ALGORITHM_SOURCE_IP: 'source'
}

CLIENT_AUTH_MAP = {constants.CLIENT_AUTH_NONE: 'none',
                   constants.CLIENT_AUTH_OPTIONAL: 'optional',
                   constants.CLIENT_AUTH_MANDATORY: 'required'}

ACTIVE_PENDING_STATUSES = constants.SUPPORTED_PROVISIONING_STATUSES + (
    constants.DEGRADED,)

# HAProxy's rand() reduces a 32-bit draw to the requested interval.
HAPROXY_MAX_RANDOM_RANGE = 1 << 32


def _http_cookie_member_token(project_id, cookie_name, address, port):
    address = ipaddress.ip_address(address)
    address = getattr(address, 'ipv4_mapped', None) or address
    identity = json.dumps([project_id, cookie_name, str(address), port],
                          separators=(',', ':'))
    return hashlib.sha256(identity.encode('ascii')).hexdigest()[:32]


def _read_http_cookie_signing_key():
    path = CONF.haproxy_amphora.http_cookie_signing_key_file
    if path:
        try:
            # Opening first ensures the checks apply to the file being read.
            # O_NONBLOCK avoids hanging on an accidentally supplied FIFO.
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as key_file:
                mode = os.fstat(key_file.fileno()).st_mode
                non_owner = stat.S_IRWXG | stat.S_IRWXO
                if stat.S_ISREG(mode) and not mode & non_owner:
                    key = key_file.read(33)
                    if len(key) == 32:
                        return key
        except OSError:
            pass
    LOG.warning('Signed HTTP session persistence is unavailable for this '
                'render because the worker signing key is unavailable.')
    return None


def _derive_http_cookie_signing_key(key, project_id, scope, name, timeout, *,
                                    permanent=False, path_token=None):
    purpose = ('octavia-http-cookie-permanent-v1' if permanent else
               'octavia-http-cookie-v1')
    context = [purpose, project_id, scope, name, timeout]
    if path_token is not None:
        context.append(path_token)
    context = json.dumps(context, separators=(',', ':')).encode('ascii')
    digest = hmac.digest(key, context, 'sha256')
    return base64.b64encode(digest).decode('ascii')


def _derive_http_header_signing_key(key, project_id, pool_id, name, timeout):
    context = ["octavia-http-header-v1", project_id, pool_id, name, timeout]
    context = json.dumps(context, separators=(',', ':')).encode('ascii')
    return hmac.digest(key, context, 'sha256')


def _quote_config_arg(value):
    value = value.replace('\\', '\\\\')
    value = value.replace('"', '\\"').replace('$', '\\$')
    return f'"{value}"'


def _http_url_path(value):
    # Retain existing percent escapes and encode the remaining path text.
    value = re.sub(r'%(?![a-fA-F0-9]{2})', '%25', value)
    value = quote(value, safe="/%~!$&'()*+,;=:@")
    if not value.startswith('/'):
        value = '/' + value
    return value.replace('%', '%%')


# Use POSIX ERE for Amphora builds with and without PCRE. A Content-Type
# field can contain a comma inside a quoted parameter, but cannot be a list.
_HTTP_TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`|~-]+"
_HTTP_OWS = '[ \t]*'
_HTTP_QUOTED_STRING = '"([^"\\\\[:cntrl:]]|\t|\\\\([^[:cntrl:]]|\t))*"'
_CORS_DNS_LABEL = '[a-z0-9-]+'
_CORS_ANY_HOST = r"([a-z0-9.!$&'()*+,;=_~-]+|\[[a-f0-9:.]+\])"
# Match decimal ports in 1..65535, including zero-padded ports.
_CORS_PORT = (
    '0*([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|'
    '655[0-2][0-9]|6553[0-5])'
)
# HAProxy defaults. Keep the existing ingress capacity when reserving space
# for larger configured CORS response fields.
_HAPROXY_BUFFER_SIZE = 16384
_HAPROXY_REWRITE_RESERVE = 1024
# Allow for the signed value, expiry attributes, cache control and HTX blocks.
_HTTP_COOKIE_RESPONSE_OVERHEAD = 256
_CORS_RESPONSE_OVERHEAD = 512
_GRPC_CONTENT_TYPE_PATTERN = (
    f'^{_HTTP_OWS}{constants.GRPC_CONTENT_TYPE}([+]{_HTTP_TOKEN})?{_HTTP_OWS}'
    f'(;{_HTTP_OWS}'
    f'({_HTTP_TOKEN}=({_HTTP_TOKEN}|{_HTTP_QUOTED_STRING}){_HTTP_OWS})?)*$'
)
# Quote the fixed pattern for the HAProxy config parser, which expands
# dollar signs and processes escapes inside double quotes.
_GRPC_CONTENT_TYPE_ACL = '"' + _GRPC_CONTENT_TYPE_PATTERN.translate({
    ord('\\'): r'\\', ord('"'): r'\x22', ord('$'): r'\x24',
    ord('\t'): r'\x09',
}) + '"'

BASE_PATH = '/var/lib/octavia'
BASE_CRT_DIR = BASE_PATH + '/certs'

HAPROXY_TEMPLATE = os.path.abspath(
    os.path.join(os.path.dirname(__file__),
                 'templates/haproxy.cfg.j2'))

CONF = cfg.CONF

JINJA_ENV = None


def otlp_tracing_supported(loadbalancer, tracing, amp_details):
    details = amp_details or {}
    if details.get(
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING) is not True:
        return False
    if 'sampling' not in tracing:
        return True
    settings = CONF.api_settings
    provider = getattr(loadbalancer, 'provider', None) or 'amphora'
    return (
        provider in settings.enabled_listener_otlp_tracing_providers and
        provider in settings.enabled_listener_otlp_sampling_providers and
        details.get(
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING) is True)


class JinjaTemplater:

    def __init__(self,
                 base_amp_path=None,
                 base_crt_dir=None,
                 haproxy_template=None,
                 log_http=None,
                 log_server=None,
                 connection_logging=True):
        """HaProxy configuration generation

        :param base_amp_path: Base path for amphora data
        :param base_crt_dir: Base directory for certificate storage
        :param haproxy_template: Absolute path to Jinja template
        :param log_http: Haproxy HTTP logging path
        :param log_server: Haproxy Server logging path
        :param connection_logging: enable logging connections in haproxy
        """

        self.base_amp_path = base_amp_path or BASE_PATH
        self.base_crt_dir = base_crt_dir or BASE_CRT_DIR
        self.haproxy_template = haproxy_template or HAPROXY_TEMPLATE
        self.log_http = log_http
        self.log_server = log_server
        self.connection_logging = connection_logging
        self.tlsv1_3_ciphers: tp.Set[str] = set(
            CONF.api_settings.tls1_3_supported_ciphers.split(":"))

    def build_config(self, host_amphora, listeners, tls_certs,
                     haproxy_versions, amp_details, socket_path=None,
                     otlp_tls_certs=None, http_persistence_results=None,
                     otlp_publication=None, http_retry_backoff_results=None,
                     weighted_passthrough_degraded=False,
                     config_publication=None, system_ca_results=None,
                     read_http_header_key=None):
        """Convert a logical configuration to the HAProxy version

        :param host_amphora: The Amphora this configuration is hosted on
        :param listener: The listener configuration
        :param amp_details: Detail information from the amphora
        :param socket_path: The socket path for Haproxy process
        :return: Rendered configuration
        """

        # Check for any backward compatibility items we need to check
        # This is done here for upgrade scenarios where one amp in a
        # pair might be running an older amphora version.

        feature_compatibility = {}
        version = ".".join(haproxy_versions)
        # Is it newer than haproxy 1.5?
        if versionutils.is_compatible("1.6.0", version, same_major=False):
            feature_compatibility[constants.HTTP_REUSE] = True
            feature_compatibility[constants.SERVER_STATE_FILE] = True
        if versionutils.is_compatible("1.9.0", version, same_major=False):
            feature_compatibility[constants.POOL_ALPN] = True
        if int(haproxy_versions[0]) >= 2:
            feature_compatibility[lib_consts.PROTOCOL_PROMETHEUS] = True
        # haproxy 2.2 requires insecure-fork-wanted for PING healthchecks
        if versionutils.is_compatible("2.2.0", version, same_major=False):
            feature_compatibility[constants.INSECURE_FORK] = True

        return self.render_loadbalancer_obj(
            host_amphora, listeners, tls_certs=tls_certs,
            socket_path=socket_path,
            feature_compatibility=feature_compatibility,
            amp_details=amp_details, haproxy_version=version,
            otlp_tls_certs=otlp_tls_certs,
            otlp_publication=otlp_publication,
            **({'weighted_passthrough_degraded': True}
               if weighted_passthrough_degraded else {}),
            **({'config_publication': config_publication}
               if config_publication is not None else {}),
            **({'system_ca_results': system_ca_results}
               if system_ca_results is not None else {}),
            **({'http_retry_backoff_results': http_retry_backoff_results}
               if http_retry_backoff_results is not None else {}),
            **({'http_persistence_results': http_persistence_results}
               if http_persistence_results is not None else {}),
            **({'read_http_header_key': read_http_header_key}
               if read_http_header_key is not None else {}))

    def _get_template(self):
        """Returns the specified Jinja configuration template."""
        global JINJA_ENV
        if not JINJA_ENV:
            template_loader = jinja2.FileSystemLoader(
                searchpath=os.path.dirname(self.haproxy_template))
            JINJA_ENV = jinja2.Environment(
                autoescape=True,
                loader=template_loader,
                trim_blocks=True,
                lstrip_blocks=True)
        JINJA_ENV.filters['hash_amp_id'] = octavia_utils.base64_sha1_string
        return JINJA_ENV.get_template(os.path.basename(self.haproxy_template))

    def _format_log_string(self, load_balancer, protocol):
        log_format = CONF.haproxy_amphora.user_log_format.replace(
            '{{ project_id }}', load_balancer.project_id)
        log_format = log_format.replace('{{ lb_id }}', load_balancer.id)

        # Order of these filters matter.
        # TODO(johnsom) Remove when HAProxy handles the format string
        #               with HTTP variables in TCP listeners.
        #               Currently it either throws an error or just fails
        #               to log the message.
        if protocol not in constants.HAPROXY_HTTP_PROTOCOLS:
            log_format = log_format.replace('%{+Q}r', '-')
            log_format = log_format.replace('%r', '-')
            log_format = log_format.replace('%{+Q}ST', '-')
            log_format = log_format.replace('%ST', '-')

        log_format = log_format.replace(' ', '\\ ')
        return log_format

    def render_loadbalancer_obj(self, host_amphora, listeners,
                                tls_certs=None, socket_path=None,
                                feature_compatibility=None,
                                amp_details: tp.Optional[dict] = None,
                                haproxy_version=None, otlp_tls_certs=None,
                                http_persistence_results=None,
                                otlp_publication=None,
                                http_retry_backoff_results=None,
                                weighted_passthrough_degraded=False,
                                config_publication=None,
                                system_ca_results=None,
                                read_http_header_key=None):
        """Renders a templated configuration from a load balancer object

        :param host_amphora: The Amphora this configuration is hosted on
        :param listener: The listener configuration
        :param tls_certs: Dict of the TLS certificates for the listener
        :param socket_path: The socket path for Haproxy process
        :param amp_details: Detail information from the amphora
        :param haproxy_version: HAProxy version for compatibility checks
        :return: Rendered configuration
        """
        feature_compatibility = dict(feature_compatibility or {})
        weighted_passthrough = (
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        feature_compatibility[weighted_passthrough] = (
            (amp_details or {}).get(weighted_passthrough) is True)
        if weighted_passthrough_degraded:
            feature_compatibility['weighted_passthrough_degraded'] = True
        cookie_capability = (
            constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT)
        path_capability = constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH
        feature_compatibility[path_capability] = (
            (amp_details or {}).get(path_capability) is True)
        read_key = functools.cache(_read_http_cookie_signing_key)
        header_capability = (
            constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE)
        if (amp_details or {}).get(header_capability) is True:
            feature_compatibility[header_capability] = (
                read_http_header_key or read_key)
        if (amp_details or {}).get(cookie_capability) is True:
            feature_compatibility[cookie_capability] = read_key
            permanent_capability = (
                constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT)
            if (amp_details or {}).get(permanent_capability) is True:
                feature_compatibility[permanent_capability] = True
        san_capability = (
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES)
        policy_capability = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY
        backoff_capability = constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF
        retry_budget_capability = (
            constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET)
        mirror_capability = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR
        auth_capability = constants.GATEWAY_CAPABILITY_LISTENER_REQUEST_FILTERS
        fallback_capability = (
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
        sampling_capability = (
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING)
        if (amp_details or {}).get(sampling_capability) is True:
            feature_compatibility[sampling_capability] = True
        loadbalancer_obj = listeners[0].load_balancer
        loadbalancer = self._transform_loadbalancer(
            host_amphora,
            loadbalancer_obj,
            listeners,
            tls_certs,
            feature_compatibility, otlp_tls_certs=otlp_tls_certs,
            amp_details=amp_details)
        if http_persistence_results is not None and loadbalancer['enabled']:
            for listener in loadbalancer['listeners']:
                if listener['enabled']:
                    for pool in listener['pools']:
                        persistence = pool['session_persistence']
                        if not pool['enabled']:
                            continue
                        if pool.get('cookie_path_unavailable'):
                            status = constants.ERROR
                        elif 'absolute_timeout_us' in persistence:
                            status = (constants.ACTIVE if persistence.get(
                                'signing_key') else constants.ERROR)
                        elif 'cookie_path_token' in persistence:
                            status = constants.ACTIVE
                        elif (persistence and persistence['type'] ==
                              constants.SESSION_PERSISTENCE_HTTP_HEADER):
                            status = (constants.ACTIVE if persistence.get(
                                'header_signing_key') else constants.ERROR)
                        else:
                            continue
                        http_persistence_results[pool['id']] = status
        if (haproxy_version and loadbalancer['enabled'] and
                not versionutils.is_compatible("2.2.0", haproxy_version,
                                               same_major=False)):
            for listener in loadbalancer['listeners']:
                if listener['enabled'] and any(
                        policy.get('tcp_weighted_targets')
                        for policy in listener['l7policies']):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; weighted TLS SNI '
                                'pools require 2.2')
                if listener['enabled'] and (
                        'default_http_status_code' in listener or any(
                            'fixed_http_status_code' in policy
                            for policy in listener['l7policies'])):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; local HTTP '
                                'responses require 2.2')
                if (listener['enabled'] and
                        'weighted_response_codes' in listener):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; weighted L7 '
                                'policies require 2.2')
                if (listener['enabled'] and
                        ('request_header_operations_by_pool' in listener or
                         'response_header_operations_by_backend' in listener)):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; header '
                                'operations require 2.2')
                if (listener['enabled'] and
                        'request_url_rewrites_by_pool' in listener):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; request URL '
                                'rewrites require 2.2')
                if listener['enabled'] and 'cors_by_backend' in listener:
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; CORS requires 2.2')
        if loadbalancer['enabled']:
            supports_mirrors = (amp_details or {}).get(mirror_capability)
            for listener in loadbalancer['listeners']:
                if not listener['enabled']:
                    continue
                self._apply_http_retry_backoff_support(
                    listener, (amp_details or {}).get(backoff_capability)
                    is True and (amp_details or {}).get(policy_capability)
                    is True, http_retry_backoff_results)
                if (listener.get('http_request_policies_by_pool') and
                        (amp_details or {}).get(policy_capability)
                        is not True):
                    raise driver_except.AmpVersionUnsupported(
                        version='HAProxy lacks HTTP request policy support')
                if (listener.get('request_filter_sections') and
                        (amp_details or {}).get(auth_capability) is not True):
                    raise driver_except.AmpVersionUnsupported(
                        version='HAProxy lacks listener HTTP authorization')
                if (listener.get('request_mirror_pools') and
                        supports_mirrors is not True):
                    raise driver_except.AmpVersionUnsupported(
                        version='HAProxy lacks HTTP request mirror support')
                if (listener.get('client_auth_insecure_fallback') and
                        (amp_details or {}).get(fallback_capability)
                        is not True):
                    raise driver_except.AmpVersionUnsupported(
                        version='HAProxy requires insecure frontend client '
                                'certificate validation fallback support')
                if ('https_sections' in listener and haproxy_version and
                        not versionutils.is_compatible(
                            '3.0.0', haproxy_version, same_major=False)):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; HTTPS listener '
                                'isolation requires 3.0')
                if (listener.get('tcp_tls_mixed_mode') and haproxy_version and
                        not versionutils.is_compatible(
                            '3.0.0', haproxy_version, same_major=False)):
                    raise driver_except.AmpVersionUnsupported(
                        version=f'HAProxy {haproxy_version}; mixed TLS '
                                'routing requires 3.0')
                active_mirrors = {pool['id'] for pool in
                                  listener.get('request_mirror_pools', [])}
                inactive_mirrors = listener.get(
                    'mirror_only_pool_ids', set()).difference(active_mirrors)
                for pool in listener['pools']:
                    if pool['id'] in inactive_mirrors:
                        continue
                    if (pool['enabled'] and
                            pool.get('backend_retry_budget') and
                            listener['protocol'] in (
                                constants.PROTOCOL_HTTP,
                                constants.PROTOCOL_TERMINATED_HTTPS) and
                            (amp_details or {}).get(retry_budget_capability)
                            is not True):
                        raise driver_except.AmpVersionUnsupported(
                            version='HAProxy lacks backend retry budget '
                                    'support')
                    hostname = pool.get('backend_tls_hostname')
                    require_h2 = pool.get('backend_tls_require_h2')
                    sans = pool.get('backend_tls_subject_alt_names')
                    system_ca = pool.get('backend_tls_system_ca_sha256')
                    if not pool['enabled'] or (
                            hostname is None and not require_h2 and
                            not sans and not system_ca):
                        continue
                    if (amp_details or {}).get(
                            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME
                    ) is not True:
                        raise driver_except.AmpVersionUnsupported(
                            version='HAProxy requires strict backend DNS '
                                    'authentication support')
                    tcp = pool['protocol'] == PROTOCOL_MAP[
                        constants.PROTOCOL_TCP]
                    if tcp and (amp_details or {}).get(
                            constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH
                    ) is not True:
                        raise driver_except.AmpVersionUnsupported(
                            version='HAProxy requires strict TCP backend TLS '
                                    'authentication support')
                    if require_h2 and (amp_details or {}).get(
                            constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN
                    ) is not True:
                        raise driver_except.AmpVersionUnsupported(
                            version='HAProxy requires backend TLS HTTP/2 '
                                    'ALPN support')
                    if sans and (amp_details or {}).get(
                            san_capability) is not True:
                        raise driver_except.AmpVersionUnsupported(
                            version='HAProxy requires explicit backend TLS '
                                    'subject alternative name support')
                    if system_ca and (amp_details or {}).get(
                            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA
                    ) is not True:
                        raise driver_except.AmpVersionUnsupported(
                            version='Amphora lacks backend TLS system CA '
                                    'support')
                    if (not validate.is_exact_sni_name(hostname) or
                            pool['protocol'] not in (
                                PROTOCOL_MAP[constants.PROTOCOL_HTTP],
                                PROTOCOL_MAP[constants.PROTOCOL_TCP]) or
                            (tcp and (require_h2 or sans)) or
                            pool['tls_enabled'] is not True or
                            not pool.get('ca_cert') or
                            pool.get('backend_h2c')):
                        raise exceptions.ValidationException(detail=(
                            'Missing or invalid backend TLS identity or '
                            'trust configuration.'))
                    if system_ca and system_ca_results is not None:
                        system_ca_results[pool['id']] = system_ca
                    monitor = pool['health_monitor']
                    if tcp and monitor and monitor['enabled']:
                        validate.validate_tcp_tls_backend_monitor(
                            monitor['type'])
                    if sans:
                        pool['backend_tls_san_options'] = (
                            self._backend_tls_san_options(sans))
        if not socket_path:
            socket_path = (f'{self.base_amp_path}/'
                           f'{listeners[0].load_balancer.id}.sock')
        state_file_path = '{}/{}/servers-state'.format(
            self.base_amp_path,
            listeners[0].load_balancer.id) if feature_compatibility.get(
            constants.SERVER_STATE_FILE) else ''
        prometheus_listener = any(
            lsnr.protocol == lib_consts.PROTOCOL_PROMETHEUS for lsnr in
            listeners)
        require_insecure_fork = feature_compatibility.get(
            constants.INSECURE_FORK)
        enable_prometheus = prometheus_listener and feature_compatibility.get(
            lib_consts.PROTOCOL_PROMETHEUS, False)
        has_tls_termination = any(
            lsnr.protocol == lib_consts.PROTOCOL_TERMINATED_HTTPS or
            getattr(lsnr, 'tcp_tls_termination', False) is True
            for lsnr in listeners)

        jinja_dict = {
            'otlp_publication': otlp_publication,
            'config_publication': config_publication,
            'loadbalancer': loadbalancer,
            'stats_sock': socket_path,
            'log_http': self.log_http,
            'log_server': self.log_server,
            'state_file': state_file_path,
            'administrative_log_facility':
                CONF.amphora_agent.administrative_log_facility,
            'user_log_facility':
                CONF.amphora_agent.user_log_facility,
            'connection_logging': self.connection_logging,
            'enable_prometheus': enable_prometheus,
            'require_insecure_fork': require_insecure_fork,
        }
        if loadbalancer['enabled']:
            cors_reserve = max((
                cors['response_headroom']
                for listener in loadbalancer['listeners']
                if listener['enabled']
                for policies in listener.get('cors_by_backend', {}).values()
                for _, cors in policies
            ), default=0)
            persistence_reserve = max((
                max((pool['session_persistence'] or {}).get(field, 0)
                    for field in ('cookie_response_headroom',
                                  'header_response_headroom'))
                for listener in loadbalancer['listeners']
                if listener['enabled']
                for pool in listener['pools'] if pool['enabled']
            ), default=0)
            headroom = max(cors_reserve, _HAPROXY_REWRITE_RESERVE)
            headroom += persistence_reserve
            if headroom > _HAPROXY_REWRITE_RESERVE:
                # HAProxy clamps maxrewrite to half of bufsize. Round up
                # to the 64-bit HAProxy buffer alignment before calculating.
                reserve = (headroom + 15) // 16 * 16
                readable_size = _HAPROXY_BUFFER_SIZE - _HAPROXY_REWRITE_RESERVE
                jinja_dict['buffer_tuning'] = {
                    'size': max(readable_size + reserve, 2 * reserve),
                    'rewrite_reserve': reserve,
                }
        try:
            # Enable cpu-pinning only if the amphora TuneD profile is active
            if "amphora" in amp_details["active_tuned_profiles"].split():
                jinja_dict["cpu_count"] = int(amp_details["cpu_count"])
        except (KeyError, TypeError):
            pass

        if has_tls_termination:
            try:
                mem = amp_details["memory"]
                # Account for 32 KB per established connection for each
                # pair of HAProxy network sockets. Use 1024 as fallback
                # because that is what ulimit -n typically returns.
                max_conn_mem_kb = 32 * loadbalancer.get(
                    "global_connection_limit", 1024)
                # LP #2119987: Use 2/5 of the remaining memory for SSL caches
                ssl_cache_mem_kb = (mem["free"] + mem["buffers"] +
                                    mem["cached"] - max_conn_mem_kb) * 2 // 5
                # A cache block uses about 250 bytes of data.
                # The HAProxy default of ssl_cache (20000) would take up
                # 5000 KB. We don't want to go below that.
                if ssl_cache_mem_kb > 5000:
                    jinja_dict["ssl_cache"] = ssl_cache_mem_kb * 4
            except (KeyError, TypeError):
                pass

        return self._get_template().render(
            jinja_dict, constants=constants, lib_consts=lib_consts)

    def _transform_loadbalancer(self, host_amphora, loadbalancer, listeners,
                                tls_certs, feature_compatibility,
                                otlp_tls_certs=None, amp_details=None):
        """Transforms a load balancer into an object that will

           be processed by the templating system
        """
        listener_transforms = []
        for listener in listeners:
            if listener.protocol in constants.LVS_PROTOCOLS:
                continue
            transformed = self._transform_listener(
                listener, tls_certs, feature_compatibility, loadbalancer)
            tracing = getattr(listener, 'otlp_tracing', None)
            if (tracing and listener.enabled and loadbalancer.enabled and
                    listener.provisioning_status not in (
                        constants.PENDING_DELETE, constants.DELETED) and
                    otlp_tracing_supported(loadbalancer, tracing,
                                           amp_details)):
                transformed['otlp_tracing'] = self._transform_otlp_tracing(
                    listener, loadbalancer, feature_compatibility,
                    otlp_tls_certs or {})
            listener_transforms.append(transformed)
        additional_vips = [
            vip.ip_address for vip in loadbalancer.additional_vips]

        ret_value = {
            'id': loadbalancer.id,
            'vip_address': loadbalancer.vip.ip_address,
            'additional_vips': additional_vips,
            'listeners': listener_transforms,
            'topology': loadbalancer.topology,
            'enabled': loadbalancer.enabled,
            'peer_port': listeners[0].peer_port,
            'host_amphora': self._transform_amphora(
                host_amphora, feature_compatibility),
            'amphorae': loadbalancer.amphorae
        }
        mirror_pools = {}
        for listener in listener_transforms:
            if listener['enabled']:
                for pool in listener.get('request_mirror_pools', []):
                    mirror_pools[pool['id']] = pool
        if mirror_pools:
            ret_value['request_mirror_pools'] = [
                mirror_pools[pool_id] for pool_id in sorted(mirror_pools)]
        auth_pool_ids = {
            auth['pool_id'] for listener in listener_transforms
            if listener['enabled']
            for section in listener.get('request_filter_sections', ())
            for auth in section['requests'] if auth['available']
        }
        if auth_pool_ids:
            auth_pools = {
                pool.id: pool for pool in loadbalancer.pools
                if pool.id in auth_pool_ids
            }
            ret_value['listener_auth_pools'] = [
                self._transform_pool(auth_pools[pool_id],
                                     feature_compatibility, False)
                for pool_id in sorted(auth_pool_ids)]
        # NOTE(sbalukoff): Global connection limit should be a sum of all
        # listeners' connection limits.
        connection_limit_sum = 0
        for listener in listener_transforms:
            if not listener['enabled']:
                continue
            limit = listener['connection_limit']
            connection_limit_sum += limit
            if listener.get('otlp_tracing'):
                connection_limit_sum += 1
            if listener.get('mixed_tls_termination'):
                # A terminated connection also occupies a private frontend
                # connection. Keep the public per-listener limit unchanged.
                connection_limit_sum += limit
        # If there's a limit between 0 and MAX, set it, otherwise just set MAX
        if 0 < connection_limit_sum < constants.HAPROXY_MAX_MAXCONN:
            ret_value['global_connection_limit'] = connection_limit_sum
        else:
            ret_value['global_connection_limit'] = (
                constants.HAPROXY_MAX_MAXCONN)
        return ret_value

    def _transform_amphora(self, amphora, feature_compatibility):
        """Transform an amphora into an object that will

           be processed by the templating system.
        """
        return {
            'id': amphora.id,
            'lb_network_ip': amphora.lb_network_ip,
            'vrrp_ip': amphora.vrrp_ip,
            'ha_ip': amphora.ha_ip,
            'vrrp_port_id': amphora.vrrp_port_id,
            'ha_port_id': amphora.ha_port_id,
            'role': amphora.role,
            'status': amphora.status,
            'vrrp_interface': amphora.vrrp_interface,
            'vrrp_priority': amphora.vrrp_priority
        }

    def _transform_listener(self, listener: models.Listener, tls_certs,
                            feature_compatibility,
                            loadbalancer):
        """Transforms a listener into an object that will

            be processed by the templating system
        """
        tcp_tls_termination = getattr(listener, 'tcp_tls_termination',
                                      False) is True
        mixed_mode = getattr(listener, 'tcp_tls_mixed_mode', False) is True
        active = listener.enabled and loadbalancer.enabled
        client_auth_fallback = active and getattr(
            listener, 'client_authentication_insecure_fallback', None) is True
        if client_auth_fallback and (
                listener.protocol != constants.PROTOCOL_TERMINATED_HTTPS or
                listener.client_authentication !=
                constants.CLIENT_AUTH_MANDATORY or
                not (listener.tls_certificate_id or listener.sni_containers) or
                not listener.client_ca_tls_certificate_id or
                not (tls_certs or {}).get(
                    listener.client_ca_tls_certificate_id)):
            raise exceptions.ValidationException(detail=(
                'Insecure client certificate validation fallback requires '
                'HTTPS with a server certificate and a trusted client CA.'))
        if (tcp_tls_termination or mixed_mode) and active:
            if (listener.protocol != constants.PROTOCOL_TCP or
                    not tcp_tls_termination or
                    not listener.tls_certificate_id):
                raise exceptions.ValidationException(detail=(
                    'TLS termination requires a TCP listener and a server '
                    'certificate.'))
        ret_value = {
            'id': listener.id,
            'protocol_port': listener.protocol_port,
            'protocol_mode': PROTOCOL_MAP[listener.protocol],
            'protocol': listener.protocol,
            'insert_headers': listener.insert_headers,
            'enabled': listener.enabled,
            'timeout_client_data': (
                listener.timeout_client_data or
                CONF.haproxy_amphora.timeout_client_data),
            'timeout_member_connect': (
                listener.timeout_member_connect or
                CONF.haproxy_amphora.timeout_member_connect),
            'timeout_member_data': (
                listener.timeout_member_data or
                CONF.haproxy_amphora.timeout_member_data),
            'timeout_tcp_inspect': (listener.timeout_tcp_inspect or
                                    CONF.haproxy_amphora.timeout_tcp_inspect),
            lib_consts.PROTOCOL_PROMETHEUS: feature_compatibility.get(
                lib_consts.PROTOCOL_PROMETHEUS, False)
        }
        if tcp_tls_termination:
            ret_value['tcp_tls_termination'] = True
        if mixed_mode:
            ret_value['tcp_tls_mixed_mode'] = True
        if self.connection_logging:
            ret_value['user_log_format'] = (
                self._format_log_string(loadbalancer, listener.protocol))
        if listener.connection_limit and listener.connection_limit > -1:
            ret_value['connection_limit'] = listener.connection_limit
        else:
            ret_value['connection_limit'] = (
                CONF.haproxy_amphora.default_connection_limit)

        if listener.tls_certificate_id or listener.sni_containers:
            ret_value['crt_list_filename'] = os.path.join(
                CONF.haproxy_amphora.base_cert_dir,
                loadbalancer.id, f'{listener.id}.pem')

        if (tls_certs is not None and
                (not tcp_tls_termination or active)):
            if listener.client_ca_tls_certificate_id:
                ret_value['client_ca_tls_path'] = '%s' % (
                    os.path.join(
                        self.base_crt_dir, loadbalancer.id,
                        tls_certs[listener.client_ca_tls_certificate_id]))
                ret_value['client_auth'] = CLIENT_AUTH_MAP.get(
                    listener.client_authentication)
                if client_auth_fallback:
                    ret_value['client_auth'] = 'optional'
                    ret_value['client_auth_insecure_fallback'] = True

            if listener.client_crl_container_id:
                ret_value['client_crl_path'] = '%s' % (
                    os.path.join(self.base_crt_dir, loadbalancer.id,
                                 tls_certs[listener.client_crl_container_id]))

        tls_enabled = False
        if tcp_tls_termination or listener.protocol in (
                constants.PROTOCOL_TERMINATED_HTTPS,
                constants.PROTOCOL_PROMETHEUS):
            tls_enabled = True
            if listener.tls_ciphers is not None:
                if not validate.VALID_CIPHER_RE.match(listener.tls_ciphers):
                    LOG.warning("Listener %s has invalid tls_ciphers in DB, "
                                "falling back to default", listener.id)
                    tls_ciphers = (
                        cfg.CONF.api_settings.default_listener_ciphers)
                else:
                    tls_ciphers = listener.tls_ciphers
                ciphers_config_set = set(tls_ciphers.split(":"))
                # sorted in order to make the result deterministic
                ret_value['tls_ciphers'] = ":".join(
                    sorted(ciphers_config_set - self.tlsv1_3_ciphers))
                ret_value['tlsv1_3_ciphers'] = ":".join(
                    sorted(ciphers_config_set & self.tlsv1_3_ciphers))
            if listener.tls_versions is not None:
                ret_value['tls_versions'] = listener.tls_versions
                if not any(v in constants.TLS_1_3_AND_NEWER_VERSIONS for v
                           in listener.tls_versions):
                    del ret_value['tlsv1_3_ciphers']
                if not any(v in constants.TLS_PRE_1_3_VERSIONS for v in
                           listener.tls_versions):
                    del ret_value['tls_ciphers']
            if listener.alpn_protocols is not None:
                ret_value['alpn_protocols'] = ",".join(listener.alpn_protocols)
            if listener.hsts_max_age is not None:
                hsts_directives = f"max-age={listener.hsts_max_age};"
                if listener.hsts_include_subdomains:
                    hsts_directives += " includeSubDomains;"
                if listener.hsts_preload:
                    hsts_directives += " preload;"
                ret_value['hsts_directives'] = hsts_directives

        pools = []
        tcp_weighted_pool_ids = set()
        raw_weighted_pool_ids = set()
        pool_gen = (pool for pool in listener.pools if
                    pool.provisioning_status != constants.PENDING_DELETE)
        for pool in pool_gen:
            if (tcp_tls_termination and
                    pool.protocol != constants.PROTOCOL_TCP):
                continue
            pool_certs = (tls_certs or {}).get(pool.id)
            hostname = getattr(pool, 'backend_tls_hostname', None)
            if tcp_tls_termination and active and pool.enabled:
                try:
                    validate.validate_tcp_redirect_pool_protocol(
                        pool.protocol, pool.tls_enabled,
                        tcp_tls_termination=True, hostname=hostname,
                        ca_ref=pool.ca_tls_certificate_id,
                        system_ca=getattr(pool, 'backend_tls_system_ca',
                                          False))
                except exceptions.ValidationException:
                    pool_certs = {'closed': True}
            if (not tcp_tls_termination and
                    pool.protocol == constants.PROTOCOL_TCP and
                    hostname is not None):
                pool_certs = {'closed': True}
            rendered_pool = self._transform_pool(
                pool, feature_compatibility, tls_enabled,
                pool_tls_certs=pool_certs)
            if 'cookie_path_token' in rendered_pool['session_persistence']:
                removed = (constants.PENDING_DELETE, constants.DELETED)
                cookie_path_active = (
                    active and rendered_pool['enabled'] and
                    listener.protocol not in constants.LVS_PROTOCOLS and
                    listener.provisioning_status not in removed and
                    pool.protocol == constants.PROTOCOL_HTTP and
                    pool.provisioning_status not in removed)
                path_supported = feature_compatibility.get(
                    constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH)
                if not (cookie_path_active and path_supported):
                    # Render the pool without affinity so a topology that
                    # cannot serve this path can still withdraw old policies.
                    rendered_pool['session_persistence'] = ''
                    if cookie_path_active:
                        rendered_pool['cookie_path_unavailable'] = True
            if tcp_tls_termination and not pool.enabled:
                # Keep the matched route closed without falling back.
                rendered_pool['closed'] = True
            pools.append(rendered_pool)
            if (listener.protocol == constants.PROTOCOL_TCP and
                    pool.protocol == constants.PROTOCOL_TCP and
                    getattr(pool, 'load_balancer_id', None) ==
                    loadbalancer.id and
                    getattr(pool, 'project_id', None) ==
                    listener.project_id and
                    pool.provisioning_status != constants.DELETED and
                    isinstance(pool.tls_enabled, bool)):
                if tcp_tls_termination:
                    tcp_weighted_pool_ids.add(pool.id)
                if not pool.tls_enabled and hostname is None:
                    if (not feature_compatibility.get(
                            'weighted_passthrough_degraded') or
                            (pool.provisioning_status == constants.ACTIVE and
                             all(member.provisioning_status == constants.ACTIVE
                                 for member in pool.members))):
                        raw_weighted_pool_ids.add(pool.id)
        ret_value['pools'] = pools
        https_sections = None
        if listener.https_virtual_hosts is not None:
            hosts = validate.https_virtual_hosts(listener.https_virtual_hosts)
            validate.validate_https_listener(
                listener.protocol, listener.tls_certificate_id,
                listener.sni_containers, listener.default_pool_id,
                listener.default_http_response)
            ordered_hosts = sorted(hosts, key=self._https_hostname_priority)
            https_sections = {host: index for index, host in
                              enumerate(ordered_hosts, start=1)}
            ret_value['https_sections'] = https_sections
            ret_value['default_http_status_code'] = 404
        elif listener.default_http_response is not None:
            ret_value['default_http_status_code'] = (
                validate.fixed_http_status_code(
                    listener.default_http_response))
        if active and getattr(listener, 'request_filter_sections', None):
            ret_value['request_filter_sections'] = (
                self._transform_request_filters(listener, loadbalancer))
        policy_gen = (policy for policy in listener.l7policies if
                      policy.provisioning_status != constants.PENDING_DELETE)
        if https_sections is None and not mixed_mode and listener.default_pool:
            for pool in pools:
                if pool['id'] == listener.default_pool.id:
                    ret_value['default_pool'] = pool
                    break

        available_pool_ids = {
            pool['id'] for pool in pools
            if pool['enabled'] or (tcp_tls_termination and pool.get('closed'))
        }
        available_mirror_pool_ids = {
            pool['id'] for pool in pools
            if pool['enabled'] and pool['protocol'] == 'http' and
            not pool.get('header_persistence_unavailable') and
            listener.protocol in (constants.PROTOCOL_HTTP,
                                  constants.PROTOCOL_TERMINATED_HTTPS)
        }
        primary_pool_ids = {getattr(listener.default_pool, 'id', None)}
        configured_mirror_pool_ids = set()
        if listener.protocol == constants.PROTOCOL_TCP:
            policy_gen = (policy for policy in policy_gen
                          if (policy.action ==
                              constants.L7POLICY_ACTION_WEIGHTED_TARGETS or
                              (self._is_routable_sni_policy(
                                  policy, available_pool_ids,
                                  tcp_tls_termination) and
                               (mixed_mode or not getattr(
                                   policy, 'tcp_tls_passthrough', False)))))
        else:
            policy_gen = (policy for policy in policy_gen if not any(
                rule.enabled and rule.type == constants.L7RULE_TYPE_TLS_SNI
                for rule in policy.l7rules))
        l7policies = []
        for policy in policy_gen:
            if (listener.protocol == constants.PROTOCOL_TCP and
                    policy.action ==
                    constants.L7POLICY_ACTION_WEIGHTED_TARGETS):
                if not policy.enabled or policy.provisioning_status in (
                        constants.PENDING_DELETE, constants.DELETED):
                    continue
                rules = self._active_l7rules(policy)
                if not rules:
                    continue
                if not all(validate.is_tls_sni_rule(rule) for rule in rules):
                    # An unreadable selector has no safe hostname scope.
                    ret_value['enabled'] = False
                    continue
                transformed = self._transform_tls_sni_weighted_policy(
                    policy, rules, tcp_tls_termination, mixed_mode,
                    tcp_weighted_pool_ids & available_pool_ids,
                    raw_weighted_pool_ids & available_pool_ids,
                    feature_compatibility)
                l7policies.append(transformed)
                primary_pool_ids.update(
                    target.get('pool_id')
                    for target in transformed['tcp_weighted_targets'])
                continue
            hostname = policy.https_listener_hostname
            if https_sections is None:
                if hostname is not None:
                    continue
            elif (hostname not in https_sections or
                  policy.provisioning_status == constants.DELETED):
                # A stale or unscoped policy must never handle another host.
                continue
            transformed = self._transform_l7policy(
                policy, feature_compatibility, tls_enabled, tls_certs,
                available_pool_ids, available_mirror_pool_ids)
            primary_pool_ids.add(getattr(policy.redirect_pool, 'id', None))
            targets = getattr(policy, 'targets', None) or []
            primary_pool_ids.update(
                target.get('pool_id') for target in targets)
            configured_mirror_pool_ids.update(validate.request_mirror_pool_ids(
                getattr(policy, 'request_mirrors', None), targets))
            if https_sections is not None:
                transformed['https_section'] = https_sections[hostname]
            if mixed_mode:
                transformed['tcp_tls_passthrough'] = (
                    getattr(policy, 'tcp_tls_passthrough', False) is True)
            l7policies.append(transformed)
        if any('request_redirect' in policy for policy in l7policies):
            # For requests matching a structured redirect, give legacy
            # redirects a backend in the position-ordered switching phase.
            redirect_modes = {
                constants.L7POLICY_ACTION_REDIRECT_TO_URL: ('location', 'url'),
                constants.L7POLICY_ACTION_REDIRECT_PREFIX: (
                    'prefix', 'prefix'),
            }
            for policy in l7policies:
                if (policy['action'] not in redirect_modes or
                        not (policy['enabled'] and policy['l7rules'])):
                    continue
                mode, field = redirect_modes[policy['action']]
                destination = policy[f'redirect_{field}']
                if destination:
                    policy['request_redirect'] = {
                        'mode': mode,
                        'argument': _quote_config_arg(
                            destination.replace('%', '%%'))}
        if listener.protocol == constants.PROTOCOL_TCP:
            l7policies.sort(key=self._sni_policy_priority)
            if tcp_tls_termination:
                pools_by_id = {pool['id']: pool for pool in pools}
                for policy in l7policies:
                    if policy['redirect_pool']:
                        pool_id = policy['redirect_pool']['id']
                        policy['redirect_pool'] = pools_by_id[pool_id]
            if mixed_mode or (l7policies and not tcp_tls_termination):
                ret_value['inspect_tls_sni'] = True
                if not ret_value['timeout_tcp_inspect']:
                    ret_value['timeout_tcp_inspect'] = (
                        constants.DEFAULT_TLS_SNI_INSPECT_TIMEOUT)
        if mixed_mode:
            ret_value['mixed_tls_termination'] = any(
                not policy['tcp_tls_passthrough'] and
                policy.get('tcp_weighted_targets') != []
                for policy in l7policies)
            ret_value['mixed_tls_reject'] = any(
                policy['redirect_pool'] and policy['tcp_tls_passthrough'] and
                (policy['redirect_pool']['tls_enabled'] or
                 policy['redirect_pool'].get('backend_tls_hostname'))
                for policy in l7policies)
        ret_value['l7policies'] = l7policies
        requests_by_pool = {}
        responses_by_backend = {}
        cors_by_backend = {}
        rewrites_by_pool = {}
        http_request_policies_by_pool = {}
        target_filters_by_pool = {}
        mirrored_rules_by_backend = {}
        mirror_pool_ids = set()
        for policy in l7policies:
            request_ops = policy.get('request_header_operations')
            response_ops = policy.get('response_header_operations')
            cors = policy.get('request_cors')
            rewrite = policy.get('request_url_rewrite')
            request_policy = policy.get('http_request_policy')
            pool_ids = set()
            fixed_responses = set()
            if 'weighted_targets' in policy:
                for target in policy['weighted_targets']:
                    if 'pool_id' in target:
                        pool_id = target['pool_id']
                        pool_ids.add(pool_id)
                        if target.get('request_filters'):
                            target_filters_by_pool.setdefault(
                                pool_id, []).append((policy['id'], target))
                        mirror_pool_ids.update(
                            target.get('mirror_pool_ids', []))
                    else:
                        code = target["status_code"]
                        fixed_responses.add(f'weighted-{code}')
            elif 'fixed_http_status_code' in policy:
                fixed_responses.add(policy['id'])
            elif policy['redirect_pool']:
                redirect_pool = policy['redirect_pool']
                pool_id = redirect_pool['id']
                if pool_id in available_pool_ids:
                    pool_ids.add(pool_id)
                elif cors is not None and redirect_pool.get('closed'):
                    cors_by_backend.setdefault(('pool', pool_id), []).append(
                        (policy['id'], cors))
            mirrors = policy.get('request_mirrors', [])
            if mirrors:
                backends = [('pool', pool_id) for pool_id in sorted(pool_ids)]
                backends.extend(('fixed', response_id)
                                for response_id in sorted(fixed_responses))
                if policy['redirect_pool'] and policy['redirect_pool'].get(
                        'closed'):
                    backends.append(('pool', policy['redirect_pool']['id']))
                if backends:
                    operations = self._transform_request_pipeline(
                        request_ops or [], rewrite or [], mirrors)
                    mirror_pool_ids.update(mirror['pool_id']
                                           for mirror in mirrors)
                    for backend in backends:
                        mirrored_rules_by_backend.setdefault(
                            backend, []).append((policy['id'], operations))
            for pool_id in pool_ids:
                if request_policy is not None:
                    http_request_policies_by_pool.setdefault(
                        pool_id, []).append((policy['id'], request_policy))
                if rewrite and not mirrors:
                    rewrites_by_pool.setdefault(pool_id, []).append(
                        (policy['id'], rewrite))
                if request_ops and not mirrors:
                    requests_by_pool.setdefault(pool_id, []).append(
                        (policy['id'], request_ops))
                if response_ops:
                    responses_by_backend.setdefault(('pool', pool_id),
                                                    []).append(
                        (policy['id'], response_ops))
                if cors is not None:
                    cors_by_backend.setdefault(('pool', pool_id), []).append(
                        (policy['id'], cors))
            if response_ops:
                for response_id in fixed_responses:
                    responses_by_backend.setdefault(('fixed', response_id),
                                                    []).append(
                        (policy['id'], response_ops))
            if cors is not None:
                for response_id in fixed_responses:
                    cors_by_backend.setdefault(('fixed', response_id),
                                              []).append((policy['id'], cors))
        if target_filters_by_pool:
            ret_value['target_filters_by_pool'] = target_filters_by_pool
        if mirrored_rules_by_backend:
            ret_value['mirrored_rules_by_backend'] = mirrored_rules_by_backend
        if mirror_pool_ids:
            ret_value['request_mirror_pools'] = [
                pool for pool in pools
                if pool['id'] in mirror_pool_ids]
        if configured_mirror_pool_ids - primary_pool_ids:
            ret_value['mirror_only_pool_ids'] = (
                configured_mirror_pool_ids - primary_pool_ids)
        if requests_by_pool:
            ret_value['request_header_operations_by_pool'] = requests_by_pool
        if http_request_policies_by_pool:
            ret_value['http_request_policies_by_pool'] = (
                http_request_policies_by_pool)
        if rewrites_by_pool:
            ret_value['request_url_rewrites_by_pool'] = rewrites_by_pool
        if responses_by_backend:
            ret_value['response_header_operations_by_backend'] = (
                responses_by_backend)
        if cors_by_backend:
            ret_value['cors_by_backend'] = cors_by_backend

        weighted_policies = [policy for policy in l7policies
                             if 'weighted_targets' in policy]
        if weighted_policies:
            ret_value['weighted_response_codes'] = sorted({
                target['status_code'] for policy in weighted_policies
                for target in policy['weighted_targets']
                if 'status_code' in target})
        return ret_value

    def _transform_request_filters(self, listener, loadbalancer):
        sections = listener_request_filters.normalize(
            listener.request_filter_sections)
        listener_request_filters.validate_listener(listener.protocol, sections)
        pool_ids = listener_request_filters.pool_ids(sections)
        available = {
            pool.id for pool in loadbalancer.pools
            if pool.id in pool_ids and pool.enabled and
            pool.project_id == listener.project_id and
            pool.load_balancer_id == listener.load_balancer_id and
            pool.provisioning_status not in (
                constants.PENDING_DELETE, constants.DELETED) and
            listener_request_filters.valid_pool(pool)
        }

        def encode(value):
            # Config arguments contain only hex digits or the empty marker.
            return value.encode('ascii').hex() or '-'

        ordered_sections = sorted(
            sections, key=lambda section: self._https_hostname_priority(
                section['hostname']))
        result = []
        for index, section in enumerate(ordered_sections, start=1):
            requests = []
            for step in section.get('requests', ()):
                auth = step['http']
                requests.append({
                    'pool_id': auth['pool_id'],
                    'available': auth['pool_id'] in available,
                    'prefix': encode(auth.get('path_prefix', '')),
                    'request_headers': encode(','.join(
                        auth.get('allowed_request_headers', ()))),
                    'response_headers': encode(','.join(
                        auth.get('allowed_response_headers', ()))),
                })
            result.append({'id': index, 'hostname': section['hostname'],
                           'reject': section.get('reject', False),
                           'requests': requests})
        return result

    @staticmethod
    def _backend_tls_san_options(sans):
        return [
            ('dns:' + entry['hostname'] if entry['type'] == 'Hostname' else
             'uri-hex:' + entry['uri'].encode('ascii').hex())
            for entry in validate.backend_tls_subject_alt_names(sans)]

    def _transform_otlp_tracing(self, listener, loadbalancer,
                                feature_compatibility, pool_certs):
        tracing = validate.otlp_tracing(listener.otlp_tracing)
        sampling_capability = (
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING)
        tracing['script'] = (
            constants.HAPROXY_OTLP_SAMPLING_SCRIPT
            if feature_compatibility.get(sampling_capability)
            else constants.HAPROXY_OTLP_TRACING_SCRIPT)
        tracing['socket'] = (
            f'{constants.HAPROXY_OTLP_TRACING_SOCKET_DIR}/{listener.id}.sock')
        pool = next((pool for pool in loadbalancer.pools if
                     pool.id == tracing['collector_pool_id']), None)
        if (pool is None or not pool.enabled or pool.provisioning_status in
                (constants.PENDING_DELETE, constants.DELETED)):
            return tracing

        try:
            validate.validate_otlp_collector_transport(
                pool.protocol, pool.backend_h2c, pool.backend_tls_require_h2,
                pool.tls_enabled, pool.alpn_protocols)
            certs = pool_certs.get(pool.id, {})
            required_material = {
                'client_cert': pool.tls_certificate_id,
                'ca_cert': pool.ca_tls_certificate_id,
                'crl': pool.crl_container_id,
            }
            if certs.get('closed') or (pool.tls_enabled and any(
                    ref and not certs.get(name)
                    for name, ref in required_material.items())):
                return tracing
            rendered = self._transform_pool(
                pool, feature_compatibility, False, pool_tls_certs=certs)
            if not rendered['enabled']:
                return tracing
            if 'alpn_protocols' in rendered:
                rendered['alpn_protocols'] = 'http/1.1'
            sans = rendered.get('backend_tls_subject_alt_names')
            if sans:
                rendered['backend_tls_san_options'] = (
                    self._backend_tls_san_options(sans))
        except exceptions.ValidationException:
            LOG.warning('Ignoring invalid OTLP collector pool %s', pool.id)
            return tracing
        tracing['pool'] = rendered
        return tracing

    def _transform_pool(self, pool, feature_compatibility,
                        listener_tls_enabled, pool_tls_certs=None):
        """Transforms a pool into an object that will

            be processed by the templating system
        """
        proxy_protocol_version = None
        if pool.protocol == constants.PROTOCOL_PROXY:
            proxy_protocol_version = 1
        if pool.protocol == lib_consts.PROTOCOL_PROXYV2:
            proxy_protocol_version = 2
        ret_value = {
            'id': pool.id,
            'protocol': PROTOCOL_MAP[pool.protocol],
            'proxy_protocol': proxy_protocol_version,
            'listener_tls_enabled': listener_tls_enabled,
            'lb_algorithm': BALANCE_MAP.get(pool.lb_algorithm, 'roundrobin'),
            'members': [],
            'health_monitor': '',
            'session_persistence': '',
            'enabled': pool.enabled,
            'operating_status': pool.operating_status,
            'stick_size': CONF.haproxy_amphora.haproxy_stick_size,
            constants.HTTP_REUSE: feature_compatibility.get(
                constants.HTTP_REUSE, False),
            'ca_tls_path': '',
            'crl_path': '',
            'tls_enabled': pool.tls_enabled
        }
        hostname = getattr(pool, 'backend_tls_hostname', None)
        if hostname is not None:
            ret_value['backend_tls_hostname'] = hostname
        if getattr(pool, 'backend_tls_require_h2', False) is True:
            ret_value['backend_tls_require_h2'] = True
        sans = getattr(pool, 'backend_tls_subject_alt_names', None)
        if sans:
            ret_value['backend_tls_subject_alt_names'] = sans
        system_ca = getattr(pool, 'backend_tls_system_ca', False) is True
        system_ca_digest = (pool_tls_certs or {}).get('system_ca_sha256')
        if (octavia_utils.is_disabled_backend_tls_pool(pool) or
                (pool_tls_certs and pool_tls_certs.get('closed')) or
                (system_ca and not (system_ca_digest and
                                    pool_tls_certs.get('ca_cert')))):
            ret_value['closed'] = True
            ret_value['enabled'] = False
            return ret_value
        rejection = getattr(pool, 'tcp_connection_rejection', None)
        if pool.protocol == constants.PROTOCOL_TCP and rejection is not None:
            ret_value['tcp_connection_rejection'] = (
                validate.tcp_connection_rejection(rejection))
        budget = getattr(pool, 'backend_retry_budget', None)
        if budget is not None:
            ret_value['backend_retry_budget'] = (
                validate.backend_retry_budget(budget))
        members_gen = (mem for mem in pool.members if
                       mem.provisioning_status != constants.PENDING_DELETE)
        members = [self._transform_member(x, feature_compatibility)
                   for x in members_gen]
        ret_value['members'] = members
        health_mon = pool.health_monitor
        if (health_mon and
                health_mon.provisioning_status != constants.PENDING_DELETE):
            ret_value['health_monitor'] = self._transform_health_monitor(
                health_mon, feature_compatibility)
        if pool.session_persistence:
            persistence = self._transform_session_persistence(
                pool.session_persistence, feature_compatibility)
            ret_value['session_persistence'] = persistence
            name = persistence['cookie_name']
            path_token = persistence.get('cookie_path_token', '')
            if (persistence['type'] ==
                    constants.SESSION_PERSISTENCE_HTTP_COOKIE and
                    (name or path_token)):
                for member in members:
                    token = _http_cookie_member_token(
                        pool.project_id, name, member['address'],
                        member['protocol_port']) if name else member['id']
                    member['persistence_cookie'] = path_token + token
            timeout = getattr(pool.session_persistence,
                              'cookie_absolute_timeout_ms', None)
            scope = getattr(pool.session_persistence, 'cookie_scope', None)
            permanent = getattr(pool.session_persistence, 'cookie_permanent',
                                False) is True
            if timeout is not None or scope is not None or permanent:
                self._configure_absolute_http_cookie(
                    pool, persistence, timeout, scope, permanent,
                    feature_compatibility)
            if (persistence['type'] ==
                    constants.SESSION_PERSISTENCE_HTTP_HEADER):
                self._configure_http_header_persistence(
                    pool, persistence, members, feature_compatibility)
                ret_value['header_persistence_unavailable'] = (
                    'header_signing_key' not in persistence)
        if (pool.tls_certificate_id and pool_tls_certs and
                pool_tls_certs.get('client_cert')):
            ret_value['client_cert'] = pool_tls_certs.get('client_cert')
        if getattr(pool, 'backend_h2c', False) is True:
            ret_value['backend_h2c'] = True
        if pool.tls_enabled is True:
            if pool.tls_ciphers is not None:
                if not validate.VALID_CIPHER_RE.match(pool.tls_ciphers):
                    LOG.warning("Pool %s has invalid tls_ciphers in DB, "
                                "falling back to default", pool.id)
                    tls_ciphers = (
                        cfg.CONF.api_settings.default_pool_ciphers)
                else:
                    tls_ciphers = pool.tls_ciphers
                ciphers_config_set = set(tls_ciphers.split(":"))
                # sorted in order to make the result deterministic
                ret_value['tls_ciphers'] = ":".join(
                    sorted(ciphers_config_set - self.tlsv1_3_ciphers))
                ret_value['tlsv1_3_ciphers'] = ":".join(
                    sorted(ciphers_config_set & self.tlsv1_3_ciphers))
            if pool.tls_versions is not None:
                ret_value['tls_versions'] = pool.tls_versions
                if not any(v in constants.TLS_1_3_AND_NEWER_VERSIONS for v
                           in pool.tls_versions):
                    del ret_value['tlsv1_3_ciphers']
                if not any(v in constants.TLS_PRE_1_3_VERSIONS for v in
                           pool.tls_versions):
                    del ret_value['tls_ciphers']
            if (pool.alpn_protocols is not None and
                    feature_compatibility.get(constants.POOL_ALPN, False)):
                ret_value['alpn_protocols'] = ",".join(pool.alpn_protocols)
        if system_ca:
            ret_value['backend_tls_system_ca_sha256'] = system_ca_digest
        if ((pool.ca_tls_certificate_id or system_ca) and pool_tls_certs and
                pool_tls_certs.get('ca_cert')):
            ret_value['ca_cert'] = pool_tls_certs.get('ca_cert')
        if (pool.crl_container_id and pool_tls_certs and
                pool_tls_certs.get('crl')):
            ret_value['crl'] = pool_tls_certs.get('crl')

        return ret_value

    @staticmethod
    def _configure_absolute_http_cookie(pool, persistence, timeout, scope,
                                        permanent, feature_compatibility):
        name = persistence['cookie_name']
        if (pool.protocol != constants.PROTOCOL_HTTP or
                persistence['type'] !=
                constants.SESSION_PERSISTENCE_HTTP_COOKIE or
                not name or not validate.is_valid_http_cookie_scope(scope) or
                not validate.is_valid_http_cookie_absolute_timeout(timeout)):
            raise exceptions.ValidationException(detail=_(
                'Invalid persisted absolute HTTP cookie policy.'))
        # Keep the legacy cookie tokens off these server lines even when the
        # key is unavailable or the Amphora does not support this profile.
        persistence['absolute_timeout_us'] = timeout * 1000
        if permanent:
            if not feature_compatibility.get(
                    constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT):
                return
            persistence['cookie_max_age'] = (timeout + 999) // 1000
        read_key = feature_compatibility.get(
            constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT)
        if read_key:
            key = read_key()
            if key is not None:
                persistence['signing_key'] = _derive_http_cookie_signing_key(
                    key, pool.project_id, scope, name, timeout,
                    permanent=permanent,
                    path_token=persistence.get('cookie_path_token'))

    @staticmethod
    def _configure_http_header_persistence(pool, persistence, members,
                                           feature_compatibility):
        capability = constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        read_key = feature_compatibility.get(capability)
        name = pool.session_persistence.header_name
        timeout = pool.session_persistence.header_absolute_timeout_ms
        if (pool.protocol != constants.PROTOCOL_HTTP or
                not validate.is_valid_http_header_persistence_name(name) or
                (timeout is not None and
                 not validate.is_valid_http_header_absolute_timeout(timeout))):
            LOG.warning('Ignoring invalid persisted HTTP_HEADER policy on '
                        'pool %s.', pool.id)
            return
        key = read_key() if read_key else None
        if key is None:
            return
        name = name.lower()
        signing_key = _derive_http_header_signing_key(
            key, pool.project_id, pool.id, name, timeout)
        persistence.update({
            'header_config_name': _quote_config_arg(name),
            # Quote once for the sample expression and once for the line.
            'header_fetch': _quote_config_arg(f'req.fhdr("{name}")'),
            'header_count': _quote_config_arg(f'req.fhdr_cnt("{name}")'),
            'header_signing_key': base64.b64encode(signing_key).decode(),
            'header_response_headroom': len(name) + 256,
        })
        if timeout is not None:
            persistence['header_absolute_timeout_us'] = timeout * 1000
        for member in members:
            member['header_persistence_token'] = hmac.digest(
                signing_key, member['id'].encode('ascii'), 'sha256').hex()[:32]

    @staticmethod
    def _transform_session_persistence(persistence, feature_compatibility):
        """Transforms session persistence into an object that will

            be processed by the templating system
        """
        name = persistence.cookie_name
        rendered = {'type': persistence.type, 'cookie_name': name}
        if persistence.type == constants.SESSION_PERSISTENCE_HTTP_COOKIE:
            if getattr(persistence, 'http_cookie_name_enabled', False) is True:
                if not validate.is_valid_http_cookie_name(name):
                    raise exceptions.ValidationException(detail=_(
                        'Invalid configured HTTP_COOKIE name.'))
            else:
                rendered['cookie_name'] = None
            path = getattr(persistence, 'cookie_path', None)
            if path not in (None, constants.HTTP_COOKIE_DEFAULT_PATH):
                if not validate.is_valid_http_cookie_path(path):
                    raise exceptions.ValidationException(detail=_(
                        'Invalid persisted HTTP_COOKIE path.'))
                # Decode after configuration parsing. Double backslashes for
                # the regex replacement performed after format expansion.
                replacement = path.replace('\\', '\\\\').encode('ascii')
                rendered['cookie_path_replacement'] = (
                    base64.b64encode(replacement).decode('ascii'))
                # The prefix distinguishes cookies for this path from stored
                # cookies of the same name issued with earlier paths.
                rendered['cookie_path_token'] = hashlib.sha256(
                    path.encode('ascii')).hexdigest()[:32]
                rendered['cookie_path_trailing_space'] = path.endswith(' ')
                cookie_name = rendered['cookie_name'] or 'SRV'
                rendered['cookie_response_headroom'] = (
                    len(path) + len(cookie_name) +
                    _HTTP_COOKIE_RESPONSE_OVERHEAD)
        return rendered

    @staticmethod
    def _transform_member(member, feature_compatibility):
        """Transforms a member into an object that will

            be processed by the templating system
        """
        return {
            'id': member.id,
            'address': member.ip_address,
            'protocol_port': member.protocol_port,
            'weight': member.weight,
            'enabled': member.enabled,
            'subnet_id': member.subnet_id,
            'operating_status': member.operating_status,
            'monitor_address': member.monitor_address,
            'monitor_port': member.monitor_port,
            'backup': member.backup
        }

    def _transform_health_monitor(self, monitor, feature_compatibility):
        """Transforms a health monitor into an object that will

            be processed by the templating system
        """
        codes = None
        if monitor.expected_codes:
            codes = '|'.join(octavia_utils.expand_expected_codes(
                monitor.expected_codes))
        return {
            'id': monitor.id,
            'type': monitor.type,
            'delay': monitor.delay,
            'timeout': monitor.timeout,
            'fall_threshold': monitor.fall_threshold,
            'rise_threshold': monitor.rise_threshold,
            'http_method': monitor.http_method,
            'url_path': monitor.url_path,
            'expected_codes': codes,
            'enabled': monitor.enabled,
            'http_version': monitor.http_version,
            'domain_name': monitor.domain_name,
        }

    @staticmethod
    def _sanitize_url(value, field_name, obj_id):
        if value and validate.INVALID_URL_CHARS_RE.search(value):
            LOG.warning("L7policy %s has invalid %s in DB, clearing",
                        obj_id, field_name)
            return None
        return value

    @staticmethod
    def _active_l7rules(policy):
        return [rule for rule in policy.l7rules if rule.enabled and
                rule.provisioning_status not in (constants.PENDING_DELETE,
                                                 constants.DELETED)]

    def _is_routable_sni_policy(self, policy, available_pool_ids,
                                tcp_tls_termination):
        pool = policy.redirect_pool
        if (not policy.enabled or
                policy.provisioning_status == constants.DELETED or
                policy.action != constants.L7POLICY_ACTION_REDIRECT_TO_POOL or
                policy.request_header_operations or
                policy.response_header_operations or
                not pool or pool.id not in available_pool_ids or
                pool.protocol != constants.PROTOCOL_TCP or
                (not tcp_tls_termination and pool.tls_enabled) or
                pool.provisioning_status == constants.DELETED):
            return False
        rules = self._active_l7rules(policy)
        return bool(rules) and all(validate.is_tls_sni_rule(r) for r in rules)

    @staticmethod
    def _https_hostname_priority(hostname):
        if hostname == '*':
            return 2, 0
        if hostname.startswith('*.'):
            return 1, -len(hostname)
        return 0, 0

    @staticmethod
    def _sni_policy_priority(policy):
        # Rules in a policy are ANDed. An exact rule constrains the entire
        # policy to one name. Otherwise its longest suffix is most specific.
        # Stable sorting keeps listener policy positions for equal matches.
        exact = constants.L7RULE_COMPARE_TYPE_EQUAL_TO
        return min(
            (0, 0) if rule['compare_type'] == exact
            else (1, -len(rule['value']))
            for rule in policy['l7rules'])

    def _transform_tls_sni_weighted_policy(self, policy, rules,
                                           tcp_tls_termination, mixed_mode,
                                           terminated_pool_ids, raw_pool_ids,
                                           feature_compatibility):
        passthrough = getattr(policy, 'tcp_tls_passthrough', False)
        rendered = {
            'id': policy.id,
            'action': policy.action,
            'enabled': True,
            'redirect_pool': None,
            'tcp_tls_passthrough': passthrough is True,
            'l7rules': [self._transform_l7rule(rule, feature_compatibility)
                        for rule in rules],
            'tcp_weighted_targets': [],
        }
        if any(getattr(policy, field, None) is not None for field in (
                'redirect_pool', 'redirect_pool_id', 'redirect_url',
                'redirect_prefix', 'redirect_http_code', 'redirect_request',
                'fixed_response', 'request_url_rewrite', 'request_cors',
                'http_request_policy', 'https_listener_hostname')) or any(
                    getattr(policy, field, None) for field in (
                        'request_header_operations',
                        'response_header_operations', 'request_mirrors')):
            return rendered
        try:
            raw_tls = validate.tls_sni_weighted_passthrough(
                tcp_tls_termination, mixed_mode, passthrough)
            targets = validate.tls_sni_weighted_targets(policy.targets)
        except (exceptions.InvalidL7PolicyArgs, exceptions.ValidationException,
                TypeError, ValueError):
            # Keep the match and close it ahead of any less specific route.
            return rendered
        capability = (
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        if raw_tls and (
                not feature_compatibility.get(capability) or
                (feature_compatibility.get('weighted_passthrough_degraded') and
                 (policy.provisioning_status != constants.ACTIVE or
                  any(rule.provisioning_status != constants.ACTIVE
                      for rule in rules)))):
            return rendered
        pool_ids = raw_pool_ids if raw_tls else terminated_pool_ids
        intervals, total = self._transform_weighted_targets(targets, pool_ids)
        for interval in intervals:
            interval.pop('status_code', None)
        rendered.update(tcp_weighted_targets=intervals, total_weight=total)
        return rendered

    def _transform_l7policy(self, l7policy, feature_compatibility,
                            listener_tls_enabled, tls_certs=None,
                            available_pool_ids=(),
                            available_mirror_pool_ids=()):
        """Transforms an L7 policy into an object that will

            be processed by the templating system
        """
        ret_value = {
            'id': l7policy.id,
            'action': l7policy.action,
            'redirect_url': self._sanitize_url(
                l7policy.redirect_url, 'redirect_url', l7policy.id),
            'redirect_prefix': self._sanitize_url(
                l7policy.redirect_prefix, 'redirect_prefix', l7policy.id),
            'enabled': l7policy.enabled
        }
        if (l7policy.redirect_pool and
            l7policy.redirect_pool.provisioning_status !=
                constants.PENDING_DELETE):
            kwargs = {}
            if tls_certs is not None and tls_certs.get(
                    l7policy.redirect_pool.id):
                kwargs = {'pool_tls_certs':
                          tls_certs.get(l7policy.redirect_pool.id)}
            ret_value['redirect_pool'] = self._transform_pool(
                l7policy.redirect_pool, feature_compatibility,
                listener_tls_enabled, **kwargs)
        else:
            ret_value['redirect_pool'] = None
        if (l7policy.action in [constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                                constants.L7POLICY_ACTION_REDIRECT_PREFIX,
                                constants.L7POLICY_ACTION_REDIRECT_REQUEST] and
                l7policy.redirect_http_code):
            ret_value['redirect_http_code'] = l7policy.redirect_http_code
        else:
            ret_value['redirect_http_code'] = None
        l7rules = [self._transform_l7rule(rule, feature_compatibility)
                   for rule in self._active_l7rules(l7policy)]
        ret_value['l7rules'] = l7rules
        if l7policy.enabled and l7rules:
            if l7policy.action == constants.L7POLICY_ACTION_FIXED_RESPONSE:
                ret_value['fixed_http_status_code'] = (
                    validate.fixed_http_status_code(l7policy.fixed_response))
            elif l7policy.action == constants.L7POLICY_ACTION_WEIGHTED_TARGETS:
                targets, total = self._transform_weighted_targets(
                    l7policy.targets, available_pool_ids,
                    available_mirror_pool_ids)
                ret_value['weighted_targets'] = targets
                ret_value['total_weight'] = total
            elif l7policy.action == constants.L7POLICY_ACTION_REDIRECT_REQUEST:
                ret_value['request_redirect'] = (
                    self._transform_request_redirect(l7policy.redirect_request))
                ret_value['redirect_http_code'] = (
                    l7policy.redirect_http_code or 302)
            if l7policy.request_url_rewrite is not None:
                ret_value['request_url_rewrite'] = (
                    self._transform_request_url_rewrite(
                        l7policy.request_url_rewrite))
            mirrors = self._active_mirrors(
                getattr(l7policy, 'request_mirrors', None),
                available_mirror_pool_ids)
            if mirrors:
                ret_value['request_mirrors'] = mirrors
            request_policy = getattr(l7policy, 'http_request_policy', None)
            if (request_policy is not None and l7policy.action in
                    (constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
                     constants.L7POLICY_ACTION_WEIGHTED_TARGETS)):
                ret_value['http_request_policy'] = (
                    self._transform_http_request_policy(request_policy))
            cors = getattr(l7policy, 'request_cors', None)
            if (cors is not None and l7policy.action in
                    (constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
                     constants.L7POLICY_ACTION_WEIGHTED_TARGETS)):
                ret_value['request_cors'] = self._transform_request_cors(cors)
            for field in ('request_header_operations',
                          'response_header_operations'):
                operations = getattr(l7policy, field)
                if operations:
                    ret_value[field] = self._transform_header_operations(
                        operations, field)
        return ret_value

    @staticmethod
    def _apply_http_retry_backoff_support(listener, supported, results):
        policies_by_pool = listener.get('http_request_policies_by_pool', {})
        closed_by_pool = {}
        for pool_id, policies in list(policies_by_pool.items()):
            backoff = [policy_id for policy_id, args in policies
                       if len(args) == 5]
            if results is not None:
                status = constants.ACTIVE if supported else constants.ERROR
                results.update(dict.fromkeys(backoff, status))
            if backoff and not supported:
                closed_by_pool[pool_id] = backoff
                policies_by_pool[pool_id] = [
                    (policy_id, args) for policy_id, args in policies
                    if len(args) == 4]
                if not policies_by_pool[pool_id]:
                    del policies_by_pool[pool_id]
        if closed_by_pool:
            listener['http_retry_backoff_closed_by_pool'] = closed_by_pool

    @staticmethod
    def _transform_http_request_policy(policy):
        policy = validate.http_request_policy(policy)
        retry = policy.get('retry')
        attempts = 'default' if retry is None else retry.get('attempts', 1)
        codes = ','.join(str(code) for code in (retry or {}).get('codes', []))
        args = (
            policy.get('request_timeout_ms', 'default'),
            policy.get('backend_request_timeout_ms', 'default'),
            attempts, codes or 'none')
        if retry is not None and 'backoff_ms' in retry:
            args += (retry['backoff_ms'],)
        return args

    @staticmethod
    def _cors_origin_pattern(origin):
        if origin == '*':
            # Opaque browser origins serialize to "null".
            return rf'^(null|https?://{_CORS_ANY_HOST}(:{_CORS_PORT})?)$'

        scheme, authority = origin.split('://', 1)
        host, separator, configured_port = authority.partition(':')
        default_port = 80 if scheme == 'http' else 443
        port = int(configured_port) if separator else default_port
        port_match = f'(:0*{port})' + ('?' if port == default_port else '')
        if host == '*':
            host_match = _CORS_ANY_HOST
        elif host.startswith('*.'):
            host_match = rf'({_CORS_DNS_LABEL}[.])+' + re.escape(host[2:])
        else:
            host_match = re.escape(host)
        return f'^{scheme}://{host_match}{port_match}$'

    @classmethod
    def _transform_request_cors(cls, cors):
        origins = cors.get('allow_origins', [])
        methods = cors.get('allow_methods', [])
        headers = cors.get('allow_headers', [])
        expose = cors.get('expose_headers', [])
        credentials = cors.get('allow_credentials', False)
        allowed_methods = sorted({'GET', 'HEAD', 'POST'}.union(methods))
        header_name = (_HTTP_TOKEN if '*' in headers else
                       '(' + '|'.join(map(re.escape, headers)) + ')')
        # Include the allow-list alternatives once so the largest CRD list
        # fits HAProxy's PCRE2 compiled-pattern limit.
        header_list = f'^({_HTTP_OWS}{header_name}{_HTTP_OWS}(,|$))+$'
        response_headers = {
            name: ', '.join(values)
            for name, values in (
                ('Access-Control-Allow-Methods', methods),
                ('Access-Control-Allow-Headers', headers),
                ('Access-Control-Expose-Headers', expose),
            ) if values and '*' not in values
        }
        # Static lists dominate the response cost at the CRD bounds. Add
        # space for each HTX field and for Origin, Vary and the scalar fields.
        response_headroom = _CORS_RESPONSE_OVERHEAD + sum(
            len(name) + len(value) + 16
            for name, value in response_headers.items()
        )
        return {
            'origin_patterns': [
                _quote_config_arg(cls._cors_origin_pattern(origin))
                for origin in origins
            ],
            'origin_response': ('"*"' if '*' in origins and not credentials
                                else '"%[var(txn.octavia_cors_origin)]"'),
            'credentials': credentials,
            'methods_wildcard': '*' in methods,
            'method_token_pattern': _quote_config_arg(f'^{_HTTP_TOKEN}$'),
            'accepted_methods': ' '.join(map(_quote_config_arg,
                                             allowed_methods)),
            'headers_wildcard': '*' in headers,
            'header_list_pattern': (_quote_config_arg(header_list)
                                    if headers else None),
            'expose_wildcard': '*' in expose,
            # The literals also pass through HAProxy's log-format parser.
            'response_headers': {
                name: _quote_config_arg(value.replace('%', '%%'))
                for name, value in response_headers.items()
            },
            'response_headroom': response_headroom,
            'max_age': int(cors.get('max_age', 5)),
        }

    @staticmethod
    def _transform_request_redirect(redirect):
        redirect = validate.http_request_redirect(redirect)
        scheme = redirect['scheme']
        port = redirect['port']
        hostname = redirect.get('hostname')
        authority = hostname or '%[req.fhdr(host),regsub(:[0-9]*$,)]'
        target = f'{scheme}://{authority}'
        if port != {'http': 80, 'https': 443}[scheme]:
            target += f':{port}'

        result = {'mode': 'prefix', 'request_hostname': hostname is None}
        query_suffix = '%[pathq,regsub(^[^?]+,)]'
        if 'replace_full_path' in redirect:
            result['mode'] = 'location'
            target += _http_url_path(redirect['replace_full_path'])
            target += query_suffix
        elif 'replace_prefix' in redirect:
            prefix = redirect['replace_prefix']
            match = prefix['match'].removesuffix('/') or '/'
            replacement = _http_url_path(prefix['replacement']).removesuffix(
                '/')
            if match != '/':
                result['match'] = _quote_config_arg(match)
                result['descendants'] = _quote_config_arg(match + '/')
                result['mode'] = 'location'
                # Match is already checked by the frontend ACLs. For an
                # empty replacement, emit a root slash and consume the
                # existing delimiter when the suffix starts with one.
                if replacement:
                    suffix = f'%[pathq,regsub(^.{{{len(match)}}},)]'
                    target += replacement + suffix
                else:
                    target += f'%[pathq,regsub(^.{{{len(match)}}}/?,/)]'
            else:
                target += replacement
        result['argument'] = _quote_config_arg(target)
        return result

    @staticmethod
    def _transform_request_url_rewrite(rewrite):
        rewrite = validate.http_request_url_rewrite(rewrite)
        operations = []
        if 'hostname' in rewrite:
            hostname = rewrite['hostname']
            # Absolute-form clients carry the authority in both places.
            absolute_uri = _quote_config_arg(
                r'^([A-Za-z][A-Za-z0-9+.-]*://)[^/?]*(.*)$')
            authority = r'\1' + hostname + r'\2'
            operations.extend((
                f'replace-uri {absolute_uri} {_quote_config_arg(authority)}',
                f'set-header host {_quote_config_arg(hostname)}',
            ))
        if 'replace_full_path' in rewrite:
            path = _http_url_path(rewrite['replace_full_path'])
            operations.append(f'set-path {_quote_config_arg(path)}')
        if 'replace_prefix' in rewrite:
            prefix = rewrite['replace_prefix']
            match = prefix['match'].removesuffix('/') or '/'
            replacement = _http_url_path(prefix['replacement']).removesuffix(
                '/')
            if match == '/':
                if not replacement:
                    return operations
                pattern = r'^(/.+)?/?$'
                replacement += r'\1'
            else:
                # Quote only POSIX ERE metacharacters. The optional suffix
                # starts at a segment boundary and excludes the query.
                literal = re.sub(r'[][\\.^$*+?{}()|]', r'\\\g<0>', match)
                if replacement:
                    pattern = f'^{literal}(/.*)?$'
                    replacement += r'\1'
                else:
                    pattern = f'^{literal}(/(.*))?$'
                    replacement = r'/\2'
            operations.append(
                f'replace-path {_quote_config_arg(pattern)} '
                f'{_quote_config_arg(replacement)}')
        return operations

    @staticmethod
    def _transform_header_operations(operations, field):
        actions = {'SET': 'set-header', 'ADD': 'add-header',
                   'REMOVE': 'del-header'}

        transformed = []
        for operation in validate.header_operations(operations, field):
            action = actions[operation['operation']]
            name = _quote_config_arg(operation['name'])
            if 'value' in operation:
                # HAProxy parses a log-format expression after the config
                # parser. Double percent signs denote literal percent signs.
                value = operation['value'].replace('%', '%%')
                # HAProxy treats a zero-length argument as a missing one.
                argument = _quote_config_arg(value or '%[str()]')
                line = f'{action} {name} {argument}'
            else:
                line = f'{action} {name}'
            transformed.append(line)
        return transformed

    @staticmethod
    def _active_mirrors(mirrors, available_pool_ids):
        return [mirror for mirror in validate.http_request_mirrors(mirrors)
                if mirror['numerator'] and
                mirror['pool_id'] in available_pool_ids]

    @staticmethod
    def _transform_request_pipeline(headers, rewrites, mirrors):
        phases = {phase: [] for phase in validate.REQUEST_MIRROR_PHASES}
        for mirror in mirrors:
            phase = mirror.get('phase', validate.REQUEST_MIRROR_DEFAULT_PHASE)
            phases[phase].append('octavia-mirror {pool_id} {numerator} '
                                 '{denominator}'.format(**mirror))
        return (phases['before_transforms'] + headers +
                phases['after_headers'] + rewrites + phases['after_rewrite'])

    def _transform_weighted_targets(self, targets, available_pool_ids,
                                    available_mirror_pool_ids=()):
        intervals = []
        total = 0
        for target in targets:
            weight = target['weight']
            if type(weight) is not int or weight < 0:
                raise exceptions.InvalidL7PolicyArgs(
                    msg='Weighted targets need nonnegative integer weights.')
            if weight == 0:
                continue
            interval = {'first': total, 'last': total + weight - 1}
            if 'fixed_response' in target:
                interval['status_code'] = validate.fixed_http_status_code(
                    target['fixed_response'])
            elif target['pool_id'] in available_pool_ids:
                interval['pool_id'] = target['pool_id']
                operations = target.get('request_header_operations', [])
                headers = self._transform_header_operations(
                    operations, 'request_header_operations')
                rewrites = []
                if 'request_url_rewrite' in target:
                    rewrites = self._transform_request_url_rewrite(
                        target['request_url_rewrite'])
                mirrors = self._active_mirrors(
                    target.get('request_mirrors'), available_mirror_pool_ids)
                if mirrors:
                    interval['mirror_pool_ids'] = [
                        mirror['pool_id'] for mirror in mirrors]
                request_filters = self._transform_request_pipeline(
                    headers, rewrites, mirrors)
                if request_filters:
                    interval['request_filters'] = request_filters
            else:
                # Keep the unavailable target's share and terminate here.
                interval['status_code'] = 503
            intervals.append(interval)
            total += weight
        if not 0 < total <= HAPROXY_MAX_RANDOM_RANGE:
            raise exceptions.InvalidL7PolicyArgs(
                msg='Total weight is outside the HAProxy random range.')
        return intervals, total

    @staticmethod
    def _query_param_fetch(key):
        """Normalize the query name for HAProxy's first-value lookup."""
        encoded_name = []
        name_pattern = []
        for byte in key.encode('ascii'):
            encoded_name.append(f'%{byte:02X}')
            # Fold hex digits while preserving the case of the decoded name.
            digits = ''.join(
                f'[{digit}{digit.upper()}]' if digit in 'abcdef' else digit
                for digit in f'{byte:02x}')
            percent_escape = f'%{digits}'
            char = chr(byte)
            if char in '+&%#':
                # These characters must be percent-encoded in a name.
                name_pattern.append(percent_escape)
            else:
                # Pass a regex escape through the outer HAProxy config
                # quotes. Escape a dollar there and match it in a class.
                literal = rf'\\{char}' if char in '*.^|' else char
                if char == '$':
                    literal = r'[\$]'
                name_pattern.append(f'({literal}|{percent_escape})')
        encoded_name = ''.join(encoded_name)
        pattern = '(^|&)' + ''.join(name_pattern)
        # Both libc and PCRE2 support POSIX alternation. Consume each
        # delimiter with a separate substitution so only the leading
        # boundary needs a backreference. Normalize a bare name to an
        # empty assignment, preserving its position relative to duplicates.
        assigned = rf'regsub(\"{pattern}=\",\"\\1{encoded_name}=\")'
        bare = rf'regsub(\"{pattern}(&|\$)\",\"\\1{encoded_name}=&\")'
        # Split before decoding the value so encoded delimiters stay data.
        return (f'"query,{assigned},{bare},'
                f'param({encoded_name}),url_dec(1)"')

    def _transform_l7rule(self, l7rule, feature_compatibility):
        """Transforms an L7 rule into an object that will

            be processed by the templating system
        """
        key = l7rule.key
        if l7rule.type == constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
            # Protect the token in both the configuration and sample fetch
            # parsers. Match raw field bytes with a hex-encoded ACL pattern.
            escaped_key = key.translate({
                ord('#'): r'\x23', ord('$'): r'\x24', ord("'"): r'\x27',
            })
            key = rf'\"{escaped_key}\"'
            value = l7rule.value.encode('utf-8').hex()
        elif l7rule.type == constants.L7RULE_TYPE_HTTP_QUERY_PARAM_EXACT:
            key = self._query_param_fetch(key)
            value = l7rule.value.encode('utf-8').hex()
        elif l7rule.type == constants.L7RULE_TYPE_GRPC_CONTENT_TYPE:
            value = _GRPC_CONTENT_TYPE_ACL
        else:
            value = self._escape_haproxy_config_string(l7rule.value)

        return {
            'id': l7rule.id,
            'type': l7rule.type,
            'compare_type': l7rule.compare_type,
            'key': key,
            'value': value,
            'invert': l7rule.invert,
            'enabled': l7rule.enabled
        }

    @staticmethod
    def _escape_haproxy_config_string(value):
        """Escapes certain characters in a given string such that

            haproxy will parse the string as a single value
        """
        # Escape backslashes first
        value = re.sub(r'\\', r'\\\\', value)
        # Spaces next
        value = re.sub(' ', '\\ ', value)
        return value
