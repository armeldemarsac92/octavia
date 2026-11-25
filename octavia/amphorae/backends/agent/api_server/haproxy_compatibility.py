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

import re
import subprocess

from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def get_haproxy_capabilities():
    try:
        output = subprocess.check_output(
            [CONF.haproxy_amphora.haproxy_cmd, '-vv'],
            stderr=subprocess.STDOUT, encoding='utf-8', timeout=5)
    except (OSError, subprocess.SubprocessError):
        return {}
    capabilities = {}
    version = re.match(r'HAProxy version (\d+)\.(\d+)\.', output)
    if (version and int(version.group(1)) >= 3 and
            '+OPENSSL' in output.split()):
        capabilities[
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK
        ] = True
    strict_dns = 'HAProxy version 3.0.19-ade9c1262-octavia-strict-dns-v1'
    backend_sans = f'{strict_dns}-h2-alpn-v1-backend-sans-v1'
    http_request_policy = f'{backend_sans}-http-policy-v1'
    http_request_mirror_build = f'{http_request_policy}-http-mirror-v1 '
    strict_dns_builds = (
        f'{strict_dns} ', f'{strict_dns}-h2-alpn-v1 ',
        f'{backend_sans} ', f'{http_request_policy} ',
        http_request_mirror_build,
    )
    if not output.startswith(strict_dns_builds):
        return capabilities
    capabilities[constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME] = True
    capabilities[constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH] = True
    if output.startswith(strict_dns_builds[1:]):
        capabilities[constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN] = True
    if output.startswith(strict_dns_builds[2:]):
        capabilities[
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES] = True
    if output.startswith(strict_dns_builds[3:]):
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY] = True
    if output.startswith(http_request_mirror_build):
        capabilities[constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR] = True
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
