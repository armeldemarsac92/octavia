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
import subprocess
from unittest import mock

from oslo_config import fixture as oslo_fixture

from octavia.amphorae.backends.agent.api_server import haproxy_compatibility
from octavia.common import constants
import octavia.tests.unit.base as base
from octavia.tests.unit.common.sample_configs import sample_configs_combined


class HAProxyCompatTestCase(base.TestCase):
    def setUp(self):
        super().setUp()
        probe = mock.patch.object(haproxy_compatibility.subprocess, 'run',
                                  side_effect=FileNotFoundError)
        self.mock_probe = probe.start()
        self.addCleanup(probe.stop)
        self.old_haproxy_global = (
            "# Configuration for loadbalancer sample_loadbalancer_id_1\n"
            "global\n"
            "    daemon\n"
            "    user nobody\n"
            "    log /run/rsyslog/octavia/log local0\n"
            "    log /run/rsyslog/octavia/log local1 notice\n"
            "    stats socket /var/lib/octavia/sample_loadbalancer_id_1.sock"
            " mode 0666 level user\n"
            "    maxconn {maxconn}\n\n"
            "defaults\n"
            "    log global\n"
            "    retries 3\n"
            "    option redispatch\n"
            "    option splice-request\n"
            "    option splice-response\n"
            "    option http-keep-alive\n\n\n\n\n"
            "frontend sample_listener_id_1\n"
            "    maxconn {maxconn}\n"
            "    bind 10.0.0.2:80\n"
            "    mode http\n"
            "    default_backend sample_pool_id_1:sample_listener_id_1\n"
            "    timeout client 50000\n"
            "    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
            "%ci\\ %cp\\ %t\\ %{{+Q}}r\\ %ST\\ %B\\ %U\\ "
            "%[ssl_c_verify]\\ %{{+Q}}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
            "%tsc\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        self.backend_without_external = (
            "backend sample_pool_id_1:sample_listener_id_1\n"
            "    mode http\n"
            "    balance roundrobin\n"
            "    cookie SRV insert indirect nocache\n"
            "    timeout check 31\n"
            "    option httpchk GET /index.html\n"
            "    http-check expect rstatus 418\n"
            "    fullconn {maxconn}\n"
            "    option allbackups\n"
            "    timeout connect 5000\n"
            "    timeout server 50000\n"
            "    server sample_member_id_1 10.0.0.99:82 weight 13 "
            "check inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
            "    server sample_member_id_2 10.0.0.98:82 weight 13 "
            "check inter 30s fall 3 rise 2 cookie "
            "sample_member_id_2\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        self.backend_with_external = (
            "backend sample_pool_id_1:sample_listener_id_1\n"
            "    mode http\n"
            "    balance roundrobin\n"
            "    cookie SRV insert indirect nocache\n"
            "    timeout check 31\n"
            "    option httpchk GET /index.html\n"
            "    http-check expect rstatus 418\n"
            "    option external-check\n"
            "    external-check command /var/lib/octavia/ping-wrapper.sh\n"
            "    fullconn {maxconn}\n"
            "    option allbackups\n"
            "    timeout connect 5000\n"
            "    timeout server 50000\n"
            "    server sample_member_id_1 10.0.0.99:82 weight 13 "
            "check inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
            "    server sample_member_id_2 10.0.0.98:82 weight 13 "
            "check inter 30s fall 3 rise 2 cookie "
            "sample_member_id_2\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)

    @mock.patch('subprocess.check_output')
    def test_get_haproxy_versions(self, mock_process):
        mock_process.return_value = (
            b"THIS-App version 1.6.3 2099/10/12\n"
            b"Some other data here <test@example.com>\n")
        major, minor = haproxy_compatibility.get_haproxy_versions()
        self.assertEqual(1, major)
        self.assertEqual(6, minor)

    @mock.patch('subprocess.check_output')
    def test_get_haproxy_versions_devel(self, mock_process):
        mock_process.return_value = (
            b"HA-Proxy version 2.3-dev0 2019/11/25 - https://haproxy.org/\n"
            b"Some other data here <test@example.com>\n")
        major, minor = haproxy_compatibility.get_haproxy_versions()
        self.assertEqual(2, major)
        self.assertEqual(3, minor)

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_backend_tls_capabilities(self, check_output):
        hostname = constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME
        tcp_auth = constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH
        system_ca = constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA
        authenticated = {hostname: True, tcp_auth: True, system_ca: True}
        h2_alpn = constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN
        sans = constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES
        policy = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY
        mirror = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR
        strict_dns = 'HAProxy version 3.0.19-ade9c1262-octavia-strict-dns-v1'
        for version, expected in (
                ('HAProxy version 3.0.19-ade9c1262 ', {}),
                (f'{strict_dns} ', authenticated),
                (f'{strict_dns}-h2-alpn-v1 ',
                 {**authenticated, h2_alpn: True}),
                (f'{strict_dns}-h2-alpn-v1-backend-sans-v1 ',
                 {**authenticated, h2_alpn: True, sans: True}),
                (f'{strict_dns}-h2-alpn-v1-backend-sans-v1-http-policy-v1 ',
                 {**authenticated, h2_alpn: True, sans: True,
                  policy: True}),
                (f'{strict_dns}-h2-alpn-v1-backend-sans-v1-http-policy-v1'
                 '-http-mirror-v1 ',
                 {**authenticated, h2_alpn: True, sans: True,
                  policy: True, mirror: True})):
            with self.subTest(version=version):
                check_output.side_effect = [
                    version, subprocess.CalledProcessError(1, 'haproxy')]
                result = haproxy_compatibility.get_haproxy_capabilities()
                self.assertEqual(expected, result)

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_http_retry_backoff_capability_uses_configured_binary(
            self, check_output):
        binary = '/opt/amphora/custom-haproxy'
        haproxy_compatibility.CONF.set_override(
            'haproxy_cmd', binary, group='haproxy_amphora')
        capability = constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF
        build = (
            'HAProxy version 3.0.19-ade9c1262-octavia-strict-dns-v1'
            '-h2-alpn-v1-backend-sans-v1-http-policy-v1-http-mirror-v1'
            '-listener-auth-v1-backend-retry-budget-v1-route-retry-backoff-v1 '
            '2026/03/19')
        for supported, probe in (
                (False, subprocess.CalledProcessError(1, binary)),
                (True, '')):
            with self.subTest(supported=supported):
                check_output.reset_mock()
                check_output.side_effect = [build, probe]
                features = haproxy_compatibility.get_haproxy_capabilities()
                self.assertEqual(supported, features.get(capability, False))
                self.assertTrue(
                    features[constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY])
                budget = constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET
                self.assertTrue(features[budget])
                version, config = check_output.call_args_list
                self.assertEqual([binary, '-vv'], version.args[0])
                self.assertEqual([binary, '-c', '-q', '-f', '/dev/stdin'],
                                 config.args[0])
                self.assertTrue(config.kwargs['input'].startswith('defaults'))
                self.assertIn('octavia-http-policy default default 1 503 1',
                              config.kwargs['input'])

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    @mock.patch.object(haproxy_compatibility.os.path, 'isfile')
    def test_listener_otlp_tracing_capability(self, isfile, check_output):
        check_output.return_value = (
            'HAProxy version 3.0.19-ade9c1262-octavia-strict-dns-v1'
            '-h2-alpn-v1-backend-sans-v1-http-policy-v1-http-mirror-v1'
            '-listener-auth-v1-backend-retry-budget-v1-listener-otlp-v1'
            '-route-retry-backoff-v1 '
            '2026/03/19\nFeature list : +OPENSSL +LUA')
        tracing = constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING
        sampling = constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING
        attrs = constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SPAN_ATTRIBUTES
        isfile.return_value = False
        self.assertNotIn(tracing,
                         haproxy_compatibility.get_haproxy_capabilities())
        isfile.side_effect = lambda path: (
            path == constants.HAPROXY_OTLP_TRACING_SCRIPT)
        features = haproxy_compatibility.get_haproxy_capabilities()
        self.assertTrue(features[tracing])
        self.assertNotIn(sampling, features)
        self.assertNotIn(attrs, features)
        isfile.side_effect = lambda path: path in (
            constants.HAPROXY_OTLP_TRACING_SCRIPT,
            constants.HAPROXY_OTLP_SPAN_ATTRIBUTES_SCRIPT)
        features = haproxy_compatibility.get_haproxy_capabilities()
        self.assertTrue(features[attrs])
        self.assertNotIn(sampling, features)
        isfile.side_effect = None
        isfile.return_value = True
        features = haproxy_compatibility.get_haproxy_capabilities()
        self.assertTrue(features[tracing])
        self.assertTrue(features[sampling])
        self.assertTrue(features[attrs])
        self.assertTrue(
            features[constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET])

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_cookie_path_checks_configured_binary(self, check_output):
        haproxy_cmd = '/opt/octavia/bin/haproxy'
        config = self.useFixture(oslo_fixture.Config(
            haproxy_compatibility.CONF))
        config.config(group='haproxy_amphora', haproxy_cmd=haproxy_cmd)
        capability = constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH
        check_output.return_value = 'HAProxy version 2.8.19 custom'
        self.mock_probe.side_effect = None

        self.assertIs(haproxy_compatibility.get_haproxy_capabilities()[
            capability], True)
        self.assertEqual([haproxy_cmd, '-vv'],
                         check_output.call_args.args[0])
        cookie_probe = next(
            call for call in self.mock_probe.call_args_list
            if 'http-after-response replace-header Set-Cookie'
            in call.kwargs['input'])
        self.assertEqual([haproxy_cmd, '-c', '-q', '-f', '/dev/stdin'],
                         cookie_probe.args[0])
        self.assertTrue(cookie_probe.kwargs['check'])

        check_output.return_value = 'HAProxy version 3.0.19 custom'
        self.mock_probe.side_effect = (
            haproxy_compatibility.subprocess.CalledProcessError(
                1, self.mock_probe.call_args.args[0]))
        self.assertNotIn(capability,
                         haproxy_compatibility.get_haproxy_capabilities())

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_header_persistence_requires_the_probe(self, check_output):
        capability = constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        check_output.return_value = 'HAProxy version 3.0.19 custom'
        self.mock_probe.side_effect = None
        self.assertTrue(haproxy_compatibility.get_haproxy_capabilities()[
            capability])

        def fail_header_probe(*args, **kwargs):
            if 'secure_memcmp' in kwargs['input']:
                raise haproxy_compatibility.subprocess.CalledProcessError(
                    1, args[0])

        self.mock_probe.side_effect = fail_header_probe
        self.assertNotIn(capability,
                         haproxy_compatibility.get_haproxy_capabilities())

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_tls_sni_passthrough_weighted_pool_capability(self, check_output):
        capability = (
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        check_output.return_value = 'HAProxy version 2.2.0 custom'
        self.mock_probe.side_effect = None
        self.assertIs(haproxy_compatibility.get_haproxy_capabilities()[
            capability], True)
        self.assertIn('req.ssl_sni', self.mock_probe.call_args.kwargs['input'])
        self.assertIn('rand(16000000)',
                      self.mock_probe.call_args.kwargs['input'])

        def fail_weighted_probe(*args, **kwargs):
            if 'req.ssl_sni' in kwargs['input']:
                raise haproxy_compatibility.subprocess.CalledProcessError(
                    1, args[0])

        self.mock_probe.side_effect = fail_weighted_probe
        self.assertNotIn(capability,
                         haproxy_compatibility.get_haproxy_capabilities())

    @mock.patch.object(haproxy_compatibility.subprocess, 'check_output')
    def test_frontend_client_auth_fallback_capability(self, check_output):
        fallback = (
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
        capabilities = {
            fallback,
            constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT,
            constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT,
        }
        for version, feature, supported in (
                ('3.0.19', '+OPENSSL', True),
                ('3.0.19', '-OPENSSL', False),
                ('2.8.19', '+OPENSSL', False)):
            with self.subTest(version=version, feature=feature):
                check_output.return_value = (
                    f'HAProxy version {version} fake\nFeature list : {feature}')
                result = haproxy_compatibility.get_haproxy_capabilities()
                self.assertEqual(capabilities if supported else set(),
                                 capabilities.intersection(result))

    @mock.patch('octavia.amphorae.backends.agent.api_server.'
                'haproxy_compatibility.get_haproxy_versions')
    def test_process_cfg_for_version_compat(self, mock_get_version):
        # Test 1.6 version path, no change to config expected
        mock_get_version.return_value = [1, 6]
        test_config = sample_configs_combined.sample_base_expected_config(
            backend=self.backend_with_external)
        result_config = haproxy_compatibility.process_cfg_for_version_compat(
            test_config)
        self.assertEqual(test_config, result_config)

        # Test 1.5 version path, external-check should be removed
        mock_get_version.return_value = [1, 5]
        test_config = sample_configs_combined.sample_base_expected_config(
            backend=self.backend_with_external)
        result_config = haproxy_compatibility.process_cfg_for_version_compat(
            test_config)
        expected_config = (self.old_haproxy_global +
                           self.backend_without_external)
        self.assertEqual(expected_config, result_config)
