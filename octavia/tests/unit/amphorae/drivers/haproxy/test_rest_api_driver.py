# Copyright 2020 Red Hat, Inc. All rights reserved.
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
import ssl
from types import SimpleNamespace
from unittest import mock

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.amphorae.drivers.haproxy import exceptions as exc
from octavia.amphorae.drivers.haproxy import rest_api_driver
from octavia.common import constants
from octavia.common import data_models
import octavia.tests.unit.base as base
from octavia.tests.unit.common.sample_configs import sample_configs_combined


class TestCustomHostNameCheckingAdapter(base.TestCase):

    def setUp(self):
        super().setUp()
        self.adapter = rest_api_driver.CustomHostNameCheckingAdapter()

    def test_init_poolmanager_uses_ssl_minimum_version(self):
        # Ensure that ssl_minimum_version (not deprecated ssl_version) is used
        # when initialising the pool manager.
        with mock.patch(
            'octavia.amphorae.drivers.haproxy.rest_api_driver.CONF'
        ) as mock_conf, mock.patch.object(
            rest_api_driver.requests.adapters.HTTPAdapter,
            'init_poolmanager'
        ) as mock_http_init:
            mock_conf.amphora_agent.agent_tls_protocol = 'TLSv1.2'
            self.adapter.init_poolmanager(10, 10)
            call_kwargs = mock_http_init.call_args[1]
            self.assertNotIn('ssl_version', call_kwargs)
            self.assertIn('ssl_minimum_version', call_kwargs)
            self.assertEqual(ssl.TLSVersion.TLSv1_2,
                             call_kwargs['ssl_minimum_version'])


class TestHAProxyAmphoraDriver(base.TestCase):

    def setUp(self):
        super().setUp()
        self.driver = rest_api_driver.HaproxyAmphoraLoadBalancerDriver()

    def test_http_retry_backoff_failover_and_independent_withdrawal(self):
        listener = sample_configs_combined.sample_listener_tuple(
            l7=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        ordinary = listener.l7policies[0]
        first, sibling = [
            SimpleNamespace(**ordinary._replace(
                id=policy_id,
                l7rules=[sample_configs_combined.sample_l7rule_tuple(
                    f'{policy_id}-path', value=f'/{policy_id}')])._asdict(),
                http_request_policy={'retry': {'backoff_ms': duration}})
            for policy_id, duration in (('first', 80), ('sibling', 150))]
        listener = listener._replace(l7policies=[first, sibling])
        amphorae = [amp._replace(status=constants.AMPHORA_ALLOCATED)
                    for amp in listener.load_balancer.amphorae]
        loadbalancer = listener.load_balancer._replace(
            amphorae=amphorae, listeners=[listener])
        client = self.driver.clients['1.0'] = mock.Mock()
        client.get_info.return_value = {'haproxy_version': '3.0.19'}
        policy_cap = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY
        backoff_cap = constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF
        details = {amphorae[0].id: {policy_cap: True, backoff_cap: True},
                   amphorae[1].id: {policy_cap: True}}
        client.get_details.side_effect = (
            lambda amphora, **kwargs: details[amphora.id])
        statuses = {amp.id: {constants.UNREACHABLE: False}
                    for amp in amphorae}
        with (mock.patch.object(self.driver, '_process_listener_tls_certs',
                                return_value={}),
              mock.patch.object(self.driver, '_process_listener_pool_certs',
                                return_value={}),
              mock.patch.object(rest_api_driver.db_api, 'session'),
              mock.patch.object(
                  rest_api_driver.repo.L7PolicyRepository,
                  'set_http_retry_backoff_statuses') as publish):
            backup = amphorae[1]
            self.driver.update_amphora_listeners(
                loadbalancer._replace(amphorae=[backup]), backup)
            config = client.upload_config.call_args.args[2]
            closed = 'http-request return status 503 if { var('
            self.assertIn(closed, config)
            self.assertNotIn('octavia-http-policy', config)
            self.assertEqual({'first', 'sibling'},
                             publish.call_args.kwargs['closed'])

            client.reset_mock()
            self.assertRaises(
                driver_except.CoordinatedListenerUpdateError,
                self.driver.update_failover_listeners, loadbalancer, 0,
                statuses)
            client.upload_config.assert_not_called()
            client.reload_listener.assert_not_called()

            details[amphorae[1].id][backoff_cap] = True
            self.assertTrue(self.driver.update_failover_listeners(
                loadbalancer, 0, statuses))
            self.assertEqual(amphorae, [call.args[0] for call in
                                        client.upload_config.call_args_list])
            for call in client.upload_config.call_args_list:
                self.assertIn(
                    'octavia-http-policy default default 1 none 80 if',
                    call.args[2])
            self.assertEqual(2, client.reload_listener.call_count)
            self.assertEqual({'first', 'sibling'},
                             publish.call_args.kwargs['recovered'])

            client.reset_mock()
            del details[backup.id][backoff_cap]
            first.http_request_policy = {'retry': {'attempts': 2}}
            self.driver.update(loadbalancer)
            for call in client.upload_config.call_args_list:
                config = call.args[2]
                self.assertIn(
                    'octavia-http-policy default default 2 none if '
                    '{ var(txn.octavia_l7_policy) -m str first }', config)
                self.assertIn(
                    closed + 'txn.octavia_l7_policy) -m str sibling }', config)
            self.assertEqual(2, client.reload_listener.call_count)
            self.assertEqual({'sibling'}, publish.call_args.kwargs['closed'])

    def test_http_retry_backoff_single_failover_requires_details_and_reload(
            self):
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        policy = SimpleNamespace(**listener.l7policies[0]._asdict(),
                                 http_request_policy={
                                     'retry': {'backoff_ms': 0}})
        listener = listener._replace(l7policies=[policy])
        amphora = listener.load_balancer.amphorae[0]._replace(
            role=constants.ROLE_STANDALONE, status=constants.AMPHORA_ALLOCATED)
        loadbalancer = listener.load_balancer._replace(
            amphorae=[amphora], listeners=[listener])
        client = self.driver.clients['1.0'] = mock.Mock()
        client.get_info.return_value = {'haproxy_version': '3.0.19'}
        with (mock.patch.object(self.driver, '_process_listener_tls_certs',
                                return_value={}),
              mock.patch.object(self.driver, '_process_listener_pool_certs',
                                return_value={}),
              mock.patch.object(rest_api_driver.db_api, 'session'),
              mock.patch.object(
                  rest_api_driver.repo.L7PolicyRepository,
                  'set_http_retry_backoff_statuses') as publish):
            client.get_details.side_effect = exc.ServiceUnavailable()
            self.assertRaises(
                driver_except.HttpRetryBackoffUnsupported,
                self.driver.update_amphora_listeners, loadbalancer, amphora,
                finalizing_failover=True)
            client.upload_config.assert_not_called()
            self.assertEqual({policy.id}, publish.call_args.kwargs['closed'])

            client.get_details.side_effect = None
            client.get_details.return_value = {
                constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY: True,
                constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF: True}
            client.reload_listener.side_effect = exc.ServiceUnavailable()
            self.assertRaises(
                exc.ServiceUnavailable, self.driver.update_amphora_listeners,
                loadbalancer, amphora, finalizing_failover=True)
            client.upload_config.assert_called_once()
            self.assertEqual({policy.id}, publish.call_args.kwargs['closed'])

    def test_tcp_batch_prepares_all_peers_before_reload(self):
        amps = [
            data_models.Amphora(id=amp_id,
                                status=constants.AMPHORA_ALLOCATED)
            for amp_id in ('first', 'second')
        ]
        for amp in amps:
            amp.api_version = '1.0'
        loadbalancer = data_models.LoadBalancer(
            id='loadbalancer', enabled=True, amphorae=amps,
            listeners=[
                data_models.Listener(protocol=constants.PROTOCOL_TCP),
                data_models.Listener(protocol=constants.PROTOCOL_HTTP),
                data_models.Listener(protocol=constants.PROTOCOL_UDP),
            ])
        client = self.driver.clients['1.0'] = mock.Mock()
        client.get_info.return_value = {'haproxy_version': '3.0.19'}
        with (mock.patch.object(self.driver.jinja_combo, 'build_config',
                                return_value='combined-config'),
              mock.patch.object(self.driver, '_process_listener_tls_certs',
                                return_value={}) as certificates):
            certificates.side_effect = [{}, {}, RuntimeError('TLS prep')]
            self.assertRaises(RuntimeError, self.driver.update,
                              loadbalancer, tcp_member_batch=True)
            client.upload_config.assert_not_called()
            client.reload_listener.assert_not_called()

            certificates.side_effect = None
            client.upload_config.side_effect = [None, RuntimeError('upload')]
            self.assertRaises(RuntimeError, self.driver.update,
                              loadbalancer, tcp_member_batch=True)
            client.reload_listener.assert_not_called()

            client.reset_mock(side_effect=True)
            self.driver.update(loadbalancer, tcp_member_batch=True)
            self.assertEqual([
                mock.call.upload_config(amps[0], loadbalancer.id,
                                        'combined-config'),
                mock.call.upload_config(amps[1], loadbalancer.id,
                                        'combined-config'),
                mock.call.reload_listener(amps[0], loadbalancer.id),
                mock.call.reload_listener(amps[1], loadbalancer.id),
            ], [call for call in client.mock_calls
                if call[0] in ('upload_config', 'reload_listener')])
            client.upload_udp_config.assert_not_called()

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver.'
                '_populate_amphora_api_version')
    def test_get_interface_from_ip(self, mock_api_version):
        FAKE_INTERFACE = 'fake0'
        IP_ADDRESS = '203.0.113.42'
        TIMEOUT_DICT = {'outa': 'time'}
        amphora_mock = mock.MagicMock()
        amphora_mock.api_version = '0'
        client_mock = mock.MagicMock()
        client_mock.get_interface.side_effect = [
            {'interface': FAKE_INTERFACE}, {'interface': FAKE_INTERFACE},
            {}, exc.NotFound]
        self.driver.clients['0'] = client_mock

        # Test interface found no timeout

        result = self.driver.get_interface_from_ip(amphora_mock, IP_ADDRESS)

        self.assertEqual(FAKE_INTERFACE, result)
        mock_api_version.assert_called_once_with(amphora_mock, None)
        client_mock.get_interface.assert_called_once_with(
            amphora_mock, IP_ADDRESS, None, log_error=False)

        # Test interface found with timeout
        mock_api_version.reset_mock()
        client_mock.reset_mock()

        result = self.driver.get_interface_from_ip(amphora_mock, IP_ADDRESS,
                                                   timeout_dict=TIMEOUT_DICT)

        self.assertEqual(FAKE_INTERFACE, result)
        mock_api_version.assert_called_once_with(amphora_mock, TIMEOUT_DICT)
        client_mock.get_interface.assert_called_once_with(
            amphora_mock, IP_ADDRESS, TIMEOUT_DICT, log_error=False)

        # Test no interface data
        mock_api_version.reset_mock()
        client_mock.reset_mock()

        result = self.driver.get_interface_from_ip(amphora_mock, IP_ADDRESS)

        self.assertIsNone(result)
        mock_api_version.assert_called_once_with(amphora_mock, None)
        client_mock.get_interface.assert_called_once_with(
            amphora_mock, IP_ADDRESS, None, log_error=False)

        # Test NotFound
        mock_api_version.reset_mock()
        client_mock.reset_mock()

        self.assertRaises(
            exc.NotFound,
            self.driver.get_interface_from_ip, amphora_mock, IP_ADDRESS)
        mock_api_version.assert_called_once_with(amphora_mock, None)
        client_mock.get_interface.assert_called_once_with(
            amphora_mock, IP_ADDRESS, None, log_error=False)

    def test_unsupported_api_version(self):
        mock_amp = mock.MagicMock()
        mock_amp.api_version = "0.5"

        self.assertRaises(driver_except.AmpVersionUnsupported,
                          self.driver._populate_amphora_api_version,
                          mock_amp)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver.'
                '_populate_amphora_api_version')
    def test_set_interface_rules(self, mock_api_version):

        IP_ADDRESS = '203.0.113.44'
        amphora_mock = mock.MagicMock()
        amphora_mock.api_version = '0'
        client_mock = mock.MagicMock()
        client_mock.set_interface_rules.side_effect = [mock.DEFAULT,
                                                       exc.NotFound]
        self.driver.clients['0'] = client_mock

        self.driver.set_interface_rules(amphora_mock, IP_ADDRESS, 'fake_rules')
        mock_api_version.assert_called_once_with(amphora_mock, None)
        client_mock.set_interface_rules.assert_called_once_with(
            amphora_mock, IP_ADDRESS, 'fake_rules', timeout_dict=None)

        self.assertRaises(driver_except.AmpDriverNotImplementedError,
                          self.driver.set_interface_rules, amphora_mock,
                          IP_ADDRESS, 'fake_rules')
