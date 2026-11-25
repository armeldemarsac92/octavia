# Copyright 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2015 Rackspace
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
import hashlib
from types import SimpleNamespace
from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils
import requests
import requests_mock

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.amphorae.drivers.haproxy import exceptions as exc
from octavia.amphorae.drivers.haproxy import rest_api_driver as driver
from octavia.common import constants
from octavia.common import data_models
from octavia.common.jinja.lvs import jinja_cfg as jinja_udp_cfg
from octavia.common import utils as octavia_utils
from octavia.db import models
from octavia.network import data_models as network_models
from octavia.tests.common import sample_certs
from octavia.tests.unit import base
from octavia.tests.unit.common.sample_configs import sample_configs_combined

API_VERSION = '1.0'
FAKE_CIDR = '198.51.100.0/24'
FAKE_GATEWAY = '192.51.100.1'
FAKE_IP = '192.0.2.10'
FAKE_IPV6 = '2001:db8::cafe'
FAKE_IPV6_LLA = 'fe80::00ff:fe00:cafe'
FAKE_PEM_FILENAME = "file_name"
FAKE_UUID_1 = uuidutils.generate_uuid()
FAKE_VRRP_IP = '192.0.2.5'
FAKE_VIP_SUBNET = '192.0.2.0/24'
FAKE_MAC_ADDRESS = '123'
FAKE_MTU = 1450
FAKE_MEMBER_IP_PORT_NAME_1 = "10.0.0.10:1003"
FAKE_MEMBER_IP_PORT_NAME_2 = "10.0.0.11:1004"


class TestHaproxyAmphoraLoadBalancerDriverTest(base.TestCase):

    def setUp(self):
        super().setUp()

        DEST1 = '198.51.100.0/24'
        DEST2 = '203.0.113.0/24'
        NEXTHOP = '192.0.2.1'

        self.driver = driver.HaproxyAmphoraLoadBalancerDriver()

        self.driver.cert_manager = mock.MagicMock()
        self.driver.cert_parser = mock.MagicMock()
        self.driver.clients = {
            'base': mock.MagicMock(),
            API_VERSION: mock.MagicMock()}
        self.driver.clients['base'].get_api_version.return_value = {
            'api_version': API_VERSION}
        self.driver.clients[
            API_VERSION].get_info.return_value = {
            'haproxy_version': '1.6.3-1ubuntu0.1',
            'api_version': API_VERSION}
        self.driver.jinja_combo = mock.MagicMock()
        self.driver.lvs_jinja = mock.MagicMock()

        # Build sample Listener and VIP configs
        self.sl = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True, client_ca_cert=True, client_crl_cert=True,
            recursive_nest=True)
        self.sl_udp = sample_configs_combined.sample_listener_tuple(
            proto=constants.PROTOCOL_UDP,
            persistence_type=constants.SESSION_PERSISTENCE_SOURCE_IP,
            persistence_timeout=33,
            persistence_granularity='255.255.0.0',
            monitor_proto=constants.HEALTH_MONITOR_UDP_CONNECT)
        self.pool_has_cert = sample_configs_combined.sample_pool_tuple(
            pool_cert=True, pool_ca_cert=True, pool_crl=True)
        self.amp = self.sl.load_balancer.amphorae[0]
        self.sv = sample_configs_combined.sample_vip_tuple()
        self.lb = self.sl.load_balancer
        self.lb_udp = (
            sample_configs_combined.sample_lb_with_udp_listener_tuple())
        self.fixed_ip = mock.MagicMock()
        self.fixed_ip.ip_address = '198.51.100.5'
        self.fixed_ip.subnet.cidr = '198.51.100.0/24'
        self.fixed_ip.subnet.gateway_ip = FAKE_GATEWAY
        self.network = network_models.Network(mtu=FAKE_MTU)
        self.port = network_models.Port(mac_address=FAKE_MAC_ADDRESS,
                                        fixed_ips=[self.fixed_ip],
                                        network=self.network)

        self.host_routes = [network_models.HostRoute(destination=DEST1,
                                                     nexthop=NEXTHOP),
                            network_models.HostRoute(destination=DEST2,
                                                     nexthop=NEXTHOP)]
        host_routes_data = [{'destination': DEST1, 'nexthop': NEXTHOP},
                            {'destination': DEST2, 'nexthop': NEXTHOP}]
        self.subnet_info = {'subnet_cidr': FAKE_CIDR,
                            'gateway': FAKE_GATEWAY,
                            'mac_address': FAKE_MAC_ADDRESS,
                            'vrrp_ip': self.amp.vrrp_ip,
                            'mtu': FAKE_MTU,
                            'host_routes': host_routes_data,
                            'additional_vips': [],
                            'is_sriov': False}

        self.timeout_dict = {constants.REQ_CONN_TIMEOUT: 1,
                             constants.REQ_READ_TIMEOUT: 2,
                             constants.CONN_MAX_RETRIES: 3,
                             constants.CONN_RETRY_INTERVAL: 4}
        self.amp_net_config = network_models.AmphoraNetworkConfig(
            vip_subnet=network_models.Subnet(
                id=self.lb.vip.subnet_id,
                cidr=FAKE_VIP_SUBNET,
                host_routes=[])).to_dict(recurse=True)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_secret')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_amphora_listeners(self, mock_load_cert, mock_secret):
        mock_amphora = mock.MagicMock()
        mock_amphora.id = 'mock_amphora_id'
        mock_amphora.api_version = API_VERSION
        mock_secret.return_value = 'filename.pem'
        mock_load_cert.return_value = {
            'tls_cert': self.sl.default_tls_container, 'sni_certs': [],
            'client_ca_cert': None}
        self.driver.jinja_combo.build_config.return_value = 'the_config'

        mock_empty_lb = mock.MagicMock()
        mock_empty_lb.listeners = []
        self.driver.update_amphora_listeners(mock_empty_lb, mock_amphora,
                                             self.timeout_dict)
        mock_load_cert.assert_not_called()
        self.driver.jinja_combo.build_config.assert_not_called()
        self.driver.clients[API_VERSION].upload_config.assert_not_called()
        self.driver.clients[API_VERSION].reload_listener.assert_not_called()

        self.driver.update_amphora_listeners(self.lb,
                                             mock_amphora, self.timeout_dict)
        self.driver.clients[API_VERSION].upload_config.assert_called_once_with(
            mock_amphora, self.lb.id, 'the_config',
            timeout_dict=self.timeout_dict)
        self.driver.clients[API_VERSION].reload_listener(
            mock_amphora, self.lb.id, timeout_dict=self.timeout_dict)

        mock_load_cert.reset_mock()
        self.driver.jinja_combo.build_config.reset_mock()
        self.driver.clients[API_VERSION].upload_config.reset_mock()
        self.driver.clients[API_VERSION].reload_listener.reset_mock()
        mock_amphora.status = constants.DELETED
        self.driver.update_amphora_listeners(self.lb,
                                             mock_amphora, self.timeout_dict)
        mock_load_cert.assert_not_called()
        self.driver.jinja_combo.build_config.assert_not_called()
        self.driver.clients[API_VERSION].upload_config.assert_not_called()
        self.driver.clients[API_VERSION].reload_listener.assert_not_called()

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.ListenerRepository.update')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_amphora_listeners_bad_cert(
            self, mock_load_cert, mock_list_update, mock_get_session):
        mock_amphora = mock.MagicMock()
        mock_amphora.id = 'mock_amphora_id'
        mock_amphora.api_version = API_VERSION

        mock_session = mock_get_session().begin().__enter__()

        mock_load_cert.side_effect = [Exception]
        self.driver.update_amphora_listeners(self.lb,
                                             mock_amphora, self.timeout_dict)
        mock_list_update.assert_called_once_with(
            mock_session, self.lb.listeners[0].id,
            provisioning_status=constants.ERROR,
            operating_status=constants.ERROR)
        self.driver.jinja_combo.build_config.assert_not_called()
        (self.driver.clients[API_VERSION].delete_listener.
         assert_called_once_with)(mock_amphora, self.lb.id)

    def test_otlp_collector_tls_closes_and_recovers(self):
        collector = data_models.Pool(
            id=FAKE_UUID_1, protocol=constants.PROTOCOL_HTTP,
            enabled=True, tls_enabled=True, ca_tls_certificate_id='ca-ref')
        tracing = {'collector_pool_id': collector.id,
                   'service_name': 'gateway', 'span_name': 'Gateway HTTP'}
        listener = data_models.Listener(
            id='listener', protocol=constants.PROTOCOL_HTTP,
            enabled=True, otlp_tracing=tracing)
        amphora = data_models.Amphora(
            id='amphora', status=constants.ACTIVE,
            role=constants.ROLE_STANDALONE)
        amphora.api_version = API_VERSION
        lb = data_models.LoadBalancer(
            id='load-balancer', enabled=True, listeners=[listener],
            pools=[collector], amphorae=[amphora],
            topology=constants.TOPOLOGY_SINGLE)
        listener.load_balancer = lb
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING: True}
        client.reload_listener.side_effect = (
            lambda *args, otlp_publication, **kwargs: mock.Mock(
                status_code=202, headers={
                    constants.HAPROXY_OTLP_PUBLICATION_HEADER:
                    otlp_publication}))

        with (
            mock.patch.object(self.driver, '_process_pool_certs',
                              side_effect=[OSError('transfer failed'),
                                           {'ca_cert': '/tmp/ca.pem'}]),
            mock.patch.object(driver.db_api, 'session') as session,
            mock.patch.object(driver.repo.ListenerRepository,
                              'set_otlp_tracing_statuses') as publish,
        ):
            publication = mock.Mock()
            publication.attach_mock(client.reload_listener, 'reload')
            publication.attach_mock(publish, 'status')
            self.driver.update(lb)
            config = self.driver.jinja_combo.build_config.call_args.kwargs
            self.assertEqual([listener], config['listeners'])
            self.assertEqual({collector.id: {'closed': True}},
                             config['otlp_tls_certs'])

            self.driver.update(lb)
            config = self.driver.jinja_combo.build_config.call_args.kwargs
            self.assertEqual([listener], config['listeners'])
            self.assertEqual({collector.id: {'ca_cert': '/tmp/ca.pem'}},
                             config['otlp_tls_certs'])
            transaction = session().begin().__enter__()
            topology = (lb.id, lb.topology, {amphora.id: amphora.role}, True)
            self.assertEqual([
                mock.call.reload(amphora, lb.id, timeout_dict=None,
                                 otlp_publication=mock.ANY),
                mock.call.status(transaction, {
                    listener.id: (tracing, None, constants.ERROR)},
                    topology=topology),
                mock.call.reload(amphora, lb.id, timeout_dict=None,
                                 otlp_publication=mock.ANY),
                mock.call.status(transaction, {
                    listener.id: (tracing, None, constants.ACTIVE)},
                    topology=topology),
            ], publication.mock_calls)

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_system_ca_digests')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_pool_statuses')
    @mock.patch('octavia.db.repositories.ListenerRepository.'
                'set_otlp_tracing_statuses')
    def test_otlp_system_ca_is_attested_before_attachment_and_fails_closed(
            self, tracing_status, pool_status, proof, _db_session):
        digest = 'a' * 64
        config = self.useFixture(oslo_fixture.Config(cfg.CONF))
        config.config(group='api_settings',
                      enabled_backend_tls_hostname_providers=['amphora'],
                      enabled_backend_tls_system_ca_providers=['amphora'])
        config.config(group='haproxy_amphora',
                      backend_tls_system_ca_sha256=digest)
        app = data_models.Pool(id='app', enabled=True,
                               protocol=constants.PROTOCOL_HTTP)
        collector = data_models.Pool(
            id=FAKE_UUID_1, enabled=True, protocol=constants.PROTOCOL_HTTP,
            backend_tls_system_ca=True, tls_enabled=True,
            backend_tls_hostname='collector.example.test',
            alpn_protocols=['http/1.1'],
            tags=[constants.GATEWAY_OTLP_COLLECTOR_POOL_TAG])
        listener = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP, protocol_port=80,
            enabled=True, pools=[app], default_pool=app)
        peers = [data_models.Amphora(id=role, role=role,
                                     status=constants.AMPHORA_ALLOCATED)
                 for role in (constants.ROLE_MASTER, constants.ROLE_BACKUP)]
        for amp in peers:
            amp.api_version = API_VERSION
        lb = data_models.LoadBalancer(
            id='lb', project_id='project', enabled=True,
            pools=[app, collector], listeners=[listener],
            vip=data_models.Vip(ip_address='127.0.0.1'),
            amphorae=peers, topology=constants.TOPOLOGY_ACTIVE_STANDBY,
            provider='amphora')
        listener.load_balancer = lb
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True,
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA: True,
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING: True,
        }
        client.get_info.return_value = {'haproxy_version': '3.0.19',
                                        'api_version': API_VERSION}
        client.stage_backend_tls_system_ca.return_value = digest
        client.reload_listener.side_effect = (
            lambda *args, config_publication, **kwargs: mock.Mock(
                status_code=202, headers={
                    constants.HAPROXY_CONFIG_PUBLICATION_HEADER:
                    config_publication}))
        self.driver.jinja_combo = driver.jinja_combo.JinjaTemplater()

        client.stage_backend_tls_system_ca.side_effect = [digest, 'b' * 64]
        self.driver.update(lb)
        self.assertEqual({collector.id: None}, proof.call_args.args[2])
        self.assertEqual({collector.id},
                         pool_status.call_args.kwargs['closed'])
        tracing_status.assert_not_called()

        # The same isolated pool can attest after the pair recovers.
        client.stage_backend_tls_system_ca.side_effect = None
        collector.provisioning_status = constants.PENDING_UPDATE
        self.driver.update(lb)
        for call in client.upload_config.call_args_list[-2:]:
            staged = call.args[2]
            self.assertIn('default_backend app:http', staged)
            self.assertNotIn('listen octavia-otlp-', staged)
        self.assertEqual({collector.id: digest}, proof.call_args.args[2])
        tracing_status.assert_not_called()
        collector.provisioning_status = constants.ACTIVE

        collector.members = [data_models.Member(
            id='collector-member', ip_address='192.0.2.30', protocol_port=4318,
            weight=1, enabled=True)]
        listener.otlp_tracing = {
            'collector_pool_id': collector.id, 'service_name': 'gateway',
            'span_name': 'Gateway HTTP'}
        self.driver.update(lb)
        attached = client.upload_config.call_args.args[2]
        self.assertIn('default_backend app:http', attached)
        exporter = attached[attached.index('listen octavia-otlp-'):]
        self.assertIn('server collector-member 192.0.2.30:4318', exporter)
        self.assertIn(f'backend-system-ca/{digest}.pem verify required',
                      exporter)
        self.assertIn('verifyhost-strict collector.example.test', exporter)
        self.assertIn('alpn http/1.1', exporter)
        collector.alpn_protocols = None
        self.driver.update(lb)
        attached = client.upload_config.call_args.args[2]
        exporter = attached[attached.index('listen octavia-otlp-'):]
        self.assertIn('server collector-member 192.0.2.30:4318', exporter)
        self.assertIn(f'backend-system-ca/{digest}.pem verify required',
                      exporter)
        self.assertIn('verifyhost-strict collector.example.test', exporter)
        self.assertNotIn(' alpn ', exporter)
        self.assertEqual({collector.id: digest}, proof.call_args.args[2])
        self.assertEqual(constants.ACTIVE,
                         tracing_status.call_args.args[1][listener.id][-1])

        client.stage_backend_tls_system_ca.side_effect = [digest, 'b' * 64]
        self.driver.update(lb)
        for call in client.upload_config.call_args_list[-2:]:
            closed = call.args[2]
            self.assertIn('default_backend app:http', closed)
            self.assertNotIn('server collector-member', closed)
        self.assertEqual({collector.id: None}, proof.call_args.args[2])
        self.assertEqual(constants.ERROR,
                         tracing_status.call_args.args[1][listener.id][-1])

    def test_protected_pool_preflights_every_amphora(self):
        capability = constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME
        amphorae = [
            data_models.Amphora(id='amp-one', status=constants.ACTIVE),
            data_models.Amphora(id='amp-two', status=constants.ACTIVE)]
        for amphora in amphorae:
            amphora.api_version = API_VERSION
        pool = data_models.Pool(id='pool-one', enabled=True,
                                backend_tls_hostname='backend.example.test')
        listener = mock.Mock(enabled=True, pools=[pool], l7policies=[],
                             protocol=constants.PROTOCOL_HTTP)
        loadbalancer = mock.Mock(id='lb', enabled=True, listeners=[listener],
                                 amphorae=amphorae, pools=[pool])
        details = self.driver.clients[API_VERSION].get_details
        details.side_effect = [{capability: True}, {}]
        with (
            mock.patch.object(self.driver, '_update_amphora_listeners') as arm,
            mock.patch('octavia.db.api.session') as session,
            mock.patch('octavia.db.repositories.PoolRepository.'
                       'set_backend_tls_pool_statuses') as status,
        ):
            def assert_preflight(*args, **kwargs):
                self.assertEqual(2, details.call_count)

            arm.side_effect = assert_preflight
            self.driver.update(loadbalancer)
        self.assertEqual(amphorae, [call.args[1]
                                   for call in arm.call_args_list])
        self.assertEqual([{capability: True}, {}], [
            call.kwargs['amp_details'] for call in arm.call_args_list])
        for call in arm.call_args_list:
            self.assertEqual({pool.id: {'closed': True}},
                             call.kwargs['backend_tls_certs'])
        status.assert_called_once_with(session().begin().__enter__(),
                                       closed={pool.id}, recovered=set())
        self.assertEqual(
            [mock.call(amp, timeout_dict=None) for amp in amphorae],
            details.call_args_list)

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_system_ca_digests')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_pool_statuses')
    def test_system_ca_pairs_confirm_load_then_close_on_failover_mismatch(
            self, close_status, proof, db_session):
        digest = 'a' * 64
        config = self.useFixture(oslo_fixture.Config(cfg.CONF))
        config.config(group='api_settings',
                      enabled_backend_tls_hostname_providers=['amphora'],
                      enabled_backend_tls_system_ca_providers=['amphora'])
        config.config(group='haproxy_amphora',
                      backend_tls_system_ca_sha256=digest)
        peers = [data_models.Amphora(id=role, role=role,
                                     status=constants.AMPHORA_ALLOCATED)
                 for role in (constants.ROLE_MASTER, constants.ROLE_BACKUP)]
        for amp in peers:
            amp.api_version = API_VERSION
        pool = data_models.Pool(
            id='system', enabled=True, protocol=constants.PROTOCOL_HTTP,
            backend_tls_system_ca=True, tls_enabled=True,
            backend_tls_hostname='system.example.test')
        neighbor = data_models.Pool(
            id='private', enabled=True, protocol=constants.PROTOCOL_HTTP,
            backend_tls_hostname='private.example.test', tls_enabled=True,
            ca_tls_certificate_id='private-ca')
        listener = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP,
            enabled=True, pools=[pool, neighbor])
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, pools=[pool, neighbor],
            listeners=[listener], amphorae=peers, provider='amphora',
            topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True,
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA: True,
        }
        client.stage_backend_tls_system_ca.return_value = digest

        def render(lb, peer, *, backend_tls_certs, system_ca_observed,
                   **kwargs):
            material = backend_tls_certs[pool.id]
            if material.get('system_ca_sha256'):
                system_ca_observed[peer.id] = {pool.id: digest}
            return {listener.id}

        with (
            mock.patch.object(self.driver, '_update_amphora_listeners',
                              side_effect=render) as reload_config,
            mock.patch.object(self.driver, '_process_secret',
                              return_value='private.pem'),
        ):
            self.driver.update(lb)
            self.assertEqual([mock.call(
                amp, lb.id, '/etc/ssl/certs/ca-certificates.crt', digest,
                timeout_dict=None) for amp in peers],
                client.stage_backend_tls_system_ca.call_args_list)
            self.assertEqual({pool.id: digest}, proof.call_args.args[2])
            self.assertEqual(2, reload_config.call_count)
            for call in reload_config.call_args_list:
                material = call.kwargs['backend_tls_certs']
                self.assertEqual(digest, material[pool.id]['system_ca_sha256'])

            proof.reset_mock()
            reload_config.reset_mock()
            client.stage_backend_tls_system_ca.side_effect = [
                digest, exc.Conflict()]
            statuses = {amp.id: {} for amp in peers}
            self.assertTrue(self.driver.update_failover_listeners(
                lb, 0, statuses))
            self.assertEqual([{pool.id: None}] * 2,
                             [call.args[2] for call in proof.call_args_list])
            self.assertEqual({pool.id},
                             close_status.call_args.kwargs['closed'])
            self.assertEqual(2, reload_config.call_count)
            for call in reload_config.call_args_list:
                material = call.kwargs['backend_tls_certs']
                self.assertEqual({'closed': True}, material[pool.id])
                self.assertTrue(material[neighbor.id]['ca_cert'].endswith(
                    '/private.pem'))

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_system_ca_digests')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_pool_statuses')
    def test_system_ca_publication_failure_closes_reachable_peer(
            self, close_status, proof, db_session):
        digest = 'a' * 64
        config = self.useFixture(oslo_fixture.Config(cfg.CONF))
        config.config(group='api_settings',
                      enabled_backend_tls_hostname_providers=['amphora'],
                      enabled_backend_tls_system_ca_providers=['amphora'])
        config.config(group='haproxy_amphora',
                      backend_tls_system_ca_sha256=digest)
        peers = [data_models.Amphora(id=role, role=role,
                                     status=constants.AMPHORA_ALLOCATED)
                 for role in (constants.ROLE_MASTER, constants.ROLE_BACKUP)]
        for amp in peers:
            amp.api_version = API_VERSION
        pool = data_models.Pool(
            id='system', enabled=True, protocol=constants.PROTOCOL_HTTP,
            backend_tls_system_ca=True, tls_enabled=True,
            backend_tls_hostname='system.example.test')
        listener = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP,
            enabled=True, pools=[pool])
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, pools=[pool], listeners=[listener],
            amphorae=peers, provider='amphora',
            topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True,
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA: True,
        }
        upload_error = exc.Conflict()
        uploaded = {}
        installed = []

        def render(*, tls_certs, system_ca_results, config_publication,
                   **kwargs):
            closed = tls_certs[pool.id].get('closed', False)
            if not closed:
                system_ca_results[pool.id] = digest
            return closed, config_publication

        def upload(peer, lb_id, config, **kwargs):
            if peer == peers[1]:
                raise upload_error
            uploaded[peer.id] = config

        def reload(peer, lb_id, *, config_publication, **kwargs):
            closed, token = uploaded.pop(peer.id)
            self.assertEqual(token, config_publication)
            installed.append((peer.id, closed))
            return mock.Mock(
                status_code=202, headers={
                    constants.HAPROXY_CONFIG_PUBLICATION_HEADER: token})

        self.driver.jinja_combo.build_config.side_effect = render
        client.upload_config.side_effect = upload
        client.reload_listener.side_effect = reload
        with (mock.patch.object(self.driver, '_process_listener_tls_certs',
                                return_value={}),
              mock.patch.object(self.driver, '_process_listener_pool_certs',
                                return_value={})):
            client.stage_backend_tls_system_ca.side_effect = [
                digest, exc.Conflict()]
            self.assertRaises(exc.Conflict, self.driver.update, lb,
                              tcp_member_batch=True)
            self.assertEqual([(peers[0].id, True)], installed)
            self.assertEqual({pool.id: None}, proof.call_args.args[2])
            self.assertEqual({pool.id},
                             close_status.call_args.kwargs['closed'])

            installed.clear()
            client.stage_backend_tls_system_ca.side_effect = [digest, digest]
            error = self.assertRaises(
                driver_except.CoordinatedListenerUpdateError,
                self.driver.update_failover_listeners,
                lb, 0, {amp.id: {} for amp in peers})
            self.assertEqual({peers[1].id: upload_error},
                             error.amphora_errors)
            self.assertEqual([(peers[0].id, False), (peers[0].id, True)],
                             installed)
            self.assertEqual({pool.id: None}, proof.call_args.args[2])

    def test_missing_tls_capabilities_close_only_affected_pools(self):
        hostname = constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME
        h2_alpn = constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN
        amphorae = [
            data_models.Amphora(id='amp-one', status=constants.ACTIVE),
            data_models.Amphora(id='amp-two', status=constants.ACTIVE)]
        for amphora in amphorae:
            amphora.api_version = API_VERSION
        tls_pool = data_models.Pool(
            id='tls', enabled=True,
            backend_tls_hostname='backend.example.test')
        grpc_pool = data_models.Pool(
            id='grpc', enabled=True,
            backend_tls_hostname='backend.example.test',
            backend_tls_require_h2=True)
        san_pool = data_models.Pool(
            id='sans', enabled=True,
            backend_tls_hostname='sni.example.test',
            backend_tls_subject_alt_names=[
                {'type': 'Hostname', 'hostname': 'id.example.test'}])
        tcp_pool = data_models.Pool(
            id='tcp', protocol=constants.PROTOCOL_TCP, enabled=True,
            backend_tls_hostname='abc.example.com')
        listener = mock.Mock(enabled=True, protocol=constants.PROTOCOL_HTTP,
                             pools=[tls_pool, grpc_pool, san_pool],
                             l7policies=[])
        tcp_listener = mock.Mock(
            enabled=True, protocol=constants.PROTOCOL_TCP,
            tcp_tls_termination=True, pools=[tcp_pool], l7policies=[])
        lb = mock.Mock(enabled=True, listeners=[listener, tcp_listener],
                       amphorae=amphorae,
                       pools=[tls_pool, grpc_pool, san_pool, tcp_pool])
        sans = constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES
        tcp_auth = constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH
        self.driver.clients[API_VERSION].get_details.side_effect = [
            {hostname: True, h2_alpn: True, sans: True, tcp_auth: True},
            {hostname: True}]
        trust = {'ca_cert': '/ca.pem'}
        with (
            mock.patch.object(self.driver, '_process_pool_certs',
                              return_value=trust) as process_certs,
            mock.patch.object(self.driver, '_update_amphora_listeners') as arm,
            mock.patch('octavia.db.api.session'),
            mock.patch('octavia.db.repositories.PoolRepository.'
                       'set_backend_tls_pool_statuses') as status,
        ):
            self.driver.update(lb)
        self.assertEqual(
            [mock.call(listener, tls_pool, amp, lb.id) for amp in amphorae],
            process_certs.call_args_list)
        self.assertEqual(2, arm.call_count)
        for call in arm.call_args_list:
            self.assertEqual(
                {tls_pool.id: trust, grpc_pool.id: {'closed': True},
                 san_pool.id: {'closed': True}, tcp_pool.id: {'closed': True}},
                call.kwargs['backend_tls_certs'])
        self.assertEqual({grpc_pool.id, san_pool.id, tcp_pool.id},
                         status.call_args.kwargs['closed'])

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.ListenerRepository.'
                'set_frontend_fallback_statuses')
    def test_old_peer_closes_only_frontend_fallback_listener(
            self, listener_update, session):
        capability = (
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
        amphorae = [
            data_models.Amphora(id='current', status=constants.ACTIVE),
            data_models.Amphora(id='old', status=constants.ACTIVE)]
        for amphora in amphorae:
            amphora.api_version = API_VERSION
        fallback = data_models.Listener(
            id='fallback', protocol=constants.PROTOCOL_TERMINATED_HTTPS,
            enabled=True, client_authentication_insecure_fallback=True)
        strict = data_models.Listener(
            id='strict', protocol=constants.PROTOCOL_TERMINATED_HTTPS,
            enabled=True, client_authentication=constants.CLIENT_AUTH_MANDATORY)
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, listeners=[fallback, strict],
            amphorae=amphorae)
        client = self.driver.clients[API_VERSION]
        client.get_details.side_effect = [{capability: True}, {}]
        with mock.patch.object(self.driver, '_process_listener_tls_certs',
                               return_value={}) as process:
            self.driver.update(lb)
        self.assertEqual([mock.call(strict, amp, lb.id) for amp in amphorae],
                         process.call_args_list)
        render = self.driver.jinja_combo.build_config
        self.assertEqual(2, render.call_count)
        for call in render.call_args_list:
            self.assertEqual([strict], call.kwargs['listeners'])
        listener_update.assert_called_once_with(
            session().begin().__enter__(), closed={fallback.id},
            restored=set())

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.ListenerRepository.'
                'set_frontend_fallback_statuses')
    def test_activation_restores_reachable_peer_on_frontend_trust_loss(
            self, status, session):
        capability = 'frontend_client_auth_insecure_fallback_v1'
        peers = [data_models.Amphora(id=name, status=constants.ACTIVE)
                 for name in ('reachable', 'unreachable')]
        for peer in peers:
            peer.api_version = API_VERSION
        fallback = data_models.Listener(
            id='fallback', protocol=constants.PROTOCOL_TERMINATED_HTTPS,
            enabled=True, client_authentication_insecure_fallback=True)
        policy = data_models.L7Policy(id='activated', enabled=True)
        http = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP, enabled=True,
            l7policies=[policy])
        lb = data_models.LoadBalancer(id='lb', enabled=True,
                                      listeners=[fallback, http],
                                      amphorae=peers)
        client = self.driver.clients[API_VERSION]
        render = self.driver.jinja_combo.build_config
        with mock.patch.object(self.driver, '_process_listener_tls_certs',
                               return_value={}):
            client.get_details.return_value = {capability: True}
            client.reload_listener.side_effect = [None, RuntimeError()]
            self.assertRaises(RuntimeError, self.driver.update, lb,
                              l7policy_activation=True)
            status.assert_not_called()

            policy.enabled = False
            render.reset_mock()
            client.reload_listener.reset_mock()
            client.get_details.side_effect = [{capability: True}, {}]
            client.reload_listener.side_effect = [None, RuntimeError()]
            self.assertRaises(RuntimeError, self.driver.update, lb,
                              l7policy_activation=True,
                              l7policy_restoration=True)

        first = render.call_args_list[0].kwargs
        self.assertEqual(peers[0], first['host_amphora'])
        self.assertEqual([http], first['listeners'])
        self.assertFalse(first['listeners'][0].l7policies[0].enabled)
        self.assertEqual(peers[0],
                         client.reload_listener.call_args_list[0].args[0])
        status.assert_called_once_with(session().begin().__enter__(),
                                       closed={fallback.id}, restored=set())

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.ListenerRepository.'
                'set_frontend_fallback_statuses')
    def test_fallback_recovers_after_both_peers_apply(self, status, session):
        peers = [data_models.Amphora(id=name, status=constants.ACTIVE)
                 for name in ('current-one', 'current-two')]
        for peer in peers:
            peer.api_version = API_VERSION
        listener = data_models.Listener(
            id='fallback', protocol=constants.PROTOCOL_TERMINATED_HTTPS,
            enabled=True, client_authentication_insecure_fallback=True,
            provisioning_status=constants.ERROR,
            frontend_fallback_owns_error=True)
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY,
            listeners=[listener], amphorae=peers)
        capability = (
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {capability: True}
        with mock.patch.object(self.driver, '_process_listener_tls_certs',
                               return_value={}):
            lb.amphorae = peers[:1]
            self.driver.update_amphora_listeners(lb, peers[0])
            status.assert_not_called()
            lb.amphorae = peers
            client.reload_listener.side_effect = [None, RuntimeError()]
            self.assertRaises(RuntimeError, self.driver.update, lb)
            status.assert_not_called()
            client.reload_listener.reset_mock(side_effect=True)
            self.driver.update(lb)

        self.assertEqual(2, client.reload_listener.call_count)
        status.assert_called_once_with(
            session().begin().__enter__(), closed=set(), restored={listener.id})

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_http_cookie_pool_statuses')
    def test_http_cookie_status_uses_acknowledged_amphorae(self, status,
                                                           session):
        primary, secondary = [
            data_models.Amphora(id=name, role=role,
                                status=constants.AMPHORA_ALLOCATED)
            for name, role in (('primary', constants.ROLE_MASTER),
                               ('secondary', constants.ROLE_BACKUP))]
        primary.api_version = secondary.api_version = API_VERSION
        scope = 'a' * 64
        pool = data_models.Pool(
            id='pool', protocol=constants.PROTOCOL_HTTP, enabled=True,
            session_persistence=data_models.SessionPersistence(
                cookie_name='gw', cookie_absolute_timeout_ms=1500,
                cookie_scope=scope, cookie_permanent=True))
        listener = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP, enabled=True,
            pools=[pool])
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY,
            listeners=[listener], amphorae=[primary, secondary])
        client = self.driver.clients[API_VERSION]
        published_in = session().begin().__enter__()
        policy = {pool.id: ('gw', 1500, scope, True, None)}
        rendered_states = {primary.id: constants.ERROR,
                           secondary.id: constants.ACTIVE}

        def build_config(host_amphora, http_persistence_results, **kwargs):
            state = rendered_states[host_amphora.id]
            http_persistence_results[pool.id] = state
            return 'config'

        self.driver.jinja_combo.build_config.side_effect = build_config
        for batch in (False, True):
            with self.subTest(batch=batch):
                status.reset_mock()
                client.reload_listener.side_effect = [None, RuntimeError()]
                self.assertRaises(RuntimeError, self.driver.update, lb,
                                  tcp_member_batch=batch)
                status.assert_called_once_with(
                    published_in, policy, failed={pool.id}, recovered=set())

        status.reset_mock()
        client.upload_config.side_effect = [None, RuntimeError()]
        self.assertRaises(RuntimeError, self.driver.update, lb,
                          tcp_member_batch=True)
        status.assert_not_called()

        client.upload_config.side_effect = None
        client.reload_listener.side_effect = None
        rendered_states[primary.id] = constants.ACTIVE
        secondary.role = constants.ROLE_MASTER
        self.driver.update(lb)
        status.assert_not_called()
        secondary.role = constants.ROLE_BACKUP
        retiring = data_models.Amphora(id='retiring',
                                       role=constants.ROLE_BACKUP,
                                       status=constants.PENDING_DELETE)
        retiring.api_version = API_VERSION
        lb.amphorae.append(retiring)
        rendered_states[retiring.id] = constants.ERROR
        self.driver.update(lb)
        status.assert_called_once_with(
            published_in, policy, failed=set(), recovered={pool.id})
        status.reset_mock()
        lb.amphorae = [retiring, primary, secondary]
        client.reload_listener.side_effect = [None, RuntimeError()]
        self.assertRaises(RuntimeError, self.driver.update, lb)
        status.assert_not_called()

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_http_cookie_pool_statuses')
    def test_cookie_path_requires_current_confirmation_from_both_peers(
            self, status, session):
        peers = [data_models.Amphora(id=role, role=role,
                                     status=constants.AMPHORA_ALLOCATED)
                 for role in (constants.ROLE_MASTER, constants.ROLE_BACKUP)]
        for peer in peers:
            peer.api_version = API_VERSION
        persistence = data_models.SessionPersistence(
            type=constants.SESSION_PERSISTENCE_HTTP_COOKIE, cookie_path='')
        pool = data_models.Pool(id='pool', protocol=constants.PROTOCOL_HTTP,
                                enabled=True, session_persistence=persistence)
        listener = data_models.Listener(id='http', enabled=True, pools=[pool],
                                        protocol=constants.PROTOCOL_HTTP)
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY,
            listeners=[listener], amphorae=peers)
        capability = constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH
        client = self.driver.clients[API_VERSION]
        published_in = session().begin().__enter__()
        policy = {pool.id: (None, None, None, False, '')}
        render = self.driver.jinja_combo.build_config

        def build_config(amp_details, http_persistence_results=None, **kwargs):
            if http_persistence_results is not None:
                self.assertEqual(2, client.get_details.call_count)
                http_persistence_results[pool.id] = (
                    constants.ACTIVE if amp_details.get(capability) is True
                    else constants.ERROR)
            return 'config'

        render.side_effect = build_config
        yes = {capability: True}
        client.get_details.side_effect = [yes, yes]
        self.driver.update(lb)
        status.assert_called_once_with(
            published_in, policy, failed=set(), recovered={pool.id})

        status.reset_mock()
        render.reset_mock()
        client.get_details.reset_mock()
        client.get_details.side_effect = [yes, {}]
        self.driver.update(lb)
        for call in render.call_args_list:
            self.assertIs(call.kwargs['amp_details'][capability], False)
        status.assert_called_once_with(
            published_in, policy, failed={pool.id}, recovered=set())

        status.reset_mock()
        client.get_details.reset_mock()
        client.get_details.side_effect = [yes, yes]
        client.reload_listener.side_effect = [RuntimeError(), RuntimeError()]
        self.assertRaises(RuntimeError, self.driver.update, lb)
        status.assert_called_once_with(
            published_in, policy, failed={pool.id}, recovered=set())

        status.reset_mock()
        client.get_details.side_effect = [{}, {}]
        client.reload_listener.side_effect = None
        persistence.cookie_path = None
        self.driver.update(lb)
        status.assert_not_called()

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_http_header_pool_statuses')
    @mock.patch.object(driver.jinja_combo, '_read_http_cookie_signing_key',
                       return_value=None)
    def test_standby_header_withdrawal_reaches_master_after_upload_failure(
            self, read_key, status, session):
        lb, pool, peers, client = self._header_persistence_pair()
        master, standby = peers
        capability = constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE

        def render(*, amp_details, http_persistence_results, **kwargs):
            self.assertFalse(amp_details[capability])
            http_persistence_results[pool.id] = constants.ERROR
            return 'closed'

        def upload(peer, lb_id, config, **kwargs):
            if peer.id == standby.id:
                raise exc.Conflict()

        client.upload_config.side_effect = upload
        client.reload_listener.side_effect = self._ack_haproxy_publication
        self.driver.jinja_combo.build_config.side_effect = render

        for standby_has_probe in (False, True):
            with self.subTest(standby_has_probe=standby_has_probe):
                client.reset_mock()
                read_key.reset_mock()
                status.reset_mock()
                client.get_details.side_effect = [
                    {capability: standby_has_probe}, {capability: True}]
                self.assertRaises(
                    exc.Conflict, self.driver.update_amphora_listeners,
                    lb, standby)
                self.assertEqual([(standby, lb.id, 'closed'),
                                  (master, lb.id, 'closed')],
                                 [call.args for call in
                                  client.upload_config.call_args_list])
                reloads = client.reload_listener.call_args_list
                self.assertEqual([master], [call.args[0] for call in reloads])
                self.assertEqual(int(standby_has_probe), read_key.call_count)
                status.assert_called_once_with(
                    session().begin().__enter__(),
                    {pool.id: ('x-session', None)},
                    failed={pool.id}, recovered=set())

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_http_header_pool_statuses')
    @mock.patch.object(driver.jinja_combo, '_read_http_cookie_signing_key',
                       return_value=b'x' * 32)
    def test_header_recovery_requires_active_generation_on_both_peers(
            self, read_key, status, session):
        lb, pool, peers, client = self._header_persistence_pair()
        master, standby = peers
        capability = constants.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        client.get_details.return_value = {capability: True}
        uploaded = {}
        active = {}

        def render(*, amp_details, http_persistence_results, **kwargs):
            opened = amp_details[capability] is True
            http_persistence_results[pool.id] = (
                constants.ACTIVE if opened else constants.ERROR)
            return 'open' if opened else 'closed'

        def upload(peer, lb_id, config, **kwargs):
            uploaded[peer.id] = config

        def reload(peer, lb_id, **kwargs):
            if peer.id == standby.id and uploaded[peer.id] == 'open':
                return mock.Mock(status_code=202, headers={
                    constants.HAPROXY_OTLP_PUBLICATION_HEADER: 'stale'})
            active[peer.id] = uploaded[peer.id]
            return self._ack_haproxy_publication(peer, lb_id, **kwargs)

        self.driver.jinja_combo.build_config.side_effect = render
        client.upload_config.side_effect = upload
        for grouped in (False, True):
            with self.subTest(grouped=grouped):
                status.reset_mock()
                active.clear()
                client.reload_listener.side_effect = reload
                self.assertRaises(driver_except.ListenerProvisioningError,
                                  self.driver.update, lb,
                                  tcp_member_batch=grouped)
                self.assertEqual({peer.id: 'closed' for peer in peers}, active)
                status.assert_called_once_with(
                    session().begin().__enter__(),
                    {pool.id: ('x-session', None)},
                    failed={pool.id}, recovered=set())

                status.reset_mock()
                client.reload_listener.side_effect = (
                    self._ack_haproxy_publication)
                self.driver.update(lb, tcp_member_batch=grouped)
                status.assert_called_once_with(
                    session().begin().__enter__(),
                    {pool.id: ('x-session', None)},
                    failed=set(), recovered={pool.id})

        status.reset_mock()
        client.reload_listener.reset_mock()
        self.driver.update_amphora_listeners(lb, standby)
        reloads = client.reload_listener.call_args_list
        self.assertEqual([standby], [call.args[0] for call in reloads])
        status.assert_not_called()

    def _header_persistence_pair(self):
        peers = [
            data_models.Amphora(id=role, role=role,
                                status=constants.AMPHORA_ALLOCATED)
            for role in (constants.ROLE_MASTER, constants.ROLE_BACKUP)]
        persistence = data_models.SessionPersistence(
            type=constants.SESSION_PERSISTENCE_HTTP_HEADER,
            header_name='x-session')
        pool = data_models.Pool(id='pool', protocol=constants.PROTOCOL_HTTP,
                                enabled=True, session_persistence=persistence)
        listener = data_models.Listener(id='http', enabled=True, pools=[pool],
                                        protocol=constants.PROTOCOL_HTTP)
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY,
            listeners=[listener], amphorae=peers)
        return lb, pool, peers, self.driver.clients[API_VERSION]

    @staticmethod
    def _ack_haproxy_publication(peer, lb_id, *, otlp_publication=None,
                                 **kwargs):
        return mock.Mock(status_code=202, headers={
            constants.HAPROXY_OTLP_PUBLICATION_HEADER: otlp_publication})

    @mock.patch('octavia.db.api.session')
    @mock.patch('octavia.db.repositories.PoolRepository.'
                'set_backend_tls_pool_statuses')
    def test_failover_uses_same_trust_decision_on_both_peers(
            self, status, session):
        amphorae = [
            data_models.Amphora(id='amp-one', status=constants.ACTIVE),
            data_models.Amphora(id='amp-two', status=constants.ACTIVE)]
        pool = data_models.Pool(
            id='grpc', protocol=constants.PROTOCOL_HTTP, enabled=True,
            tls_enabled=True, backend_tls_hostname='backend.example.test',
            backend_tls_require_h2=True, ca_tls_certificate_id='ca')
        listener = data_models.Listener(
            id='http', protocol=constants.PROTOCOL_HTTP, enabled=True,
            pools=[pool])
        lb = data_models.LoadBalancer(
            id='lb', enabled=True, listeners=[listener], amphorae=amphorae)
        client = self.driver.clients[API_VERSION]
        client.get_details.return_value = {
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True,
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN: True,
        }
        self.driver.cert_manager.get_secret.return_value = (
            sample_certs.X509_CA_CERT)

        def render(**kwargs):
            self.assertEqual(2, client.upload_cert_pem.call_count)
            return 'config'

        build = self.driver.jinja_combo.build_config
        build.side_effect = render
        client.upload_cert_pem.side_effect = [None, RuntimeError('CA upload')]
        self.assertTrue(self.driver.update_failover_listeners(lb, 1, {}))
        client.reload_listener.assert_not_called()
        self.assertTrue(self.driver.update_failover_listeners(lb, 0, {}))

        for call in build.call_args_list:
            self.assertEqual({'closed': True},
                             call.kwargs['tls_certs'][pool.id])
        reload_calls = [mock.call(amp, lb.id, timeout_dict=None)
                        for amp in amphorae]
        self.assertEqual(reload_calls, client.reload_listener.call_args_list)
        status.assert_called_once_with(session().begin().__enter__(),
                                       closed={pool.id}, recovered=set())

        pool.provisioning_status = constants.ERROR
        client.reset_mock(side_effect=True)
        build.reset_mock()
        status.reset_mock()
        reload_error = RuntimeError('reload')
        client.reload_listener.side_effect = [None, reload_error]
        with self.assertRaises(
                driver_except.CoordinatedListenerUpdateError) as caught:
            self.driver.update_failover_listeners(lb, 0, {})
        self.assertEqual({amphorae[1].id: reload_error},
                         caught.exception.amphora_errors)
        status.assert_not_called()

        client.reset_mock(side_effect=True)
        build.reset_mock()

        def publish(*args, **kwargs):
            self.assertEqual(reload_calls,
                             client.reload_listener.call_args_list)

        status.side_effect = publish
        self.assertTrue(self.driver.update_failover_listeners(lb, 0, {}))
        for call in build.call_args_list:
            self.assertIn('ca_cert', call.kwargs['tls_certs'][pool.id])
        status.assert_called_once_with(session().begin().__enter__(),
                                       closed=set(), recovered={pool.id})

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_secret')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.common.tls_utils.cert_parser.get_host_names')
    def test_update(self, mock_cert, mock_load_crt, mock_secret):
        mock_cert.return_value = {'cn': sample_certs.X509_CERT_CN}
        mock_secret.side_effect = ['filename.pem', 'crl-filename.pem']
        sconts = []
        for sni_container in self.sl.sni_containers:
            sconts.append(sni_container.tls_container)
        mock_load_crt.side_effect = [{
            'tls_cert': self.sl.default_tls_container, 'sni_certs': sconts},
            {'tls_cert': None, 'sni_certs': []}]
        self.driver.clients[API_VERSION].get_cert_md5sum.side_effect = [
            exc.NotFound, 'Fake_MD5', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'CA_CERT_MD5']
        self.driver.jinja_combo.build_config.side_effect = ['fake_config']

        # Execute driver method
        self.driver.update(self.lb)

        # verify result
        gcm_calls = [
            mock.call(self.amp, self.lb.id,
                      self.sl.default_tls_container.id + '.pem',
                      ignore=(404,)),
            mock.call(self.amp, self.lb.id,
                      sconts[0].id + '.pem', ignore=(404,)),
            mock.call(self.amp, self.lb.id,
                      sconts[1].id + '.pem', ignore=(404,)),
        ]

        self.driver.clients[API_VERSION].get_cert_md5sum.assert_has_calls(
            gcm_calls, any_order=True)

        # this is called three times (last MD5 matches)
        fp1 = b'\n'.join([sample_certs.X509_CERT,
                          sample_certs.X509_CERT_KEY,
                          sample_certs.X509_IMDS]) + b'\n'
        fp2 = b'\n'.join([sample_certs.X509_CERT_2,
                          sample_certs.X509_CERT_KEY_2,
                          sample_certs.X509_IMDS]) + b'\n'
        fp3 = b'\n'.join([sample_certs.X509_CERT_3,
                          sample_certs.X509_CERT_KEY_3,
                          sample_certs.X509_IMDS]) + b'\n'

        ucp_calls = [
            mock.call(self.amp, self.lb.id,
                      self.sl.default_tls_container.id + '.pem', fp1),
            mock.call(self.amp, self.lb.id,
                      sconts[0].id + '.pem', fp2),
            mock.call(self.amp, self.lb.id,
                      sconts[1].id + '.pem', fp3),
        ]

        self.driver.clients[API_VERSION].upload_cert_pem.assert_has_calls(
            ucp_calls, any_order=True)

        # upload only one config file
        self.driver.clients[API_VERSION].upload_config.assert_called_once_with(
            self.amp, self.lb.id, 'fake_config', timeout_dict=None)
        # start should be called once
        self.driver.clients[
            API_VERSION].reload_listener.assert_called_once_with(
            self.amp, self.lb.id, timeout_dict=None)
        secret_calls = [
            mock.call(self.sl, self.sl.client_ca_tls_certificate_id, self.amp,
                      self.lb.id),
            mock.call(self.sl, self.sl.client_crl_container_id, self.amp,
                      self.lb.id)
        ]
        mock_secret.assert_has_calls(secret_calls)

    def test_udp_update(self):
        self.driver.lvs_jinja.build_config.side_effect = ['fake_udp_config']

        # Execute driver method
        self.driver.update(self.lb_udp)

        # upload only one config file
        self.driver.clients[
            API_VERSION].upload_udp_config.assert_called_once_with(
            self.amp, self.sl_udp.id, 'fake_udp_config', timeout_dict=None)

        # start should be called once
        self.driver.clients[
            API_VERSION].reload_listener.assert_called_once_with(
            self.amp, self.sl_udp.id, timeout_dict=None)

    def _guarded_udp_graph(self):
        graph = sample_configs_combined.sample_lb_with_udp_listener_tuple(
            topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        graph.amphorae[:] = [
            amp._replace(status=constants.AMPHORA_ALLOCATED)
            for amp in graph.amphorae
        ]
        listener = graph.listeners[0]
        pool = SimpleNamespace(**listener.default_pool._asdict())
        pool.udp_packet_drop = {'numerator': 0, 'denominator': 1}
        pool.health_monitor = None
        pool.session_persistence = None
        pool.members = [member._replace(provisioning_status=status)
                        for member, status in zip(pool.members, (
                            constants.ACTIVE, constants.DELETED))]
        listener = listener._replace(default_pool=pool, load_balancer=graph)
        graph.listeners[:] = [listener]
        return graph, listener

    def test_weighted_passthrough_requires_all_amphorae_and_reload_receipts(
            self):
        graph, sample = self._guarded_udp_graph()
        rule = data_models.L7Rule(type=constants.L7RULE_TYPE_TLS_SNI,
                                  enabled=True)
        route = data_models.L7Policy(
            action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            enabled=True, l7rules=[rule])
        listener = sample._replace(protocol=constants.PROTOCOL_TCP,
                                   default_pool=None, pools=[],
                                   l7policies=[route])
        graph.listeners[:] = [listener]
        capability = (
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        client = self.driver.clients[API_VERSION]
        supported = {capability: True}
        self.driver.jinja_combo.build_config.return_value = 'the_config'

        def acknowledge(*args, otlp_publication, **kwargs):
            return SimpleNamespace(status_code=202, headers={
                constants.HAPROXY_OTLP_PUBLICATION_HEADER: otlp_publication})

        client.reload_listener.side_effect = acknowledge
        client.get_details.side_effect = [supported, requests.ConnectionError]
        self.assertRaises(driver_except.ListenerProvisioningError,
                          self.driver.update, graph, l7policy_activation=True)
        client.upload_config.assert_called_once_with(
            graph.amphorae[0], graph.id, 'the_config', timeout_dict=None)
        self.assertTrue(self.driver.jinja_combo.build_config.call_args.kwargs[
            'weighted_passthrough_degraded'])
        client.reload_listener.assert_called_once()

        # Restoration also retains ownership when the saved policy is
        # disabled and only one peer can confirm the new config.
        route.enabled = False
        client.reset_mock()
        client.get_details.side_effect = [supported, requests.ConnectionError]
        self.assertRaises(
            driver_except.ListenerProvisioningError, self.driver.update, graph,
            l7policy_activation=True, l7policy_restoration=True)
        client.reload_listener.assert_called_once()

        route.enabled = True
        client.get_details.side_effect = None
        client.get_details.return_value = supported
        client.reload_listener.side_effect = None
        client.reload_listener.return_value = requests.Response()
        self.assertRaises(driver_except.ListenerProvisioningError,
                          self.driver.update, graph, l7policy_activation=True)

        client.reset_mock()
        client.reload_listener.side_effect = acknowledge
        self.driver.update(graph, l7policy_activation=True)
        self.assertEqual(2, client.reload_listener.call_count)
        self.assertEqual(
            {amp.id for amp in graph.amphorae},
            {call.args[0].id
             for call in client.reload_listener.call_args_list})
        self.assertTrue(all(call.kwargs.get('otlp_publication')
                            for call in client.reload_listener.call_args_list))

    def test_udp_batch_prepares_every_amphora_before_reload(self):
        graph, listener = self._guarded_udp_graph()
        client = self.driver.clients[API_VERSION]
        self.driver.lvs_jinja.build_config.return_value = 'fake_udp_config'
        receipt = self.driver.apply_udp_member_batch(graph, listener.id)
        self.assertEqual(tuple((amp.id, amp.role) for amp in graph.amphorae),
                         receipt)
        guard = client.stage_udp_guard.call_args.args[-1]
        self.assertEqual({'numerator': 0, 'denominator': 1}, guard['fraction'])
        member = listener.default_pool.members[0]
        self.assertEqual([{'address': member.ip_address,
                           'port': member.protocol_port,
                           'weight': member.weight}], guard['destinations'])
        primary, secondary = graph.amphorae
        client.assert_has_calls([
            mock.call.check_udp_guard(primary, timeout_dict=None),
            mock.call.check_udp_guard(secondary, timeout_dict=None),
            mock.call.stage_udp_guard(primary, listener.id,
                                      'fake_udp_config', guard),
            mock.call.stage_udp_guard(secondary, listener.id,
                                      'fake_udp_config', guard),
            mock.call.activate_udp_guard(primary, listener.id),
            mock.call.activate_udp_guard(secondary, listener.id),
        ])
        client.upload_udp_config.assert_not_called()

    def test_udp_batch_rejects_old_amphora_before_any_upload(self):
        graph, listener = self._guarded_udp_graph()
        client = self.driver.clients[API_VERSION]
        client.check_udp_guard.side_effect = [None, exc.NotFound()]
        self.assertRaises(driver_except.AmpDriverNotImplementedError,
                          self.driver.apply_udp_member_batch, graph,
                          listener.id)
        client.stage_udp_guard.assert_not_called()
        client.upload_udp_config.assert_not_called()
        client.activate_udp_guard.assert_not_called()

    def test_udp_batch_rejects_missing_standby_before_staging(self):
        graph, listener = self._guarded_udp_graph()
        graph.amphorae.pop()
        self.assertRaises(driver_except.ListenerProvisioningError,
                          self.driver.apply_udp_member_batch, graph,
                          listener.id)
        client = self.driver.clients[API_VERSION]
        client.check_udp_guard.assert_not_called()
        client.stage_udp_guard.assert_not_called()
        client.activate_udp_guard.assert_not_called()

    def test_udp_pool_retirement_on_old_peer_only_closes_target(self):
        graph, listener = self._guarded_udp_graph()
        listener.default_pool.provisioning_status = constants.PENDING_DELETE
        stock_udp = listener._replace(id='sibling', default_pool=None)
        graph.listeners.append(stock_udp)
        client = self.driver.clients[API_VERSION]
        client.check_udp_guard.side_effect = [exc.NotFound(), None]
        self.assertRaises(driver_except.AmpDriverNotImplementedError,
                          self.driver.update_udp_pool_listeners, graph,
                          [listener.id])
        legacy, current = graph.amphorae
        client.close_legacy_udp_listener.assert_called_once_with(
            legacy, listener.id, timeout_dict=None)
        self.assertEqual((current, listener.id),
                         client.stage_udp_guard.call_args.args[:2])
        client.activate_udp_guard.assert_called_once_with(
            current, listener.id, timeout_dict=None)
        client.upload_udp_config.assert_not_called()
        client.reload_listener.assert_not_called()

    def test_udp_retirement_rejects_incomplete_allocated_peers(self):
        graph, listener = self._guarded_udp_graph()
        listener.default_pool.provisioning_status = constants.PENDING_DELETE
        for removed_peer in range(2):
            graph.amphorae.pop()
            self.assertRaises(driver_except.ListenerProvisioningError,
                              self.driver.update_udp_pool_listeners, graph,
                              [listener.id])
            self.assertRaises(driver_except.ListenerProvisioningError,
                              self.driver.delete, listener)
        self.assertFalse(self.driver.clients[API_VERSION].mock_calls)

    def test_delete_managed_listener_needs_proof_from_each_peer(self):
        # ListenerRepository.get supplies a DataModel with the default pool
        # still attached, including on the PENDING_DELETE path.
        graph, listener = self._guarded_udp_graph()
        lb = data_models.LoadBalancer(
            vip=graph.vip, amphorae=graph.amphorae,
            enabled=True, topology=graph.topology)
        pool = data_models.Pool(
            protocol=constants.PROTOCOL_UDP,
            lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
            provisioning_status=constants.ACTIVE, enabled=True,
            udp_packet_drop={'numerator': 1, 'denominator': 4})
        target = data_models.Listener(
            id=listener.id, load_balancer=lb, default_pool=pool,
            protocol=constants.PROTOCOL_UDP, protocol_port=18053,
            provisioning_status=constants.PENDING_DELETE, enabled=True)
        sibling = data_models.Listener(id='sibling', load_balancer=lb,
                                       protocol=constants.PROTOCOL_UDP,
                                       protocol_port=18054)
        lb.listeners = [target, sibling]
        client = self.driver.clients[API_VERSION]
        unavailable = exc.NotFound()
        client.check_udp_guard.side_effect = [unavailable, None]
        self.assertRaises(driver_except.AmpDriverNotImplementedError,
                          self.driver.delete, target)
        legacy, current = lb.amphorae
        client.close_legacy_udp_listener.assert_called_once_with(
            legacy, target.id, timeout_dict=None)
        self.assertEqual((current, target.id),
                         client.stage_udp_guard.call_args.args[:2])
        guard = client.stage_udp_guard.call_args.args[3]
        self.assertTrue(guard['retiring'])
        self.assertFalse(guard['has_service'])
        client.delete_guarded_udp_listener.assert_called_once_with(
            current, target.id)
        client.delete_listener.assert_not_called()
        client.activate_udp_guard.assert_not_called()
        client.reload_listener.assert_not_called()

        client.reset_mock()
        client.check_udp_guard.side_effect = None
        expected = tuple((amp.id, amp.role) for amp in lb.amphorae)
        self.assertEqual(expected, self.driver.delete(target))
        self.assertEqual(2, client.delete_guarded_udp_listener.call_count)

    def test_udp_stock_pool_retirement_only_reloads_target(self):
        graph, listener = self._guarded_udp_graph()
        listener.default_pool.udp_packet_drop = None
        listener.default_pool.provisioning_status = constants.PENDING_DELETE
        graph.listeners.append(listener._replace(id='sibling'))
        self.driver.update_udp_pool_listeners(graph, [listener.id])
        client = self.driver.clients[API_VERSION]
        client.reload_listener.assert_has_calls([
            mock.call(amp, listener.id, timeout_dict=None)
            for amp in graph.amphorae])
        self.assertEqual(2, client.reload_listener.call_count)
        client.check_udp_guard.assert_not_called()

    def test_udp_empty_pool_renders_without_ipvs_service(self):
        graph, listener = self._guarded_udp_graph()
        listener.default_pool.members.clear()
        self.driver.lvs_jinja = jinja_udp_cfg.LvsJinjaTemplater()
        self.driver.update_amphora_listeners(graph, graph.amphorae[1])
        client = self.driver.clients[API_VERSION]
        _, _, config, guard = client.stage_udp_guard.call_args.args
        self.assertNotIn('virtual_server', config)
        self.assertFalse(guard['has_service'])
        self.assertEqual([], guard['destinations'])
        client.upload_udp_config.assert_not_called()

    def test_upload_cert_amp(self):
        self.driver.upload_cert_amp(self.amp, octavia_utils.b('test'))
        self.driver.clients[
            API_VERSION].update_cert_for_rotation.assert_called_once_with(
            self.amp, octavia_utils.b('test'))

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test__process_tls_certificates_no_ca_cert(self, mock_load_crt):
        sample_listener = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True)
        sconts = []
        for sni_container in sample_listener.sni_containers:
            sconts.append(sni_container.tls_container)
        mock_load_crt.return_value = {
            'tls_cert': self.sl.default_tls_container,
            'sni_certs': sconts
        }
        self.driver.clients[API_VERSION].get_cert_md5sum.side_effect = [
            exc.NotFound, 'Fake_MD5', 'aaaaa', 'aaaaa']
        self.driver._process_tls_certificates(
            sample_listener, self.amp, sample_listener.load_balancer.id)
        gcm_calls = [
            mock.call(self.amp, self.lb.id,
                      self.sl.default_tls_container.id + '.pem',
                      ignore=(404,)),
            mock.call(self.amp, self.lb.id,
                      sconts[0].id + '.pem', ignore=(404,)),
            mock.call(self.amp, self.lb.id,
                      sconts[1].id + '.pem', ignore=(404,))
        ]
        self.driver.clients[API_VERSION].get_cert_md5sum.assert_has_calls(
            gcm_calls, any_order=True)
        fp1 = b'\n'.join([sample_certs.X509_CERT,
                          sample_certs.X509_CERT_KEY,
                          sample_certs.X509_IMDS]) + b'\n'
        fp2 = b'\n'.join([sample_certs.X509_CERT_2,
                          sample_certs.X509_CERT_KEY_2,
                          sample_certs.X509_IMDS]) + b'\n'
        fp3 = b'\n'.join([sample_certs.X509_CERT_3,
                          sample_certs.X509_CERT_KEY_3,
                          sample_certs.X509_IMDS]) + b'\n'
        ucp_calls = [
            mock.call(self.amp, self.lb.id,
                      self.sl.default_tls_container.id + '.pem', fp1),
            mock.call(self.amp, self.lb.id,
                      sconts[0].id + '.pem', fp2),
            mock.call(self.amp, self.lb.id,
                      sconts[1].id + '.pem', fp3)
        ]
        self.driver.clients[API_VERSION].upload_cert_pem.assert_has_calls(
            ucp_calls, any_order=True)
        self.assertEqual(
            4, self.driver.clients[API_VERSION].upload_cert_pem.call_count)

    @mock.patch('oslo_context.context.RequestContext')
    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._upload_cert')
    def test_process_secret(self, mock_upload_cert, mock_oslo):
        # Test bypass if no secret_ref
        sample_listener = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True)

        result = self.driver._process_secret(sample_listener, None)

        self.assertIsNone(result)
        self.driver.cert_manager.get_secret.assert_not_called()

        # Test the secret process
        sample_listener = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True, client_ca_cert=True)
        fake_context = 'fake context'
        fake_secret = b'fake cert'
        mock_oslo.return_value = fake_context
        self.driver.cert_manager.get_secret.reset_mock()
        self.driver.cert_manager.get_secret.return_value = fake_secret
        ref_md5 = hashlib.md5(
            fake_secret, usedforsecurity=False).hexdigest()  # nosec
        ref_id = hashlib.sha1(fake_secret).hexdigest()  # nosec
        ref_name = f'{ref_id}.pem'

        result = self.driver._process_secret(
            sample_listener, sample_listener.client_ca_tls_certificate_id,
            self.amp, sample_listener.id)

        mock_oslo.assert_called_once_with(
            project_id=sample_listener.project_id)
        self.driver.cert_manager.get_secret.assert_called_once_with(
            fake_context, sample_listener.client_ca_tls_certificate_id)
        mock_upload_cert.assert_called_once_with(
            self.amp, sample_listener.id, pem=fake_secret,
            md5sum=ref_md5, name=ref_name)
        self.assertEqual(ref_name, result)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_pool_certs')
    def test__process_listener_pool_certs(self, mock_pool_cert):
        sample_listener = sample_configs_combined.sample_listener_tuple(
            l7=True)

        ref_pool_cert_1 = {'client_cert': '/some/fake/cert-1.pem'}
        ref_pool_cert_2 = {'client_cert': '/some/fake/cert-2.pem'}

        mock_pool_cert.side_effect = [ref_pool_cert_1, ref_pool_cert_2]

        ref_cert_dict = {'sample_pool_id_1': ref_pool_cert_1,
                         'sample_pool_id_2': ref_pool_cert_2}

        result = self.driver._process_listener_pool_certs(
            sample_listener, self.amp, sample_listener.load_balancer.id)

        pool_certs_calls = [
            mock.call(sample_listener, sample_listener.default_pool,
                      self.amp, sample_listener.load_balancer.id),
            mock.call(sample_listener, sample_listener.pools[1],
                      self.amp, sample_listener.load_balancer.id)
        ]

        mock_pool_cert.assert_has_calls(pool_certs_calls, any_order=True)

        self.assertEqual(ref_cert_dict, result)

    def test_disabled_protected_pool_skips_certificates(self):
        pool = data_models.Pool(
            id='protected-pool', enabled=False, tls_enabled=True,
            backend_tls_hostname='backend.example.test',
            tls_certificate_id='unavailable-client-cert',
            ca_tls_certificate_id='unavailable-ca',
            crl_container_id='unavailable-crl')
        listener = self.sl._replace(pools=[pool])

        self.assertEqual(
            {}, self.driver._process_listener_pool_certs(
                listener, self.amp, self.lb.id))
        self.assertEqual([], self.driver.cert_manager.mock_calls)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_secret')
    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._upload_cert')
    @mock.patch('octavia.common.tls_utils.cert_parser.build_pem')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test__process_pool_certs(self, mock_load_certs, mock_build_pem,
                                 mock_upload_cert, mock_secret):
        fake_cert_dir = '/fake/cert/dir'
        conf = oslo_fixture.Config(cfg.CONF)
        conf.config(group="haproxy_amphora", base_cert_dir=fake_cert_dir)
        sample_listener = sample_configs_combined.sample_listener_tuple(
            pool_cert=True, pool_ca_cert=True, pool_crl=True)
        pool_cert = data_models.TLSContainer(
            id=uuidutils.generate_uuid(), certificate='pool cert')
        pool_data = {'tls_cert': pool_cert, 'sni_certs': []}
        mock_load_certs.return_value = pool_data
        fake_pem = b'fake pem'
        mock_build_pem.return_value = fake_pem
        ref_md5 = hashlib.md5(
            fake_pem, usedforsecurity=False).hexdigest()  # nosec
        ref_name = f'{pool_cert.id}.pem'
        ref_path = (f'{fake_cert_dir}/{sample_listener.load_balancer.id}/'
                    f'{ref_name}')
        ref_ca_name = 'fake_ca.pem'
        ref_ca_path = '{cert_dir}/{lb_id}/{name}'.format(
            cert_dir=fake_cert_dir, lb_id=sample_listener.load_balancer.id,
            name=ref_ca_name)
        ref_crl_name = 'fake_crl.pem'
        ref_crl_path = '{cert_dir}/{lb_id}/{name}'.format(
            cert_dir=fake_cert_dir, lb_id=sample_listener.load_balancer.id,
            name=ref_crl_name)
        ref_result = {'client_cert': ref_path, 'ca_cert': ref_ca_path,
                      'crl': ref_crl_path}
        mock_secret.side_effect = [ref_ca_name, ref_crl_name]

        result = self.driver._process_pool_certs(
            sample_listener, sample_listener.default_pool, self.amp,
            sample_listener.load_balancer.id)

        secret_calls = [
            mock.call(sample_listener,
                      sample_listener.default_pool.ca_tls_certificate_id,
                      self.amp, sample_listener.load_balancer.id),
            mock.call(sample_listener,
                      sample_listener.default_pool.crl_container_id,
                      self.amp, sample_listener.load_balancer.id)]

        mock_build_pem.assert_called_once_with(pool_cert)
        mock_upload_cert.assert_called_once_with(
            self.amp, sample_listener.load_balancer.id, pem=fake_pem,
            md5sum=ref_md5, name=ref_name)
        mock_secret.assert_has_calls(secret_calls)
        self.assertEqual(ref_result, result)

    def test_start(self):
        amp1 = mock.MagicMock()
        amp1.api_version = API_VERSION
        amp2 = mock.MagicMock()
        amp2.api_version = API_VERSION
        amp2.status = constants.DELETED
        loadbalancer = mock.MagicMock()
        loadbalancer.id = uuidutils.generate_uuid()
        loadbalancer.amphorae = [amp1, amp2]
        loadbalancer.vip = self.sv
        listener = mock.MagicMock()
        listener.id = uuidutils.generate_uuid()
        listener.protocol = constants.PROTOCOL_HTTP
        loadbalancer.listeners = [listener]
        listener.load_balancer = loadbalancer
        self.driver.clients[
            API_VERSION].start_listener.__name__ = 'start_listener'
        # Execute driver method
        self.driver.start(loadbalancer)
        self.driver.clients[
            API_VERSION].start_listener.assert_called_once_with(
            amp1, loadbalancer.id, None)

    def test_reload(self):
        amp1 = mock.MagicMock()
        amp1.api_version = API_VERSION
        amp2 = mock.MagicMock()
        amp2.api_version = API_VERSION
        amp2.status = constants.DELETED
        loadbalancer = mock.MagicMock()
        loadbalancer.id = uuidutils.generate_uuid()
        loadbalancer.amphorae = [amp1, amp2]
        loadbalancer.vip = self.sv
        listener = mock.MagicMock()
        listener.id = uuidutils.generate_uuid()
        listener.protocol = constants.PROTOCOL_HTTP
        loadbalancer.listeners = [listener]
        listener.load_balancer = loadbalancer
        self.driver.clients[
            API_VERSION].reload_listener.__name__ = 'reload_listener'
        # Execute driver method
        self.driver.reload(loadbalancer)
        self.driver.clients[
            API_VERSION].reload_listener.assert_called_once_with(
            amp1, loadbalancer.id, None)

        self.driver.clients[
            API_VERSION].reload_listener.reset_mock()
        timeout_dict = {
            'elem1': 1000
        }
        self.driver.reload(loadbalancer, timeout_dict=timeout_dict)
        self.driver.clients[
            API_VERSION].reload_listener.assert_called_once_with(
            amp1, loadbalancer.id, timeout_dict)

    def test_start_with_amphora(self):
        # Execute driver method
        amp = mock.MagicMock()
        self.driver.clients[
            API_VERSION].start_listener.__name__ = 'start_listener'
        self.driver.start(self.lb, self.amp)
        self.driver.clients[
            API_VERSION].start_listener.assert_called_once_with(
            self.amp, self.lb.id, None)

        self.driver.clients[API_VERSION].start_listener.reset_mock()
        amp.status = constants.DELETED
        self.driver.start(self.lb, amp)
        self.driver.clients[API_VERSION].start_listener.assert_not_called()

    def test_udp_start(self):
        self.driver.clients[
            API_VERSION].start_listener.__name__ = 'start_listener'
        # Execute driver method
        self.driver.start(self.lb_udp)
        self.driver.clients[
            API_VERSION].start_listener.assert_called_once_with(
            self.amp, self.sl_udp.id, None)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_secret')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.common.tls_utils.cert_parser.get_host_names')
    def test_delete_second_listener(self, mock_cert, mock_load_crt,
                                    mock_secret):
        self.driver.clients[
            API_VERSION].delete_listener.__name__ = 'delete_listener'
        sl = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True, client_ca_cert=True, client_crl_cert=True,
            recursive_nest=True)
        sl2 = sample_configs_combined.sample_listener_tuple(
            id='sample_listener_id_2')
        sl.load_balancer.listeners.append(sl2)
        mock_cert.return_value = {'cn': sample_certs.X509_CERT_CN}
        mock_secret.side_effect = ['filename.pem', 'crl-filename.pem']
        sconts = []
        for sni_container in self.sl.sni_containers:
            sconts.append(sni_container.tls_container)
        mock_load_crt.side_effect = [{
            'tls_cert': self.sl.default_tls_container, 'sni_certs': sconts},
            {'tls_cert': None, 'sni_certs': []}]
        self.driver.jinja_combo.build_config.side_effect = ['fake_config']
        # Execute driver method
        self.driver.delete(sl)

        # All of the pem files should be removed
        dcp_calls = [
            mock.call(self.amp, sl.load_balancer.id,
                      self.sl.default_tls_container.id + '.pem'),
            mock.call(self.amp, sl.load_balancer.id, sconts[0].id + '.pem'),
            mock.call(self.amp, sl.load_balancer.id, sconts[1].id + '.pem'),
        ]
        self.driver.clients[API_VERSION].delete_cert_pem.assert_has_calls(
            dcp_calls, any_order=True)

        # Now just make sure we did an update and not a delete
        self.driver.clients[API_VERSION].delete_listener.assert_not_called()
        self.driver.clients[API_VERSION].upload_config.assert_called_once_with(
            self.amp, sl.load_balancer.id, 'fake_config', timeout_dict=None)
        # start should be called once
        self.driver.clients[
            API_VERSION].reload_listener.assert_called_once_with(
            self.amp, sl.load_balancer.id, timeout_dict=None)

    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.'
                'HaproxyAmphoraLoadBalancerDriver._process_secret')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.common.tls_utils.cert_parser.get_host_names')
    def test_delete_second_listener_active_standby(self, mock_cert,
                                                   mock_load_crt,
                                                   mock_secret):
        self.driver.clients[
            API_VERSION].delete_listener.__name__ = 'delete_listener'
        sl = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True, client_ca_cert=True, client_crl_cert=True,
            recursive_nest=True, topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        sl2 = sample_configs_combined.sample_listener_tuple(
            id='sample_listener_id_2',
            topology=constants.TOPOLOGY_ACTIVE_STANDBY)
        sl.load_balancer.listeners.append(sl2)
        mock_cert.return_value = {'cn': sample_certs.X509_CERT_CN}
        mock_secret.side_effect = ['filename.pem', 'crl-filename.pem',
                                   'filename.pem', 'crl-filename.pem']
        sconts = []
        for sni_container in self.sl.sni_containers:
            sconts.append(sni_container.tls_container)
        mock_load_crt.side_effect = [{
            'tls_cert': self.sl.default_tls_container, 'sni_certs': sconts},
            {'tls_cert': None, 'sni_certs': []},
            {'tls_cert': None, 'sni_certs': []},
            {'tls_cert': None, 'sni_certs': []}]
        self.driver.jinja_combo.build_config.side_effect = [
            'fake_config', 'fake_config']
        # Execute driver method
        self.driver.delete(sl)

        amp1 = sl.load_balancer.amphorae[0]
        amp2 = sl.load_balancer.amphorae[1]

        # All of the pem files should be removed (using amp1 or amp2)
        dcp_calls_list = [
            [
                mock.call(amp1, sl.load_balancer.id,
                          sl.default_tls_container.id + '.pem'),
                mock.call(amp2, sl.load_balancer.id,
                          sl.default_tls_container.id + '.pem')
            ],
            [
                mock.call(amp1, sl.load_balancer.id, sconts[0].id + '.pem'),
                mock.call(amp2, sl.load_balancer.id, sconts[0].id + '.pem')
            ],
            [
                mock.call(amp1, sl.load_balancer.id, sconts[1].id + '.pem'),
                mock.call(amp2, sl.load_balancer.id, sconts[1].id + '.pem')
            ]
        ]
        mock_calls = (
            self.driver.clients[API_VERSION].delete_cert_pem.mock_calls)
        for dcp_calls in dcp_calls_list:
            # Ensure that at least one call in each pair has been seen
            if (dcp_calls[0] not in mock_calls and
                    dcp_calls[1] not in mock_calls):
                raise Exception(f"{dcp_calls} not found in {mock_calls}")

        # Now just make sure we did an update and not a delete
        self.driver.clients[API_VERSION].delete_listener.assert_not_called()
        upload_config_calls = [
            mock.call(amp1, sl.load_balancer.id, 'fake_config',
                      timeout_dict=None),
            mock.call(amp2, sl.load_balancer.id, 'fake_config',
                      timeout_dict=None)
        ]
        self.driver.clients[API_VERSION].upload_config.assert_has_calls(
            upload_config_calls, any_order=True)

        # start should be called once per amp
        reload_listener_calls = [
            mock.call(amp1, sl.load_balancer.id, timeout_dict=None),
            mock.call(amp2, sl.load_balancer.id, timeout_dict=None)
        ]
        self.driver.clients[
            API_VERSION].reload_listener.assert_has_calls(
                reload_listener_calls, any_order=True)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_delete_last_listener(self, mock_load_crt):
        self.driver.clients[
            API_VERSION].delete_listener.__name__ = 'delete_listener'
        sl = sample_configs_combined.sample_listener_tuple(
            tls=True, sni=True, client_ca_cert=True, client_crl_cert=True,
            recursive_nest=True)
        mock_load_crt.side_effect = [{
            'tls_cert': sl.default_tls_container, 'sni_certs': None}]
        # Execute driver method
        self.driver.delete(sl)
        self.driver.clients[
            API_VERSION].delete_listener.assert_called_once_with(
            self.amp, sl.load_balancer.id)

    def test_udp_delete(self):
        self.driver.clients[
            API_VERSION].delete_listener.__name__ = 'delete_listener'
        # Execute driver method
        self.driver.delete(self.sl_udp)
        self.driver.clients[
            API_VERSION].delete_listener.assert_called_once_with(
            self.amp, self.sl_udp.id)

    def test_get_info(self):
        expected_info = {'haproxy_version': '1.6.3-1ubuntu0.1',
                         'api_version': '1.0'}
        result = self.driver.get_info(self.amp)
        self.assertEqual(expected_info, result)

    def test_get_diagnostics(self):
        # TODO(johnsom) Implement once this exists on the amphora agent.
        result = self.driver.get_diagnostics(self.amp)
        self.assertIsNone(result)

    def test_finalize_amphora(self):
        # TODO(johnsom) Implement once this exists on the amphora agent.
        result = self.driver.finalize_amphora(self.amp)
        self.assertIsNone(result)

    def test_post_vip_plug(self):
        vip_subnet = mock.MagicMock()
        vip_subnet.cidr = FAKE_CIDR
        vip_subnet.gateway_ip = FAKE_GATEWAY
        vip_subnet.host_routes = self.host_routes
        vip_subnet.to_dict.return_value = {
            'cidr': FAKE_CIDR,
            'gateway_ip': FAKE_GATEWAY,
            'host_routes': [
                hr.to_dict(recurse=True)
                for hr in self.host_routes]
        }

        amphorae_network_config = mock.MagicMock()
        amphorae_network_config.get().vip_subnet = vip_subnet
        amphorae_network_config.get().vrrp_port = self.port
        self.driver.post_vip_plug(self.amp, self.lb, amphorae_network_config,
                                  self.port, vip_subnet,
                                  additional_vip_data=[])
        self.driver.clients[API_VERSION].plug_vip.assert_called_once_with(
            self.amp, self.lb.vip.ip_address, self.subnet_info)

    def test_post_vip_plug_additional_vips(self):
        vip_subnet = mock.MagicMock()
        vip_subnet.cidr = FAKE_CIDR
        vip_subnet.gateway_ip = FAKE_GATEWAY
        vip_subnet.host_routes = self.host_routes
        vip_subnet.to_dict.return_value = {
            'cidr': FAKE_CIDR,
            'gateway_ip': FAKE_GATEWAY,
            'host_routes': [
                hr.to_dict(recurse=True)
                for hr in self.host_routes]
        }

        amphorae_network_config = mock.MagicMock()
        amphorae_network_config.get().vip_subnet = vip_subnet
        amphorae_network_config.get().vrrp_port = self.port

        vip1_subnet = mock.MagicMock()
        vip1_subnet.cidr = mock.Mock()
        vip1_subnet.gateway_ip = mock.Mock()
        vip1_subnet.host_routes = self.host_routes
        vip1_subnet.to_dict.return_value = {
            'cidr': vip1_subnet.cidr,
            'gateway_ip': vip1_subnet.gateway_ip,
            'host_routes': [
                hr.to_dict(recurse=True)
                for hr in self.host_routes]
        }
        additional_vip1 = mock.MagicMock()
        additional_vip1.ip_address = mock.Mock()
        additional_vip1.subnet = vip1_subnet
        additional_vip_data = [additional_vip1]
        self.driver.post_vip_plug(
            self.amp, self.lb,
            amphorae_network_config,
            self.port, vip_subnet,
            additional_vip_data=additional_vip_data)
        netinfo = self.subnet_info.copy()
        netinfo['additional_vips'] = [
            {
                'ip_address': additional_vip1.ip_address,
                'subnet_cidr': additional_vip1.subnet.cidr,
                'gateway': additional_vip1.subnet.gateway_ip,
                'host_routes': netinfo['host_routes']
            }
        ]
        netinfo['is_sriov'] = False
        self.driver.clients[API_VERSION].plug_vip.assert_called_once_with(
            self.amp, self.lb.vip.ip_address, netinfo)

    def test_post_network_plug(self):
        # Test dhcp path
        port = network_models.Port(mac_address=FAKE_MAC_ADDRESS,
                                   fixed_ips=[],
                                   network=self.network)
        self.driver.post_network_plug(self.amp, port, self.amp_net_config)
        self.driver.clients[API_VERSION].plug_network.assert_called_once_with(
            self.amp, dict(mac_address=FAKE_MAC_ADDRESS,
                           fixed_ips=[],
                           mtu=FAKE_MTU,
                           is_sriov=False))

        self.driver.clients[API_VERSION].plug_network.reset_mock()

        # Test fixed IP path
        self.driver.post_network_plug(self.amp, self.port, self.amp_net_config)
        self.driver.clients[API_VERSION].plug_network.assert_called_once_with(
            self.amp, dict(mac_address=FAKE_MAC_ADDRESS,
                           fixed_ips=[dict(ip_address='198.51.100.5',
                                           subnet_cidr='198.51.100.0/24',
                                           host_routes=[],
                                           gateway=FAKE_GATEWAY)],
                           mtu=FAKE_MTU, is_sriov=False))

        self.driver.clients[API_VERSION].plug_network.reset_mock()

        # Test member network on vip port
        port = network_models.Port(id=self.amp.vrrp_port_id,
                                   mac_address=FAKE_MAC_ADDRESS,
                                   fixed_ips=[self.fixed_ip],
                                   network=self.network)
        self.driver.post_network_plug(self.amp, port, self.amp_net_config)
        self.driver.clients[API_VERSION].plug_network.assert_called_once_with(
            self.amp, dict(mac_address=FAKE_MAC_ADDRESS,
                           fixed_ips=[dict(ip_address='198.51.100.5',
                                           subnet_cidr='198.51.100.0/24',
                                           host_routes=[],
                                           gateway=FAKE_GATEWAY)],
                           mtu=FAKE_MTU,
                           vip_net_info=dict(
                               vip=self.amp.ha_ip,
                               subnet_cidr=FAKE_VIP_SUBNET,
                               mac_address=FAKE_MAC_ADDRESS,
                               gateway=None,
                               vrrp_ip=self.amp.vrrp_ip,
                               host_routes=[],
                               additional_vips=[],
                               mtu=FAKE_MTU,
                               is_sriov=False
                           ), is_sriov=False))

    def test_post_network_plug_with_host_routes(self):
        SUBNET_ID = 'SUBNET_ID'
        FIXED_IP1 = '192.0.2.2'
        FIXED_IP2 = '192.0.2.3'
        SUBNET_CIDR = '192.0.2.0/24'
        DEST1 = '198.51.100.0/24'
        DEST2 = '203.0.113.0/24'
        NEXTHOP = '192.0.2.1'
        host_routes = [network_models.HostRoute(destination=DEST1,
                                                nexthop=NEXTHOP),
                       network_models.HostRoute(destination=DEST2,
                                                nexthop=NEXTHOP)]
        subnet = network_models.Subnet(id=SUBNET_ID, cidr=SUBNET_CIDR,
                                       gateway_ip=FAKE_GATEWAY,
                                       ip_version=4, host_routes=host_routes)
        fixed_ips = [
            network_models.FixedIP(subnet_id=subnet.id, ip_address=FIXED_IP1,
                                   subnet=subnet),
            network_models.FixedIP(subnet_id=subnet.id, ip_address=FIXED_IP2,
                                   subnet=subnet)
        ]
        port = network_models.Port(mac_address=FAKE_MAC_ADDRESS,
                                   fixed_ips=fixed_ips,
                                   network=self.network)
        self.driver.post_network_plug(self.amp, port, self.amp_net_config)
        expected_fixed_ips = [
            {'ip_address': FIXED_IP1, 'subnet_cidr': SUBNET_CIDR,
             'gateway': FAKE_GATEWAY,
             'host_routes': [{'destination': DEST1, 'nexthop': NEXTHOP},
                             {'destination': DEST2, 'nexthop': NEXTHOP}]},
            {'ip_address': FIXED_IP2, 'subnet_cidr': SUBNET_CIDR,
             'gateway': FAKE_GATEWAY,
             'host_routes': [{'destination': DEST1, 'nexthop': NEXTHOP},
                             {'destination': DEST2, 'nexthop': NEXTHOP}]}
        ]
        self.driver.clients[API_VERSION].plug_network.assert_called_once_with(
            self.amp, dict(mac_address=FAKE_MAC_ADDRESS,
                           fixed_ips=expected_fixed_ips,
                           mtu=FAKE_MTU,
                           is_sriov=False))

    def test_get_haproxy_versions(self):
        ref_haproxy_versions = ['1', '6']
        result = self.driver._get_haproxy_versions(self.amp)
        self.driver.clients[API_VERSION].get_info.assert_called_once_with(
            self.amp, timeout_dict=None)
        self.assertEqual(ref_haproxy_versions, result)

    def test_get_haproxy_versions_with_timeout_dict(self):
        ref_haproxy_versions = ['1', '6']
        timeout_dict = {
            constants.CONN_MAX_RETRIES: 100,
            constants.CONN_RETRY_INTERVAL: 1
        }
        result = self.driver._get_haproxy_versions(self.amp,
                                                   timeout_dict=timeout_dict)
        self.driver.clients[API_VERSION].get_info.assert_called_once_with(
            self.amp, timeout_dict=timeout_dict)
        self.assertEqual(ref_haproxy_versions, result)

    def test_populate_amphora_api_version(self):

        # Normal path, populate the version
        # clear out any previous values
        ref_haproxy_version = list(map(int, API_VERSION.split('.')))
        mock_amp = mock.MagicMock()
        mock_amp.api_version = None
        result = self.driver._populate_amphora_api_version(mock_amp)
        self.assertEqual(API_VERSION, mock_amp.api_version)
        self.assertEqual(ref_haproxy_version, result)

        # Existing version passed in
        fake_version = '9999.9999'
        ref_haproxy_version = list(map(int, fake_version.split('.')))
        mock_amp = mock.MagicMock()
        mock_amp.api_version = fake_version
        result = self.driver._populate_amphora_api_version(mock_amp)
        self.assertEqual(fake_version, mock_amp.api_version)
        self.assertEqual(ref_haproxy_version, result)

    def test_update_amphora_agent_config(self):
        self.driver.update_amphora_agent_config(
            self.amp, octavia_utils.b('test'))
        self.driver.clients[
            API_VERSION].update_agent_config.assert_called_once_with(
            self.amp, octavia_utils.b('test'), timeout_dict=None)


class TestAmphoraAPIClientTest(base.TestCase):

    def setUp(self):
        super().setUp()
        self.driver = driver.AmphoraAPIClient1_0()
        self.base_url = "https://192.0.2.77:9443/"
        self.base_url_ver = self.base_url + "1.0"
        self.amp = models.Amphora(lb_network_ip='192.0.2.77', compute_id='123')
        self.amp.api_version = API_VERSION
        self.port_info = dict(mac_address=FAKE_MAC_ADDRESS)
        # Override with much lower values for testing purposes..
        conf = oslo_fixture.Config(cfg.CONF)
        conf.config(group="haproxy_amphora", connection_max_retries=2)

        self.subnet_info = {'subnet_cidr': FAKE_CIDR,
                            'gateway': FAKE_GATEWAY,
                            'mac_address': FAKE_MAC_ADDRESS,
                            'vrrp_ip': self.amp.vrrp_ip}
        patcher = mock.patch('time.sleep').start()
        self.addCleanup(patcher.stop)
        self.timeout_dict = {constants.REQ_CONN_TIMEOUT: 1,
                             constants.REQ_READ_TIMEOUT: 2,
                             constants.CONN_MAX_RETRIES: 3,
                             constants.CONN_RETRY_INTERVAL: 4}

    def test_base_url(self):
        url = self.driver._base_url(FAKE_IP)
        self.assertEqual('https://192.0.2.10:9443/', url)
        url = self.driver._base_url(FAKE_IPV6, self.amp.api_version)
        self.assertEqual('https://[2001:db8::cafe]:9443/1.0/', url)
        url = self.driver._base_url(FAKE_IPV6_LLA, self.amp.api_version)
        self.assertEqual('https://[fe80::00ff:fe00:cafe%o-hm0]:9443/1.0/', url)

    @mock.patch('requests.Session.get', side_effect=requests.ConnectionError)
    @mock.patch('octavia.amphorae.drivers.haproxy.rest_api_driver.time.sleep')
    def test_request(self, mock_sleep, mock_get):
        self.assertRaises(driver_except.TimeOutException,
                          self.driver.request, 'get', self.amp,
                          'unavailableURL', self.timeout_dict)

    @requests_mock.mock()
    def test_get_api_version(self, mock_requests):
        ref_api_version = {'api_version': '0.1'}
        mock_requests.get(f'{self.base_url}/',
                          json=ref_api_version)
        result = self.driver.get_api_version(self.amp)
        self.assertEqual(ref_api_version, result)

    @requests_mock.mock()
    def test_get_info(self, m):
        info = {"hostname": "some_hostname", "version": "some_version",
                "api_version": "1.0", "uuid": FAKE_UUID_1}
        m.get(f"{self.base_url_ver}/info",
              json=info)
        information = self.driver.get_info(self.amp)
        self.assertEqual(info, information)

    @requests_mock.mock()
    def test_get_info_with_timeout_dict(self, m):
        info = {"hostname": "some_hostname", "version": "some_version",
                "api_version": "1.0", "uuid": FAKE_UUID_1}
        m.get(f"{self.base_url_ver}/info",
              json=info)
        timeout_dict = {
            constants.CONN_MAX_RETRIES: 100,
            constants.CONN_RETRY_INTERVAL: 1
        }
        information = self.driver.get_info(self.amp, timeout_dict=timeout_dict)
        self.assertEqual(info, information)

    @requests_mock.mock()
    def test_get_info_unauthorized(self, m):
        m.get(f"{self.base_url_ver}/info",
              status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.get_info, self.amp)

    @requests_mock.mock()
    def test_get_info_missing(self, m):
        m.get(f"{self.base_url_ver}/info",
              status_code=404,
              headers={'content-type': 'application/json'})
        self.assertRaises(exc.NotFound, self.driver.get_info, self.amp)

    @requests_mock.mock()
    def test_get_info_server_error(self, m):
        m.get(f"{self.base_url_ver}/info",
              status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.get_info,
                          self.amp)

    @requests_mock.mock()
    def test_get_info_service_unavailable(self, m):
        m.get(f"{self.base_url_ver}/info",
              status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.get_info,
                          self.amp)

    @requests_mock.mock()
    def test_get_details(self, m):
        details = {"hostname": "some_hostname", "version": "some_version",
                   "api_version": "1.0", "uuid": FAKE_UUID_1,
                   "network_tx": "some_tx", "network_rx": "some_rx",
                   "active": True, "haproxy_count": 10}
        m.get(f"{self.base_url_ver}/details",
              json=details)
        amp_details = self.driver.get_details(self.amp)
        self.assertEqual(details, amp_details)

    @requests_mock.mock()
    def test_get_details_unauthorized(self, m):
        m.get(f"{self.base_url_ver}/details",
              status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.get_details, self.amp)

    @requests_mock.mock()
    def test_get_details_missing(self, m):
        m.get(f"{self.base_url_ver}/details",
              status_code=404,
              headers={'content-type': 'application/json'})
        self.assertRaises(exc.NotFound, self.driver.get_details, self.amp)

    @requests_mock.mock()
    def test_get_details_server_error(self, m):
        m.get(f"{self.base_url_ver}/details",
              status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.get_details,
                          self.amp)

    @requests_mock.mock()
    def test_get_details_service_unavailable(self, m):
        m.get(f"{self.base_url_ver}/details",
              status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.get_details,
                          self.amp)

    @requests_mock.mock()
    def test_get_all_listeners(self, m):
        listeners = [{"status": "ONLINE", "provisioning_status": "ACTIVE",
                      "type": "PASSIVE", "uuid": FAKE_UUID_1}]
        m.get(f"{self.base_url_ver}/listeners",
              json=listeners)
        all_listeners = self.driver.get_all_listeners(self.amp)
        self.assertEqual(listeners, all_listeners)

    @requests_mock.mock()
    def test_get_all_listeners_unauthorized(self, m):
        m.get(f"{self.base_url_ver}/listeners",
              status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.get_all_listeners,
                          self.amp)

    @requests_mock.mock()
    def test_get_all_listeners_missing(self, m):
        m.get(f"{self.base_url_ver}/listeners",
              status_code=404,
              headers={'content-type': 'application/json'})
        self.assertRaises(exc.NotFound, self.driver.get_all_listeners,
                          self.amp)

    @requests_mock.mock()
    def test_get_all_listeners_server_error(self, m):
        m.get(f"{self.base_url_ver}/listeners",
              status_code=500)
        self.assertRaises(exc.InternalServerError,
                          self.driver.get_all_listeners, self.amp)

    @requests_mock.mock()
    def test_get_all_listeners_service_unavailable(self, m):
        m.get(f"{self.base_url_ver}/listeners",
              status_code=503)
        self.assertRaises(exc.ServiceUnavailable,
                          self.driver.get_all_listeners, self.amp)

    @requests_mock.mock()
    def test_start_loadbalancer(self, m):
        m.put(f"{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/start")
        self.driver.start_listener(self.amp, FAKE_UUID_1)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_start_loadbalancer_missing(self, m):
        m.put(f"{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/start",
              status_code=404,
              headers={'content-type': 'application/json'})
        self.assertRaises(exc.NotFound, self.driver.start_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_start_loadbalancer_unauthorized(self, m):
        m.put(f"{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/start",
              status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.start_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_start_loadbalancer_server_error(self, m):
        m.put(f"{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/start",
              status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.start_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_start_loadbalancer_service_unavailable(self, m):
        m.put(f"{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/start",
              status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.start_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_delete_listener(self, m):
        m.delete(f"{self.base_url_ver}/listeners/{FAKE_UUID_1}", json={})
        self.driver.delete_listener(self.amp, FAKE_UUID_1)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_delete_listener_missing(self, m):
        m.delete(f"{self.base_url_ver}/listeners/{FAKE_UUID_1}",
                 status_code=404,
                 headers={'content-type': 'application/json'})
        self.driver.delete_listener(self.amp, FAKE_UUID_1)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_delete_listener_unauthorized(self, m):
        m.delete(f"{self.base_url_ver}/listeners/{FAKE_UUID_1}",
                 status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.delete_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_delete_listener_server_error(self, m):
        m.delete(f"{self.base_url_ver}/listeners/{FAKE_UUID_1}",
                 status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.delete_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_delete_listener_service_unavailable(self, m):
        m.delete(f"{self.base_url_ver}/listeners/{FAKE_UUID_1}",
                 status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.delete_listener,
                          self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_upload_cert_pem(self, m):
        m.put("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME))
        self.driver.upload_cert_pem(self.amp, FAKE_UUID_1,
                                    FAKE_PEM_FILENAME,
                                    "some_file")
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_upload_invalid_cert_pem(self, m):
        m.put("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=400)
        self.assertRaises(exc.InvalidRequest, self.driver.upload_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME,
                          "some_file")

    @requests_mock.mock()
    def test_upload_cert_pem_unauthorized(self, m):
        m.put("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.upload_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME,
                          "some_file")

    @requests_mock.mock()
    def test_upload_cert_pem_server_error(self, m):
        m.put("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.upload_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME,
                          "some_file")

    @requests_mock.mock()
    def test_upload_cert_pem_service_unavailable(self, m):
        m.put("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.upload_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME,
                          "some_file")

    @requests_mock.mock()
    def test_update_cert_for_rotation(self, m):
        m.put(f"{self.base_url_ver}/certificate")
        resp_body = self.driver.update_cert_for_rotation(self.amp,
                                                         "some_file")
        self.assertEqual(200, resp_body.status_code)

    @requests_mock.mock()
    def test_update_invalid_cert_for_rotation(self, m):
        m.put(f"{self.base_url_ver}/certificate",
              status_code=400)
        self.assertRaises(exc.InvalidRequest,
                          self.driver.update_cert_for_rotation, self.amp,
                          "some_file")

    @requests_mock.mock()
    def test_update_cert_for_rotation_unauthorized(self, m):
        m.put(f"{self.base_url_ver}/certificate",
              status_code=401)
        self.assertRaises(exc.Unauthorized,
                          self.driver.update_cert_for_rotation, self.amp,
                          "some_file")

    @requests_mock.mock()
    def test_update_cert_for_rotation_error(self, m):
        m.put(f"{self.base_url_ver}/certificate",
              status_code=500)
        self.assertRaises(exc.InternalServerError,
                          self.driver.update_cert_for_rotation, self.amp,
                          "some_file")

    @requests_mock.mock()
    def test_update_cert_for_rotation_unavailable(self, m):
        m.put(f"{self.base_url_ver}/certificate",
              status_code=503)
        self.assertRaises(exc.ServiceUnavailable,
                          self.driver.update_cert_for_rotation, self.amp,
                          "some_file")

    @requests_mock.mock()
    def test_get_cert_5sum(self, m):
        md5sum = {"md5sum": "some_real_sum"}
        m.get("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), json=md5sum)
        sum_test = self.driver.get_cert_md5sum(self.amp, FAKE_UUID_1,
                                               FAKE_PEM_FILENAME)
        self.assertIsNotNone(sum_test)

    @requests_mock.mock()
    def test_get_cert_5sum_missing(self, m):
        m.get("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=404,
              headers={'content-type': 'application/json'})
        self.assertRaises(exc.NotFound, self.driver.get_cert_md5sum,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_get_cert_5sum_unauthorized(self, m):
        m.get("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.get_cert_md5sum,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_get_cert_5sum_server_error(self, m):
        m.get("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.get_cert_md5sum,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_get_cert_5sum_service_unavailable(self, m):
        m.get("{base}/loadbalancer/{loadbalancer_id}/certificates/"
              "{filename}".format(
                  base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                  filename=FAKE_PEM_FILENAME), status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.get_cert_md5sum,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_delete_cert_pem(self, m):
        m.delete(
            "{base}/loadbalancer/{loadbalancer_id}/certificates/"
            "{filename}".format(
                base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                filename=FAKE_PEM_FILENAME))
        self.driver.delete_cert_pem(self.amp, FAKE_UUID_1,
                                    FAKE_PEM_FILENAME)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_delete_cert_pem_missing(self, m):
        m.delete(
            "{base}/loadbalancer/{loadbalancer_id}/certificates/"
            "{filename}".format(
                base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                filename=FAKE_PEM_FILENAME), status_code=404,
            headers={'content-type': 'application/json'})
        self.driver.delete_cert_pem(self.amp, FAKE_UUID_1,
                                    FAKE_PEM_FILENAME)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_delete_cert_pem_unauthorized(self, m):
        m.delete(
            "{base}/loadbalancer/{loadbalancer_id}/certificates/"
            "{filename}".format(
                base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                filename=FAKE_PEM_FILENAME), status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.delete_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_delete_cert_pem_server_error(self, m):
        m.delete(
            "{base}/loadbalancer/{loadbalancer_id}/certificates/"
            "{filename}".format(
                base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                filename=FAKE_PEM_FILENAME), status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.delete_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_delete_cert_pem_service_unavailable(self, m):
        m.delete(
            "{base}/loadbalancer/{loadbalancer_id}/certificates/"
            "{filename}".format(
                base=self.base_url_ver, loadbalancer_id=FAKE_UUID_1,
                filename=FAKE_PEM_FILENAME), status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.delete_cert_pem,
                          self.amp, FAKE_UUID_1, FAKE_PEM_FILENAME)

    @requests_mock.mock()
    def test_upload_config(self, m):
        config = {"name": "fake_config"}
        m.put(
            f"{self.base_url_ver}/loadbalancer/{self.amp.id}/"
            f"{FAKE_UUID_1}/haproxy",
            json=config)
        self.driver.upload_config(self.amp, FAKE_UUID_1,
                                  config)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_upload_invalid_config(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/loadbalancer/{self.amp.id}/"
            f"{FAKE_UUID_1}/haproxy",
            status_code=400)
        self.assertRaises(exc.InvalidRequest, self.driver.upload_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_config_unauthorized(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/loadbalancer/{self.amp.id}/"
            f"{FAKE_UUID_1}/haproxy",
            status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.upload_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_config_server_error(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/loadbalancer/{self.amp.id}/"
            f"{FAKE_UUID_1}/haproxy",
            status_code=500)
        self.assertRaises(exc.InternalServerError, self.driver.upload_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_config_service_unavailable(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/loadbalancer/{self.amp.id}/"
            f"{FAKE_UUID_1}/haproxy",
            status_code=503)
        self.assertRaises(exc.ServiceUnavailable, self.driver.upload_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_udp_activation_requires_guard_acknowledgement(self, router):
        reload_url = f'{self.base_url_ver}/loadbalancer/{FAKE_UUID_1}/reload'
        router.put(reload_url, [
            {'status_code': 202},
            {'status_code': 202, 'headers': {'X-Octavia-UDP-Guard': '1'}},
        ])
        self.assertRaises(driver_except.ListenerProvisioningError,
                          self.driver.activate_udp_guard,
                          self.amp, FAKE_UUID_1)
        self.driver.activate_udp_guard(self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_guarded_udp_delete_requires_kernel_receipt(self, router):
        delete_url = f'{self.base_url_ver}/listeners/{FAKE_UUID_1}'
        router.delete(delete_url, [
            {'status_code': 404},
            {'status_code': 200},
            {'status_code': 200, 'headers': {'X-Octavia-UDP-Guard': '1'}},
        ])
        self.assertRaises(exc.NotFound,
                          self.driver.delete_guarded_udp_listener,
                          self.amp, FAKE_UUID_1)
        self.assertRaises(driver_except.ListenerProvisioningError,
                          self.driver.delete_guarded_udp_listener,
                          self.amp, FAKE_UUID_1)
        self.driver.delete_guarded_udp_listener(self.amp, FAKE_UUID_1)

    @requests_mock.mock()
    def test_legacy_udp_close_reobserves_only_the_target(self, router):
        listener_id = 'udp-target'
        neighbor = {'uuid': 'udp-neighbor', 'type': 'UDP', 'status': 'ACTIVE'}
        target = {'uuid': listener_id, 'type': 'UDP', 'status': 'ACTIVE'}
        observed = [
            {'json': [target, neighbor]},
            {'json': [{**target, 'status': 'OFFLINE'}, neighbor]},
            {'json': [neighbor]},
        ]
        router.get(f'{self.base_url_ver}/listeners', observed)
        router.put(f'{self.base_url_ver}/loadbalancer/{listener_id}/stop',
                   status_code=202)
        router.delete(f'{self.base_url_ver}/listeners/{listener_id}',
                      status_code=200)
        self.driver.close_legacy_udp_listener(self.amp, listener_id)
        self.assertEqual([
            ('GET', '/1.0/listeners'),
            ('PUT', f'/1.0/loadbalancer/{listener_id}/stop'),
            ('GET', '/1.0/listeners'),
            ('DELETE', f'/1.0/listeners/{listener_id}'),
            ('GET', '/1.0/listeners'),
        ], [(request.method, request.path)
            for request in router.request_history])

    @requests_mock.mock()
    def test_upload_udp_config(self, m):
        config = {"name": "fake_config"}
        m.put(
            f"{self.base_url_ver}/listeners/{self.amp.id}/"
            f"{FAKE_UUID_1}/udp_listener",
            json=config)
        self.driver.upload_udp_config(self.amp, FAKE_UUID_1, config)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_upload_udp_invalid_config(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/listeners/{self.amp.id}/"
            f"{FAKE_UUID_1}/udp_listener",
            status_code=400)
        self.assertRaises(exc.InvalidRequest, self.driver.upload_udp_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_udp_config_unauthorized(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/listeners/{self.amp.id}/"
            f"{FAKE_UUID_1}/udp_listener",
            status_code=401)
        self.assertRaises(exc.Unauthorized, self.driver.upload_udp_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_udp_config_server_error(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/listeners/{self.amp.id}/"
            f"{FAKE_UUID_1}/udp_listener",
            status_code=500)
        self.assertRaises(exc.InternalServerError,
                          self.driver.upload_udp_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_upload_udp_config_service_unavailable(self, m):
        config = '{"name": "bad_config"}'
        m.put(
            f"{self.base_url_ver}/listeners/{self.amp.id}/"
            f"{FAKE_UUID_1}/udp_listener",
            status_code=503)
        self.assertRaises(exc.ServiceUnavailable,
                          self.driver.upload_udp_config,
                          self.amp, FAKE_UUID_1, config)

    @requests_mock.mock()
    def test_plug_vip(self, m):
        m.post(f"{self.base_url_ver}/plug/vip/{FAKE_IP}")
        self.driver.plug_vip(self.amp, FAKE_IP, self.subnet_info)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_plug_vip_api_not_ready(self, m):
        m.post(f"{self.base_url_ver}/plug/vip/{FAKE_IP}",
               status_code=404, headers={'content-type': 'text/html'})
        self.assertRaises(driver_except.TimeOutException,
                          self.driver.plug_vip,
                          self.amp, FAKE_IP, self.subnet_info)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_plug_network(self, m):
        m.post(f"{self.base_url_ver}/plug/network")
        self.driver.plug_network(self.amp, self.port_info)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_upload_vrrp_config(self, m):
        config = '{"name": "bad_config"}'
        m.put(f"{self.base_url_ver}/vrrp/upload")
        self.driver.upload_vrrp_config(self.amp, config)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_vrrp_action(self, m):
        action = 'start'
        m.put(f"{self.base_url_ver}/vrrp/{action}")
        self.driver._vrrp_action(action, self.amp)
        self.assertTrue(m.called)

    @requests_mock.mock()
    def test_get_interface(self, m):
        interface = [{"interface": "eth1"}]
        ip_addr = '192.51.100.1'
        m.get(f"{self.base_url_ver}/interface/{ip_addr}",
              json=interface)
        self.driver.get_interface(self.amp, ip_addr)
        self.assertTrue(m.called)

        m.register_uri('GET',
                       self.base_url_ver + '/interface/' + ip_addr,
                       status_code=500, reason='FAIL', json='FAIL')
        self.assertRaises(exc.InternalServerError,
                          self.driver.get_interface,
                          self.amp, ip_addr)

    @requests_mock.mock()
    def test_update_agent_config(self, m):
        m.put(f"{self.base_url_ver}/config")
        resp_body = self.driver.update_agent_config(self.amp, "some_file")
        self.assertEqual(200, resp_body.status_code)

    @requests_mock.mock()
    def test_update_agent_config_error(self, m):
        m.put(f"{self.base_url_ver}/config", status_code=500)
        self.assertRaises(exc.InternalServerError,
                          self.driver.update_agent_config, self.amp,
                          "some_file")

    @requests_mock.mock()
    def test_set_interface_rules(self, m):
        ip_addr = '192.0.2.44'
        rules = ('[{"protocol":"TCP","cidr":"192.0.2.0/24","port":8080},'
                 '{"protocol":"UDP","cidr":null,"port":80}]')
        m.put(f'{self.base_url_ver}/interface/{ip_addr}/rules')

        self.driver.set_interface_rules(self.amp, ip_addr, rules)
        self.assertTrue(m.called)
