#    Copyright 2016 Blue Box, an IBM Company
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

import contextlib
from unittest import mock

import fixtures
from octavia_lib.api.drivers import exceptions as lib_exceptions
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_policy import policy as oslo_policy
from oslo_utils import uuidutils

from octavia.amphorae.drivers.haproxy import rest_api_driver
from octavia.amphorae.drivers.noop_driver import driver as amphora_noop
from octavia.api.drivers.noop_driver import driver as noop_driver
from octavia.api.drivers import utils as driver_utils
from octavia.common import constants
import octavia.common.context
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import policy
from octavia.controller.queue.v2 import endpoints
from octavia.controller.worker.v2.tasks import amphora_driver_tasks
from octavia.controller.worker.v2.tasks import database_tasks
from octavia.controller.worker.v2.tasks import lifecycle_tasks
from octavia.db import api as db_api
from octavia.db import models
from octavia.db import repositories
from octavia.tests.common import constants as c_const
from octavia.tests.common import sample_certs
from octavia.tests.functional.api.v2 import base


class TestInitialL7Rules(base.BaseAPITest):

    def setUp(self):
        super().setUp()
        self.rpc = self.useFixture(fixtures.MockPatch(
            'octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client'
        )).mock.return_value
        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_noop_driver')
        self.conf.config(group='task_flow', jobboard_enabled=False)
        self.conf.config(group='api_settings',
                         enabled_l7policy_initial_rules_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.lb_id = lb['id']
        self.project_id = lb['project_id']
        self.set_lb_status(self.lb_id)
        listener = self.create_listener('HTTP', 80, lb_id=self.lb_id)
        self.listener_id = listener['listener']['id']
        self.set_lb_status(self.lb_id)
        self.rules = [
            {'type': 'HOST_NAME', 'compare_type': 'EQUAL_TO',
             'value': 'example.test', 'invert': False},
            {'type': 'PATH', 'compare_type': 'EQUAL_TO',
             'value': '/excluded', 'invert': True},
        ]
        self.rpc.cast.reset_mock()

    def _post_policy(self, status=201, **overrides):
        body = {
            'listener_id': self.listener_id,
            'action': 'REDIRECT_PREFIX',
            'redirect_prefix': 'https://destination.test',
            'admin_state_up': False,
            'rules': self.rules,
        }
        body.update(overrides)
        return self.post(self.L7POLICIES_PATH, {'l7policy': body},
                         status=status).json

    def _prepare_activation_group(self, **destination):
        self.conf.config(group='api_settings',
                         enabled_l7policy_batch_activation_providers=[
                             'amphora'])
        for suffix in ('first', 'second', 'unselected'):
            policy = dict(redirect_prefix=f'https://{suffix}.test',
                          tags=[f'owned-{suffix}'])
            policy.update(destination)
            self._post_policy(**policy)
            endpoints.Endpoints().create_l7policy({}, **self.rpc.cast.call_args
                                                  .kwargs)
        self.rpc.cast.reset_mock()
        path = (self.LISTENER_PATH.format(listener_id=self.listener_id) +
                '/l7policy_activation')
        return path, self._activation_request(path)

    def _activation_request(self, path):
        graph = self.get(path).json['l7policy_activation']
        entries = graph['policies']
        order = [item['policy']['id'] for item in entries]
        refs = [{'id': item['policy']['id'], 'revision': item['revision']}
                for item in entries[:2]]
        return {'l7policy_activation': {
            'expected_graph_revision': graph['graph_revision'],
            'expected_order': order, 'policies': refs}}

    def _activation_policies(self, path):
        return [item['policy'] for item in self.get(path).json[
            'l7policy_activation']['policies']]

    def test_batch_activation_disabled(self):
        path = (self.LISTENER_PATH.format(listener_id=self.listener_id) +
                '/l7policy_activation')
        capability_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        capabilities = self.get(capability_path).json['gateway_capabilities']
        self.assertNotIn(
            constants.GATEWAY_CAPABILITY_L7POLICY_BATCH_ACTIVATION,
            capabilities)
        self.get(path, status=501)
        missing = [uuidutils.generate_uuid(), uuidutils.generate_uuid()]
        body = {'expected_graph_revision': '1' * 64,
                'expected_order': missing,
                'policies': [{'id': id, 'revision': '1' * 64}
                             for id in missing]}
        self.post(path, {'l7policy_activation': body}, status=501)
        body['policies'].pop()
        self.post(path, {'l7policy_activation': body}, status=400)
        self.rpc.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_l7policy_batch_activation_providers=[
                             'noop_driver'])
        capabilities = self.get(self.PROVIDERS_PATH +
                                '/noop_driver/gateway_capabilities').json
        self.assertNotIn(
            constants.GATEWAY_CAPABILITY_L7POLICY_BATCH_ACTIVATION,
            capabilities['gateway_capabilities'])

    def test_passthrough_weighted_tls_sni_activation_and_withdrawal(self):
        enabled_providers = ['amphora']
        setting = 'enabled_tls_sni_passthrough_weighted_pool_providers'
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=enabled_providers,
            enabled_tls_sni_weighted_pool_providers=enabled_providers,
            enabled_tls_sni_providers=enabled_providers,
            enabled_tls_sni_suffix_providers=enabled_providers,
            enabled_l7policy_batch_activation_providers=enabled_providers)
        listener = self.create_listener(
            'TCP', 443, self.lb_id)['listener']
        self.set_lb_status(self.lb_id)
        origin = self.create_pool(
            self.lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        closed = self.create_pool(
            self.lb_id, 'TCP', 'ROUND_ROBIN', admin_state_up=False)['pool']
        self.set_lb_status(self.lb_id)
        http = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        targets = [{'pool_id': origin['id'], 'weight': 257},
                   {'pool_id': closed['id'], 'weight': 128}]
        rule = {'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                'value': 'a.example.test'}
        args = {'listener_id': listener['id'], 'action': 'WEIGHTED_TARGETS',
                'rules': [rule], 'targets': targets, 'admin_state_up': False}
        capability = (
            constants.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        capability_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        self.assertNotIn(capability, self.get(capability_path).json[
            'gateway_capabilities'])
        self.post(self.L7POLICIES_PATH, {'l7policy': args}, status=501)
        self.conf.config(group='api_settings', **{setting: enabled_providers})
        self.assertIn(capability, self.get(capability_path).json[
            'gateway_capabilities'])
        for bad in ([{'pool_id': http['id'], 'weight': 257}],
                    [{'fixed_response': {'status_code': 503}, 'weight': 1}]):
            self.post(self.L7POLICIES_PATH,
                      {'l7policy': dict(args, targets=bad)}, status=400)
        self.post(self.L7POLICIES_PATH, {'l7policy': dict(
            args, tcp_tls_passthrough=True)}, status=400)

        with self.session.begin():
            self.create_amphora(uuidutils.generate_uuid(), self.lb_id,
                                role=constants.ROLE_STANDALONE,
                                lb_network_ip='192.0.2.100')
        for rules in ([rule], [dict(rule, compare_type='ENDS_WITH',
                                    value='*.example.test')]):
            policy = self.post(self.L7POLICIES_PATH, {'l7policy': dict(
                args, rules=rules)}).json['l7policy']
            self.assertEqual(targets, policy['targets'])
            endpoints.Endpoints().create_l7policy({}, **self.rpc.cast
                                                  .call_args.kwargs)
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        path = listener_path + '/l7policy_activation'
        self.post(path, self._activation_request(path), status=204)
        endpoints.Endpoints().activate_l7policies(
            {}, **self.rpc.cast.call_args.kwargs)
        policies = self._activation_policies(path)
        self.assertTrue(all(policy['admin_state_up'] for policy in policies))
        self.assertTrue(all(policy['targets'] == targets for policy in
                            policies))
        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=[])
        pool_path = self.POOL_PATH.format(pool_id=closed['id'])
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.create_member(origin['id'], '192.0.2.200', 8443, status=501)
        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=enabled_providers)

        policy_path = self.L7POLICY_PATH.format(l7policy_id=policies[0]['id'])
        updated_targets = [targets[0], dict(targets[1], weight=1000000)]
        self.put(policy_path, {'l7policy': {'targets': updated_targets}})
        self.set_lb_status(self.lb_id)

        self.conf.config(group='api_settings', **{setting: []})
        self.assertNotIn(capability, self.get(capability_path).json[
            'gateway_capabilities'])
        retained = self.get(policy_path).json['l7policy']
        self.assertTrue(retained['admin_state_up'])
        self.assertEqual(updated_targets, retained['targets'])
        self.put(policy_path, {'l7policy': {'targets': targets}}, status=501)
        pool_path = self.POOL_PATH.format(pool_id=closed['id'])
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}},
                 status=501)
        self.delete(policy_path)
        self.set_lb_status(self.lb_id)

        self.conf.config(group='api_settings', **{setting: enabled_providers})
        self.put(listener_path, {'listener': {'admin_state_up': True}})

    def test_weighted_tls_sni_batch_activation_recovers_after_opt_out(self):
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_tls_sni_weighted_pool_providers=['amphora'],
            enabled_tls_sni_providers=['amphora'],
            enabled_tls_sni_passthrough_weighted_pool_providers=['amphora'])
        listener = self.create_listener('TCP', 8443, self.lb_id)['listener']
        self.listener_id = listener['id']
        self.set_lb_status(self.lb_id)
        pool = self.create_pool(self.lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        path, payload = self._prepare_activation_group(
            action='WEIGHTED_TARGETS', redirect_prefix=None,
            rules=[{'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                    'value': 'example.test'}],
            targets=[{'pool_id': pool['id'], 'weight': 257}])

        self.post(path, payload, status=204)
        request = self.rpc.cast.call_args
        self.conf.config(
            group='api_settings',
            enabled_tls_sni_passthrough_weighted_pool_providers=[])
        self.assertTrue(all(not policy['admin_state_up']
                            for policy in self._activation_policies(path)))
        self.post(path, payload, status=204)
        self.assertEqual(request, self.rpc.cast.call_args)
        endpoints.Endpoints().activate_l7policies({}, **request.kwargs)

        policies = self._activation_policies(path)
        self.assertTrue(all(not policy['admin_state_up'] for policy in
                            policies))
        self.assertEqual(['ERROR', 'ERROR', 'ACTIVE'],
                         [policy['provisioning_status'] for policy in
                          policies])
        self.post(path, self._activation_request(path), status=501)
        self.delete(self.L7POLICY_PATH.format(l7policy_id=policies[0]['id']))

    def test_batch_activation_render_and_replay(self):
        with self.session.begin():
            self.create_amphora(uuidutils.generate_uuid(), self.lb_id,
                                role=constants.ROLE_STANDALONE,
                                lb_network_ip='192.0.2.100')
        path, payload = self._prepare_activation_group()
        capability_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        self.assertIn(constants.GATEWAY_CAPABILITY_L7POLICY_BATCH_ACTIVATION,
                      self.get(capability_path).json['gateway_capabilities'])
        self.post(path, payload, status=204)
        self.rpc.cast.assert_called_once()
        call = self.rpc.cast.call_args
        self.assertEqual('activate_l7policies', call.args[1])
        self.assertEqual(['PENDING_UPDATE', 'PENDING_UPDATE', 'ACTIVE'],
                         [p['provisioning_status'] for p in
                          self._activation_policies(path)])
        self.post(path, payload, status=204)
        self.assertEqual(call, self.rpc.cast.call_args)
        rule_id = self._activation_policies(path)[0]['rules'][0]['id']
        policy_id = payload['l7policy_activation']['expected_order'][0]
        self.put(self.L7RULE_PATH.format(l7policy_id=policy_id,
                                         l7rule_id=rule_id),
                 {'rule': {'admin_state_up': False}}, status=409)

        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_haproxy_rest_driver')
        client = rest_api_driver.AmphoraAPIClient1_0
        with (mock.patch.object(rest_api_driver.AmphoraAPIClientBase,
                                'get_api_version',
                                return_value={'api_version': '1.0'}),
              mock.patch.object(client, 'get_info', return_value={
                  'haproxy_version': '3.0.19'}),
              mock.patch.object(client, 'get_details', return_value={}),
              mock.patch.object(client, 'upload_config') as upload,
              mock.patch.object(client, '_action') as action):
            endpoints.Endpoints().activate_l7policies({}, **call.kwargs)
            endpoints.Endpoints().activate_l7policies({}, **call.kwargs)
        upload.assert_called_once()
        action.assert_called_once()
        self.assertEqual(('reload', self.lb_id),
                         (action.call_args.args[0], action.call_args.args[2]))
        config = upload.call_args.args[2]
        self.assertIn('https://first.test', config)
        self.assertIn('https://second.test', config)
        self.assertNotIn('https://unselected.test', config)
        self.assertLess(config.index('https://first.test'),
                        config.index('https://second.test'))
        self.post(path, payload, status=204)
        self.assertEqual(2, self.rpc.cast.call_count)
        policies = self._activation_policies(path)
        self.assertEqual([True, True, False],
                         [policy['admin_state_up'] for policy in policies])
        self.assertEqual([constants.ACTIVE] * 3,
                         [p['provisioning_status'] for p in policies])
        self.assertEqual(payload['l7policy_activation']['expected_order'],
                         [policy['id'] for policy in policies])
        with self.session.begin():
            lb = self.lb_repo.get_for_update(self.session, self.lb_id)
            self.assertEqual('applied', lb.l7policy_activation['phase'])
            dto = driver_utils.db_loadbalancer_to_provider_loadbalancer(lb)
            self.assertEqual(self.lb_id, dto.loadbalancer_id)
            self.assertNotIn('l7policy_activation', lb.to_dict())
        partial = driver_utils.lb_dict_to_provider_dict({
            'id': self.lb_id, 'l7policy_activation': {},
            'l7policy_graph_generation': 'private',
        })
        self.assertEqual({'loadbalancer_id': self.lb_id}, partial)

    def test_batch_activation_publishes_its_protected_pool_recovery(self):
        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=['amphora'])
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        pool = self.create_pool(
            self.lb_id, 'HTTP', 'ROUND_ROBIN', tls_enabled=True,
            backend_tls_hostname='backend.example.test',
            ca_tls_container_ref=uuidutils.generate_uuid())['pool']
        self.set_lb_status(self.lb_id)
        with self.session.begin():
            self.pool_repo.update(self.session, pool['id'],
                                  provisioning_status=constants.ERROR)
            self.create_amphora(uuidutils.generate_uuid(), self.lb_id,
                                role=constants.ROLE_STANDALONE,
                                lb_network_ip='192.0.2.100')
        path, payload = self._prepare_activation_group(
            action='REDIRECT_TO_POOL', redirect_pool_id=pool['id'],
            redirect_prefix=None)
        self.post(path, payload, status=204)
        delivery = self.rpc.cast.call_args.kwargs
        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_haproxy_rest_driver')
        client = rest_api_driver.AmphoraAPIClient1_0
        caps = {constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True}
        with (mock.patch.object(rest_api_driver.AmphoraAPIClientBase,
                                'get_api_version',
                                return_value={'api_version': '1.0'}),
              mock.patch.object(client, 'get_info', return_value={
                  'haproxy_version': '3.0.19'}),
              mock.patch.object(client, 'get_details', return_value=caps),
              mock.patch.object(client, 'get_cert_md5sum'),
              mock.patch.object(client, 'upload_cert_pem'),
              mock.patch.object(client, 'upload_config'),
              mock.patch.object(client, '_action') as reload):
            endpoints.Endpoints().activate_l7policies({}, **delivery)
        reload.assert_called_once()
        self.assertEqual(constants.ACTIVE, self.get(pool_path).json[
            'pool']['provisioning_status'])
        self.assertEqual([True, True, False],
                         [p['admin_state_up'] for p in
                          self._activation_policies(path)])

    def test_batch_activation_attaches_an_empty_system_ca_pool(self):
        digest = 'a' * 64
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_backend_tls_system_ca_providers=['amphora'])
        self.conf.config(group='haproxy_amphora',
                         backend_tls_system_ca_sha256=digest)
        pool = self.create_pool(
            self.lb_id, 'HTTP', 'ROUND_ROBIN', tls_enabled=True,
            backend_tls_hostname='backend.example.test',
            backend_tls_system_ca=True)['pool']
        self.set_lb_status(self.lb_id)
        with self.session.begin():
            self.create_amphora(uuidutils.generate_uuid(), self.lb_id,
                                role=constants.ROLE_STANDALONE,
                                status=constants.AMPHORA_ALLOCATED,
                                lb_network_ip='192.0.2.100')
        path, payload = self._prepare_activation_group(
            action='REDIRECT_TO_POOL', redirect_pool_id=pool['id'],
            redirect_prefix=None)
        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        self.assertIsNone(self.get(pool_path).json['pool'][
            'backend_tls_system_ca_sha256'])
        self.post(path, payload, status=204)
        delivery = self.rpc.cast.call_args.kwargs
        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_haproxy_rest_driver')
        client = rest_api_driver.AmphoraAPIClient1_0
        capabilities = {
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True,
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA: True,
        }

        def acknowledge(action, amp, lb_id, *, timeout_dict,
                        config_publication):
            self.assertEqual('reload', action)
            self.assertEqual(self.lb_id, lb_id)
            self.assertIn('description octavia-config-' + config_publication,
                          upload.call_args.args[2])
            return mock.Mock(
                status_code=202, headers={
                    constants.HAPROXY_CONFIG_PUBLICATION_HEADER:
                    config_publication})

        with (mock.patch.object(rest_api_driver.AmphoraAPIClientBase,
                                'get_api_version',
                                return_value={'api_version': '1.0'}),
              mock.patch.object(client, 'get_info', return_value={
                  'haproxy_version': '3.0.19'}),
              mock.patch.object(client, 'get_details',
                                return_value=capabilities),
              mock.patch.object(client, 'stage_backend_tls_system_ca',
                                return_value=digest),
              mock.patch.object(client, 'upload_config') as upload,
              mock.patch.object(client, '_action',
                                side_effect=acknowledge) as reload):
            endpoints.Endpoints().activate_l7policies({}, **delivery)
        reload.assert_called_once()
        self.assertIn(f'/backend-system-ca/{digest}.pem',
                      upload.call_args.args[2])
        self.assertIn('default-server ca-file', upload.call_args.args[2])
        self.assertEqual(digest, self.get(pool_path).json['pool'][
            'backend_tls_system_ca_sha256'])
        self.assertEqual([True, True, False],
                         [p['admin_state_up'] for p in
                          self._activation_policies(path)])
        with self.session.begin():
            lb = self.lb_repo.get_for_update(self.session, self.lb_id)
            self.assertEqual('applied', lb.l7policy_activation['phase'])
        after = self._activation_request(path)
        with self.session.begin():
            # Isolate this configuration field from the receipt generation.
            self.session.get(models.Pool, pool['id']).backend_tls_system_ca = (
                False)
        self.assertNotEqual(after['l7policy_activation'][
            'expected_graph_revision'], self._activation_request(path)[
                'l7policy_activation']['expected_graph_revision'])

    def test_backend_tls_system_ca_replacement_requires_new_peer_proof(self):
        digest = 'a' * 64
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_backend_tls_system_ca_providers=['amphora'])
        self.conf.config(group='haproxy_amphora',
                         backend_tls_system_ca_sha256=digest)
        pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN, tls_enabled=True,
            backend_tls_hostname='backend.example.test',
            backend_tls_system_ca=True)['pool']
        pool_id = pool['id']
        path = self.POOL_PATH.format(pool_id=pool_id)
        topology = constants.TOPOLOGY_ACTIVE_STANDBY
        first, failed, replacement = (
            uuidutils.generate_uuid() for _ in range(3))
        original = {first: constants.ROLE_MASTER,
                    failed: constants.ROLE_BACKUP}
        with self.session.begin():
            self.lb_repo.update(self.session, self.lb_id, topology=topology)
            for amphora_id, role in original.items():
                amp = self.create_amphora(
                    amphora_id, self.lb_id, role=role,
                    status=constants.AMPHORA_ALLOCATED)
            failed_amp = amp.to_dict()
            self.pool_repo.set_backend_tls_system_ca_digests(
                self.session, (self.lb_id, topology, original),
                {pool_id: digest})

        def assert_readback(expected):
            self.assertEqual(expected, self.get(path).json['pool'][
                'backend_tls_system_ca_sha256'])
            pools = self.get(self.POOLS_PATH).json['pools']
            listed = next(item for item in pools if item['id'] == pool_id)
            self.assertEqual(expected, listed['backend_tls_system_ca_sha256'])

        assert_readback(digest)
        database_tasks.MarkAmphoraPendingDeleteInDB().execute(failed_amp)
        assert_readback(None)
        with self.session.begin():
            self.amphora_repo.update(self.session, failed,
                                     status=constants.DELETED)
            self.create_amphora(replacement, self.lb_id,
                                role=constants.ROLE_BACKUP,
                                status=constants.AMPHORA_ALLOCATED)
        assert_readback(None)
        with self.session.begin():
            self.pool_repo.set_backend_tls_system_ca_digests(
                self.session, (self.lb_id, topology, original),
                {pool_id: digest})
        assert_readback(None)
        with self.session.begin():
            current = {first: constants.ROLE_MASTER,
                       replacement: constants.ROLE_BACKUP}
            self.pool_repo.set_backend_tls_system_ca_digests(
                self.session, (self.lb_id, topology, current),
                {pool_id: digest})
        assert_readback(digest)

    def test_batch_activation_rejects_stale_or_foreign_state(self):
        path, payload = self._prepare_activation_group()
        activation = payload['l7policy_activation']
        order = activation['expected_order']
        self.post(path, {'l7policy_activation': {
            **activation, 'expected_order': order[::-1],
        }}, status=409)
        other_lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora',
            project_id=uuidutils.generate_uuid())['loadbalancer']
        self.set_lb_status(other_lb['id'])
        other_listener = self.create_listener('HTTP', 80, lb_id=other_lb['id'])
        self.set_lb_status(other_lb['id'])
        foreign = self._post_policy(
            listener_id=other_listener['listener']['id'])
        endpoints.Endpoints().create_l7policy({}, **self.rpc.cast.call_args
                                              .kwargs)
        self.rpc.cast.reset_mock()
        self.post(path, {'l7policy_activation': {
            **activation, 'policies': [
                activation['policies'][0],
                {'id': foreign['l7policy']['id'], 'revision': '1' * 64}],
        }}, status=409)
        rule_id = self._activation_policies(path)[0]['rules'][0]['id']
        self.put(self.L7RULE_PATH.format(l7policy_id=order[0],
                                         l7rule_id=rule_id),
                 {'rule': {'value': 'changed.test'}})
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        self.post(path, payload, status=409)
        self.rpc.cast.assert_not_called()
        fresh = self.get(path).json['l7policy_activation']
        self.assertNotEqual(activation['policies'][0]['revision'],
                            fresh['policies'][0]['revision'])
        activation['expected_graph_revision'] = fresh['graph_revision']
        revision = fresh['policies'][0]['revision']
        activation['policies'][0]['revision'] = revision
        self.put(self.L7POLICY_PATH.format(l7policy_id=order[0]),
                 {'l7policy': {'redirect_prefix': 'https://changed.test'}})
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        self.post(path, payload, status=409)
        self.rpc.cast.assert_not_called()
        self.assertEqual([False] * 3,
                         [entry['admin_state_up'] for entry in
                          self._activation_policies(path)])
        self.assertEqual(constants.ACTIVE, self.get(self.LB_PATH.format(
            lb_id=self.lb_id)).json['loadbalancer']['provisioning_status'])

    def test_batch_activation_failure_restores_the_group(self):
        path, payload = self._prepare_activation_group()
        with mock.patch.object(self.rpc, 'cast',
                               side_effect=RuntimeError('dispatch failed')):
            self.post(path, payload, status=500)
        self.assertEqual([constants.ACTIVE] * 3, [p['provisioning_status']
                                                  for p in
                                                  self._activation_policies(
                                                      path)])
        self.post(path, payload, status=204)
        call = self.rpc.cast.call_args
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=[
                                   RuntimeError('reload failed'), None,
                               ]) as update:
            self.assertRaises(RuntimeError,
                              endpoints.Endpoints().activate_l7policies,
                              {}, **call.kwargs)
        self.assertEqual(2, update.call_count)
        restored = update.call_args.args[0].listeners[0].l7policies
        self.assertEqual([False] * 3, [policy.enabled for policy in restored])
        self.assertEqual([constants.ERROR, constants.ERROR, constants.ACTIVE],
                         [policy['provisioning_status']
                          for policy in self._activation_policies(path)])
        self.assertEqual(constants.ACTIVE, self.get_listener(self.listener_id)[
            'listener']['provisioning_status'])
        self.post(path, payload, status=409)

    def test_batch_activation_retries_unconfirmed_restoration(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        call = self.rpc.cast.call_args
        worker = endpoints.Endpoints()
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=[
                                   RuntimeError('reload failed'),
                                   RuntimeError('restore failed'), None,
                               ]) as update:
            self.assertRaises(RuntimeError, worker.activate_l7policies,
                              {}, **call.kwargs)
            listener = self.get_listener(self.listener_id)['listener']
            self.assertEqual(constants.ERROR, listener['provisioning_status'])
            self.post(path, payload, status=204)
            self.assertEqual(call, self.rpc.cast.call_args)
            worker.activate_l7policies({}, **call.kwargs)
        self.assertEqual(3, update.call_count)
        policies = update.call_args.args[0].listeners[0].l7policies
        self.assertTrue(all(not policy.enabled for policy in policies))
        listener = self.get_listener(self.listener_id)['listener']
        self.assertEqual(constants.ACTIVE, listener['provisioning_status'])
        self.post(path, payload, status=409)

    def test_batch_activation_failed_restore_can_fail_over(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        activation = self.rpc.cast.call_args.kwargs
        worker = endpoints.Endpoints()
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=RuntimeError('offline')):
            self.assertRaises(RuntimeError, worker.activate_l7policies,
                              {}, **activation)

        failover = self._get_full_path(
            self.LB_PATH.format(lb_id=self.lb_id) + '/failover')
        with db_api.listener_render_lock(self.lb_id) as lock:
            self.assertTrue(lock)
            self.app.put(failover, status=409)
        self.app.put(failover, status=202)
        self.post(path, payload, status=409)
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update') as update:
            worker.activate_l7policies({}, **activation)
        update.assert_not_called()

        policy_id = payload['l7policy_activation']['expected_order'][0]
        obsolete = {constants.L7POLICY_ID: policy_id}
        lb = {constants.LOADBALANCER_ID: self.lb_id}
        listener = {constants.LISTENER_ID: self.listener_id}
        # A jobboard flow can resume at its write and publication steps.
        policy_update = database_tasks.UpdateL7PolicyInDB()
        policy_update.execute(obsolete, {'enabled': True})
        database_tasks.MarkLBAndListenersActiveInDB().execute(
            self.lb_id, [listener])
        self.assertEqual(constants.PENDING_UPDATE, self.get(
            self.LB_PATH.format(lb_id=self.lb_id)).json['loadbalancer'][
                'provisioning_status'])
        lifecycle_tasks.LoadBalancerToErrorOnRevertTask(
            for_failover=True).revert(lb)
        self.assertEqual(constants.ERROR, self.get(
            self.LB_PATH.format(lb_id=self.lb_id)).json['loadbalancer'][
                'provisioning_status'])
        self.app.put(failover, status=202)

        with self.session.begin():
            replacement = self.create_amphora(
                uuidutils.generate_uuid(), self.lb_id,
                role=constants.ROLE_STANDALONE, lb_network_ip='192.0.2.100')
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update_amphora_listeners') as render:
            amphora_driver_tasks.AmpListenersUpdate().execute(
                lb, {'id': replacement.id})
        render.assert_called_once()
        rendered = render.call_args.args[0].listeners[0].l7policies
        self.assertEqual([False] * 3, [policy.enabled for policy in rendered])
        database_tasks.MarkLBActiveInDB(mark_subobjects=True).execute(lb)
        self.assertEqual(constants.ACTIVE, self.get(
            self.LB_PATH.format(lb_id=self.lb_id)).json['loadbalancer'][
                'provisioning_status'])
        policy_update.execute(obsolete, {'enabled': True})
        self.post(path, payload, status=409)
        self.assertEqual([False] * 3,
                         [p['admin_state_up'] for p in
                          self._activation_policies(path)])

    def test_batch_activation_waits_for_an_ordinary_render(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        delivery = self.rpc.cast.call_args.kwargs
        self.conf.config(group='haproxy_amphora', connection_max_retries=2,
                         connection_retry_interval=0)
        real_lock = db_api.listener_render_lock
        busy_once = iter((True, False, False))

        @contextlib.contextmanager
        def render_lock(lb_id):
            if next(busy_once):
                yield False
            else:
                with real_lock(lb_id) as acquired:
                    yield acquired

        with (mock.patch.object(db_api, 'listener_render_lock', render_lock),
              mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                                'update', return_value=None) as update):
            worker = endpoints.Endpoints()
            worker.activate_l7policies({}, **delivery)
            worker.activate_l7policies({}, **delivery)
        update.assert_called_once()
        self.assertEqual([True, True, False],
                         [p['admin_state_up'] for p in
                          self._activation_policies(path)])

    def test_failover_completion_preserves_unrestored_frontend_error(self):
        with self.session.begin():
            listener = self.session.get(models.Listener, self.listener_id)
            listener.provisioning_status = constants.ERROR
            listener.frontend_fallback_owns_error = True
        lb = {constants.LOADBALANCER_ID: self.lb_id}
        database_tasks.MarkLBActiveInDB(mark_subobjects=True).execute(lb)
        listener = self.get_listener(self.listener_id)['listener']
        self.assertEqual(constants.ERROR, listener['provisioning_status'])

    def test_batch_activation_replays_after_interruption(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        delivery = self.rpc.cast.call_args
        self.post(path, payload, status=204)
        self.assertEqual(delivery, self.rpc.cast.call_args)

        def reload_candidate(candidate, **kwargs):
            rendered = candidate.listeners[0].l7policies
            self.assertEqual([True, True, False],
                             [p.enabled for p in rendered])
            self.assertEqual([False] * 3,
                             [p['admin_state_up'] for p in
                              self._activation_policies(path)])

        with (mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                                'update', side_effect=reload_candidate),
              mock.patch.object(amphora_driver_tasks.ApplyL7PolicyActivation,
                                '_finish', side_effect=RuntimeError(
                                    'worker interrupted after reload'))):
            self.assertRaises(RuntimeError,
                              endpoints.Endpoints().activate_l7policies,
                              {}, **delivery.kwargs)
        self.assertEqual([False] * 3, [p['admin_state_up'] for p in
                                       self._activation_policies(path)])
        self.post(path, payload, status=204)
        self.assertEqual(delivery, self.rpc.cast.call_args)
        endpoints.Endpoints().activate_l7policies({}, **delivery.kwargs)
        self.assertEqual([True, True, False],
                         [p['admin_state_up'] for p in
                          self._activation_policies(path)])
        self.rpc.cast.reset_mock()
        self.post(path, payload, status=204)
        self.rpc.cast.assert_not_called()

    def test_batch_activation_cannot_reopen_a_withdrawn_group(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        worker = endpoints.Endpoints()
        worker.activate_l7policies({}, **self.rpc.cast.call_args.kwargs)
        selected = payload['l7policy_activation']['policies']
        for enabled in (False, True, False):
            for item in selected:
                self.put(self.L7POLICY_PATH.format(l7policy_id=item['id']),
                         {'l7policy': {'admin_state_up': enabled}})
                worker.update_l7policy({}, **self.rpc.cast.call_args.kwargs)
        self.assertEqual([False] * 3, [p['admin_state_up'] for p in
                                       self._activation_policies(path)])
        self.rpc.cast.reset_mock()
        self.post(path, payload, status=409)
        self.rpc.cast.assert_not_called()
        self.post(path, self._activation_request(path), status=204)

    def test_batch_activation_detects_listener_and_destination_changes(self):
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        member = self.create_member(pool['id'], '192.0.2.4', 8000)['member']
        self.set_lb_status(self.lb_id)
        monitor = self.create_health_monitor(
            pool['id'], 'HTTP', 5, 2, 2, 2)['healthmonitor']
        self.set_lb_status(self.lb_id)
        path, payload = self._prepare_activation_group(
            action='REDIRECT_TO_POOL', redirect_pool_id=pool['id'],
            redirect_prefix=None)
        graph = self.get(path).json['l7policy_activation']
        self.assertEqual(self.lb_id, graph['loadbalancer']['id'])
        self.assertEqual(self.listener_id, graph['listener']['id'])
        destination, = graph['pools']
        self.assertEqual(pool['id'], destination['pool']['id'])
        self.assertEqual(monitor['id'],
                         destination['pool']['healthmonitor']['id'])
        self.assertEqual([{'id': pool['id']}],
                         destination['pool']['healthmonitor']['pools'])
        actual_member, = destination['members']
        self.assertEqual(member['id'], actual_member['id'])
        self.assertEqual(pool['id'], actual_member['pool_id'])
        self.assertEqual(8000, actual_member['protocol_port'])
        self.put(self.MEMBER_PATH.format(pool_id=pool['id'],
                                         member_id=member['id']),
                 {'member': {'weight': 2}})
        self.set_lb_status(self.lb_id)
        self.post(path, payload, status=409)
        payload = self._activation_request(path)
        self.put(self.LISTENER_PATH.format(listener_id=self.listener_id),
                 {'listener': {'tags': ['new-owner']}})
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        self.post(path, payload, status=409)
        self.rpc.cast.assert_not_called()

    def test_batch_activation_fences_an_old_update_flow(self):
        path, _payload = self._prepare_activation_group()
        policy_id = self._activation_policies(path)[0]['id']
        self.put(self.L7POLICY_PATH.format(l7policy_id=policy_id),
                 {'l7policy': {'redirect_prefix': 'https://withdrawn.test'}})
        previous = self.rpc.cast.call_args.kwargs
        self.set_lb_status(self.lb_id)
        self.put(self.L7POLICY_PATH.format(l7policy_id=policy_id),
                 {'l7policy': {'redirect_prefix': 'https://first.test'}})
        self.set_lb_status(self.lb_id)
        self.post(path, self._activation_request(path), status=204)
        batch = self.rpc.cast.call_args.kwargs
        worker = endpoints.Endpoints()
        worker.update_l7policy({}, **previous)
        # A flow already queued on a jobboard may enter its write step
        # directly. Its persisted payload has no authority over the batch.
        database_tasks.UpdateL7PolicyInDB().execute(
            previous['original_l7policy'], previous['l7policy_updates'])
        still_pending = self._activation_policies(path)[0]
        self.assertEqual('https://first.test',
                         still_pending['redirect_prefix'])
        self.assertEqual(constants.PENDING_UPDATE,
                         still_pending['provisioning_status'])
        worker.activate_l7policies({}, **batch)
        self.assertTrue(self._activation_policies(path)[0]['admin_state_up'])

    def test_batch_activation_restores_an_invalidated_pending_snapshot(self):
        path, payload = self._prepare_activation_group()
        self.post(path, payload, status=204)
        delivery = self.rpc.cast.call_args.kwargs
        policy_id = payload['l7policy_activation']['policies'][0]['id']
        # Emulate an obsolete writer that bypasses the repository guard.
        with self.session.begin():
            self.session.get(models.L7Policy, policy_id).enabled = True
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', return_value=None) as update:
            endpoints.Endpoints().activate_l7policies({}, **delivery)
        update.assert_called_once()
        rendered = update.call_args.args[0].listeners[0].l7policies
        self.assertTrue(all(not policy.enabled for policy in rendered))
        self.assertEqual([constants.ERROR, constants.ERROR, constants.ACTIVE],
                         [p['provisioning_status'] for p in
                          self._activation_policies(path)])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_batch_activation_preserves_ordinary_https_put(self, cert_data):
        self.conf.config(group='api_settings',
                         enabled_l7policy_batch_activation_providers=[
                             'amphora'])
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='certificate')}
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        tls = uuidutils.generate_uuid()
        ca = uuidutils.generate_uuid()
        listener = self.create_listener(
            constants.PROTOCOL_TERMINATED_HTTPS, 443, self.lb_id,
            default_tls_container_ref=tls,
            client_ca_tls_container_ref=ca)['listener']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        path = self.LISTENER_PATH.format(listener_id=listener['id'])
        payload = {'listener': {'tags': ['ordinary-put'],
                                'connection_limit': 5}}
        updated = self.put(path, payload).json['listener']
        self.assertEqual(tls, updated['default_tls_container_ref'])
        self.assertEqual(ca, updated['client_ca_tls_container_ref'])
        self.assertEqual(5, updated['connection_limit'])
        self.rpc.cast.assert_called_once()
        self.assertEqual('update_listener', self.rpc.cast.call_args.args[1])

    def test_create_initial_rules_in_one_worker_operation(self):
        response = self._post_policy()['l7policy']
        self.assertFalse(response['admin_state_up'])
        self.assertEqual('PENDING_CREATE', response['provisioning_status'])
        self.rpc.cast.assert_called_once()
        call = self.rpc.cast.call_args
        self.assertEqual('create_l7policy', call.args[1])
        policy = call.kwargs['l7policy']
        self.assertFalse(policy['admin_state_up'])
        self.assertCountEqual([rule['id'] for rule in response['rules']],
                              [rule['l7rule_id'] for rule in policy['rules']])
        self.assertCountEqual(self.rules, [
            {key: rule[key] for key in self.rules[0]} for rule in policy['rules']
        ])

        path = self.L7POLICY_PATH.format(l7policy_id=response['id'])
        rule_path = self.L7RULES_PATH.format(l7policy_id=response['id'])
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=409)

        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update') as update:
            endpoints.Endpoints().create_l7policy({}, policy)
        update.assert_called_once()
        snapshot, = update.call_args.args
        rendered_policy, = snapshot.listeners[0].l7policies
        self.assertFalse(rendered_policy.enabled)
        self.assertCountEqual([rule['id'] for rule in response['rules']],
                              [rule.id for rule in rendered_policy.l7rules])

        active = self.get(path).json['l7policy']
        self.assertFalse(active['admin_state_up'])
        self.assertEqual('ACTIVE', active['provisioning_status'])
        saved = self.get(rule_path).json['rules']
        self.assertCountEqual(self.rules, [
            {key: rule[key] for key in self.rules[0]} for rule in saved
        ])
        self.assertEqual({'ACTIVE'}, {
            rule['provisioning_status'] for rule in saved
        })

    def test_invalid_second_rule_rolls_back_the_policy(self):
        self.rules[1]['compare_type'] = 'REGEX'
        self.rules[1]['value'] = '['
        self._post_policy(status=400)
        self.rpc.cast.assert_not_called()
        self.assertEqual([], self.get(self.L7POLICIES_PATH).json['l7policies'])
        with self.session.begin():
            self.assertEqual(0, self.l7rule_repo.count(self.session))
            self.assertEqual('ACTIVE', self.lb_repo.get(
                self.session, id=self.lb_id).provisioning_status)
            self.assertEqual('ACTIVE', self.listener_repo.get(
                self.session, id=self.listener_id).provisioning_status)

    def _authenticated_project(self):
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        context = octavia.common.context.RequestContext(
            project_id=self.project_id,
            roles=['load-balancer_member', 'member'])
        self.useFixture(fixtures.MockPatchObject(
            octavia.common.context.RequestContext, 'from_environ',
            return_value=context))
        with self.session.begin():
            repositories.QuotasRepository().update(
                self.session, self.project_id,
                quota={'l7policy': 2, 'l7rule': 2})

    def _dispatch(self, operation):
        self.rpc.cast.assert_called_once()
        call = self.rpc.cast.call_args
        self.assertEqual(operation, call.args[1])
        self.rpc.cast.reset_mock()
        getattr(endpoints.Endpoints(), operation)({}, **call.kwargs)

    def test_weighted_target_filters_with_initial_rules(self):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_weighted_target_request_filter_providers=['amphora'])
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        targets = [{'weight': 1, 'pool_id': pool['id'],
                    'request_url_rewrite': {'hostname': 'backend.example'}}]
        policy = self.create_l7policy(
            self.listener_id, 'WEIGHTED_TARGETS', admin_state_up=False,
            rules=self.rules, targets=targets)['l7policy']
        self.assertEqual(targets, self.rpc.cast.call_args.kwargs[
            constants.L7POLICY]['targets'])
        self._dispatch('create_l7policy')
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        stored = self.get(path).json['l7policy']
        self.assertEqual('ACTIVE', stored['provisioning_status'])
        self.assertEqual(targets, stored['targets'])
        self.assertEqual(2, len(stored['rules']))

    def test_rewrite_and_initial_rules_require_independent_enrollment(self):
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        target = dict(redirect_pool_id=pool, admin_state_up=False,
                      rules=self.rules,
                      request_url_rewrite={'hostname': 'backend.example'})

        self.create_l7policy(self.listener_id, 'REDIRECT_TO_POOL',
                             status=501, **target)
        self.rpc.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=['amphora'])
        policy = self.create_l7policy(self.listener_id, 'REDIRECT_TO_POOL',
                                      **target)['l7policy']
        self.assertEqual(2, len(policy['rules']))
        self.assertEqual(target['request_url_rewrite'],
                         policy['request_url_rewrite'])
        self._dispatch('create_l7policy')

        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=[])
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        self.rpc.cast.assert_not_called()
        stored = self.get(path).json['l7policy']
        self.assertFalse(stored['admin_state_up'])
        self.assertEqual('ACTIVE', stored['provisioning_status'])

    @mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver, 'update')
    def test_cors_create_update_and_clear_reach_worker_snapshot(self, update):
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        target = {'redirect_pool_id': pool['id'],
                  'admin_state_up': False, 'rules': self.rules}
        field = 'request_cors'
        self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL', status=501,
            request_cors={}, **target)
        self.rpc.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_request_cors_providers=['amphora'])

        for invalid in ([], {'unknown': True}, {'allow_credentials': 'true'},
                        {'allow_origins': ['https://example.test:65536']},
                        {'allow_origins': ['*', 'https://example.test']},
                        {'allow_origins': ['https://example.test/path']},
                        {'allow_methods': ['get']},
                        {'allow_headers': ['x-header\nnext']},
                        {'allow_headers': ['x' * 257]},
                        {'expose_headers': ['same', 'same']},
                        {'max_age': True}, {'max_age': 2**31}):
            with self.subTest(invalid=invalid):
                self.create_l7policy(
                    self.listener_id, 'REDIRECT_TO_POOL', status=400,
                    request_cors=invalid, **target)
        self.create_l7policy(
            self.listener_id, 'REJECT', status=400, request_cors={})
        self.rpc.cast.assert_not_called()

        cors = {
            'allow_origins': ['https://*.example.test:443', 'http://*'],
            'allow_credentials': True,
            'allow_methods': ['GET', 'PATCH'],
            'allow_headers': ['X-Custom'],
            'expose_headers': ['*', 'X-Trace'],
            'max_age': 3600,
        }
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL', request_cors=cors,
            **target)['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])

        def assert_snapshot(operation, expected):
            update.reset_mock()
            self._dispatch(operation)
            update.assert_called_once()
            snapshot, = update.call_args.args
            rendered, = snapshot.listeners[0].l7policies
            self.assertEqual(expected, rendered.request_cors)

        self.assertEqual(cors, self.rpc.cast.call_args.kwargs[
            constants.L7POLICY][field])
        assert_snapshot('create_l7policy', cors)

        cases = (({'name': 'retained'}, cors), ({field: {}}, {}))
        for body, expected in cases:
            self.put(path, {'l7policy': body})
            cast_args = self.rpc.cast.call_args.kwargs
            updates = cast_args[constants.L7POLICY_UPDATES]
            self.assertEqual(field in body, field in updates)
            if field in body:
                self.assertEqual(body[field], updates[field])
            assert_snapshot('update_l7policy', expected)
            self.assertEqual(expected, self.get(path).json['l7policy'][field])

        self.conf.config(group='api_settings',
                         enabled_request_cors_providers=[])
        cleared = self.put(path, {'l7policy': {field: None}})
        self.assertNotIn(field, cleared.json['l7policy'])
        self.assertIsNone(self.rpc.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES][field])
        assert_snapshot('update_l7policy', None)
        self.assertNotIn(field, self.get(path).json['l7policy'])

    @mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver, 'update')
    def test_http_retry_backoff_admission_and_readback(self, update):
        field = 'http_request_policy'
        cap = constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF
        caps_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        target = {'redirect_pool_id': pool['id'], 'rules': self.rules,
                  'admin_state_up': False}
        maximum = constants.HTTP_REQUEST_POLICY_DURATION_MAX
        data = {'request_timeout_ms': 500, 'retry': {
            'attempts': 2, 'codes': [503], 'backoff_ms': maximum}}
        self.conf.config(group='api_settings',
                         enabled_http_retry_backoff_providers=['amphora'])
        self.assertNotIn(cap, self.get(caps_path).json['gateway_capabilities'])
        self.create_l7policy(self.listener_id, 'REDIRECT_TO_POOL',
                             http_request_policy=data, status=501, **target)
        self.conf.config(group='api_settings',
                         enabled_http_request_policy_providers=['amphora'],
                         enabled_http_retry_backoff_providers=[])
        self.create_l7policy(self.listener_id, 'REDIRECT_TO_POOL',
                             http_request_policy=data, status=501, **target)
        self.conf.config(group='api_settings',
                         enabled_http_retry_backoff_providers=['amphora'])
        self.assertIn(cap, self.get(caps_path).json['gateway_capabilities'])
        with mock.patch.object(
                driver_utils, 'HTTP_REQUEST_POLICY_PAYLOAD_AVAILABLE', False):
            self.assertNotIn(cap, self.get(caps_path).json[
                'gateway_capabilities'])
        for invalid in (True, -1, 0.5, '20', None, maximum + 1):
            with self.subTest(backoff_ms=invalid):
                self.create_l7policy(
                    self.listener_id, 'REDIRECT_TO_POOL', status=400,
                    http_request_policy={'retry': {'backoff_ms': invalid}},
                    **target)
        created = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL', http_request_policy=data,
            **target)['l7policy']
        self.assertEqual(data, created[field])
        self.assertEqual(data, self.rpc.cast.call_args.kwargs[
            constants.L7POLICY][field])
        self._dispatch('create_l7policy')
        snapshot, = update.call_args.args
        worker_policy, = snapshot.listeners[0].l7policies
        self.assertEqual(data, worker_policy.http_request_policy)
        path = self.L7POLICY_PATH.format(l7policy_id=created['id'])
        self.assertEqual(data, self.get(path).json['l7policy'][field])
        listed, = self.get(self.L7POLICIES_PATH).json['l7policies']
        self.assertEqual(data, listed[field])
        self.put(path, {'l7policy': {'admin_state_up': True}})
        self._dispatch('update_l7policy')

        self.conf.config(group='api_settings',
                         enabled_http_retry_backoff_providers=[])
        reduced = {'request_timeout_ms': 500, 'retry': {
            'attempts': 2, 'codes': [503], 'backoff_ms': 0}}
        self.put(path, {'l7policy': {field: reduced}})
        self.assertEqual(reduced, self.rpc.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES][field])
        self._dispatch('update_l7policy')
        self.assertEqual(reduced, self.get(path).json['l7policy'][field])
        self.put(path, {'l7policy': {field: data}}, status=501)
        self.put(path, {'l7policy': {field: {
            **reduced, 'retry': {**reduced['retry'], 'attempts': 3},
        }}}, status=501)
        cleared = {'request_timeout_ms': 500, 'retry': {
            'attempts': 2, 'codes': [503]}}
        sibling = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL', http_request_policy=cleared,
            **target)['l7policy']
        self._dispatch('create_l7policy')
        sibling_path = self.L7POLICY_PATH.format(l7policy_id=sibling['id'])
        self.put(sibling_path, {'l7policy': {'admin_state_up': True}})
        self._dispatch('update_l7policy')

        # The sibling can take over while backoff remains withdrawn.
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self._dispatch('update_l7policy')
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        self.put(path, {'l7policy': {
            field: cleared, 'admin_state_up': True}})
        self._dispatch('update_l7policy')
        self.assertEqual(cleared, self.get(path).json['l7policy'][field])
        self.delete(path)
        self._dispatch('delete_l7policy')
        self.get(path, status=404)

    @mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver, 'update')
    def test_backend_retry_budget_pool_worker_lifecycle(self, update):
        self.conf.config(group='api_settings',
                         enabled_backend_retry_budget_providers=['amphora'])
        self.rpc.cast.reset_mock()
        field = 'backend_retry_budget'
        budget = dict(service_uid='service-uid', budget_percent=20,
                      budget_interval_ms=10000, min_retry_count=10,
                      min_retry_interval_ms=1000)
        pool = self.create_pool(
            self.lb_id, 'HTTP', 'ROUND_ROBIN', listener_id=self.listener_id,
            backend_retry_budget=budget)['pool']
        self.assertEqual(budget, self.rpc.cast.call_args.kwargs[
            constants.POOL][field])
        self._dispatch('create_pool')
        snapshot, = update.call_args.args
        default_pool = snapshot.listeners[0].default_pool
        self.assertEqual(budget, default_pool.backend_retry_budget)

        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.put(path, {'pool': {field: None}})
        self.assertIsNone(self.rpc.cast.call_args.kwargs[
            constants.POOL_UPDATES][field])
        self._dispatch('update_pool')
        snapshot, = update.call_args.args
        self.assertIsNone(
            snapshot.listeners[0].default_pool.backend_retry_budget)

    @mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver, 'update')
    def test_http_request_policy_round_trip_and_withdrawal(self, update):
        field = 'http_request_policy'
        provider_caps = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        capability = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        pool_id = pool['id']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        target = {'redirect_pool_id': pool_id, 'admin_state_up': False,
                  'rules': self.rules}
        policy_data = {'request_timeout_ms': 2**63 - 1,
                       'backend_request_timeout_ms': 500,
                       'retry': {'attempts': 3, 'codes': [500, 504]}}
        self.assertNotIn(
            capability, self.get(provider_caps).json['gateway_capabilities'])
        self.create_l7policy(self.listener_id, 'REDIRECT_TO_POOL', status=501,
                             http_request_policy=policy_data, **target)
        self.conf.config(
            group='api_settings',
            enabled_http_request_policy_providers=['amphora'])
        self.assertIn(
            capability, self.get(provider_caps).json['gateway_capabilities'])
        with mock.patch.object(
                driver_utils, 'HTTP_REQUEST_POLICY_PAYLOAD_AVAILABLE', False):
            self.assertNotIn(capability, self.get(
                provider_caps).json['gateway_capabilities'])

        for value in (
                {'request_timeout_ms': True},
                {'request_timeout_ms': 2**63},
                {'request_timeout_ms': 100, 'backend_request_timeout_ms': 200},
                {'retry': {'attempts': 2**31}},
                {'retry': {'codes': [500, 500]}},
                {'retry': {'codes': [501]}},
                {'retry': {'backoff': 10}}):
            with self.subTest(value=value):
                self.create_l7policy(
                    self.listener_id, 'REDIRECT_TO_POOL', status=400,
                    http_request_policy=value, **target)
        self.create_l7policy(self.listener_id, 'REJECT', status=400,
                             http_request_policy={})

        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            http_request_policy=policy_data, **target)['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual(policy_data, policy[field])
        self.assertEqual(policy_data, self.rpc.cast.call_args.kwargs[
            constants.L7POLICY][field])
        self._dispatch('create_l7policy')
        snapshot, = update.call_args.args
        worker_policy, = snapshot.listeners[0].l7policies
        self.assertEqual(policy_data, worker_policy.http_request_policy)
        self.assertEqual(policy_data, self.get(path).json['l7policy'][field])
        listed, = self.get(self.L7POLICIES_PATH).json['l7policies']
        self.assertEqual(policy_data, listed[field])

        for body, stored in (
                ({'name': 'renamed'}, policy_data),
                ({field: {'request_timeout_ms': 0, 'retry': {}}},
                 {'request_timeout_ms': 0, 'retry': {}}),
                ({field: {'retry': {'attempts': 0}}},
                 {'retry': {'attempts': 0}})):
            with self.subTest(body=body):
                updated = self.put(path, {'l7policy': body}).json['l7policy']
                self.assertEqual(stored, updated[field])
                updates = self.rpc.cast.call_args.kwargs[
                    constants.L7POLICY_UPDATES]
                self.assertEqual(field in body, field in updates)
                if field in body:
                    self.assertEqual(stored, updates[field])
                self._dispatch('update_l7policy')

        self.put(path, {'l7policy': {'admin_state_up': True}})
        self._dispatch('update_l7policy')
        self.conf.config(
            group='api_settings', enabled_http_request_policy_providers=[])
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=policy['rules'][0]['id'])
        self.delete(rule_path, status=501)
        self.rpc.cast.assert_not_called()
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self._dispatch('update_l7policy')
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        self.rpc.cast.assert_not_called()

        cleared = self.put(path, {'l7policy': {field: None}}).json['l7policy']
        self.assertNotIn(field, cleared)
        self.assertIsNone(self.rpc.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES][field])
        update.reset_mock()
        self._dispatch('update_l7policy')
        snapshot, = update.call_args.args
        worker_policy, = snapshot.listeners[0].l7policies
        self.assertIsNone(worker_policy.http_request_policy)
        self.assertNotIn(field, self.get(path).json['l7policy'])

    @mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver, 'update')
    def test_request_mirrors_round_trip_scope_and_withdrawal(self, update):
        field = 'request_mirrors'
        capability = constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR
        caps_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        primary = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        copy = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        tcp = self.create_pool(self.lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        other_lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.set_lb_status(other_lb['id'])
        foreign = self.create_pool(
            other_lb['id'], 'HTTP', 'ROUND_ROBIN')['pool']
        self.rpc.cast.reset_mock()
        mirror = dict(pool_id=copy['id'], numerator=7, denominator=13)
        first = dict(mirror, phase='before_transforms')
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        target = dict(weight=3, pool_id=primary['id'])
        post = dict(action='WEIGHTED_TARGETS', redirect_prefix=None,
                    targets=[dict(target, request_mirrors=[mirror])])
        self.assertNotIn(capability,
                         self.get(caps_path).json['gateway_capabilities'])
        self._post_policy(status=501, **post)
        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=['amphora'])
        self.assertIn(capability,
                      self.get(caps_path).json['gateway_capabilities'])
        with mock.patch.object(
                driver_utils, 'HTTP_REQUEST_MIRROR_PAYLOAD_AVAILABLE', False):
            self.assertNotIn(capability,
                             self.get(caps_path).json['gateway_capabilities'])
        for bad in ({'numerator': True}, {'numerator': '7'},
                    {'denominator': 0}, {'numerator': 14},
                    {'denominator': 2**31}, {'phase': None},
                    {'pool_id': 'not-a-uuid'}, {'address': '192.0.2.4'}):
            with self.subTest(bad=bad):
                self._post_policy(
                    status=400, request_mirrors=[dict(mirror, **bad)], **post)
        self._post_policy(status=400, request_mirrors=[mirror, first], **post)
        self._post_policy(status=404, request_mirrors=[
            dict(mirror, pool_id=foreign['id'], numerator=0)], **post)
        self._post_policy(status=400, request_mirrors=[
            dict(mirror, pool_id=tcp['id'], numerator=0)], **post)
        self.rpc.cast.assert_not_called()

        policy = self._post_policy(**post)['l7policy']
        self.assertEqual([], policy[field])
        self.assertEqual(post['targets'], policy['targets'])
        payload = self.rpc.cast.call_args.kwargs[constants.L7POLICY]
        self.assertEqual(policy['targets'], payload['targets'])
        self._dispatch('create_l7policy')
        listed, = self.get(self.L7POLICIES_PATH).json['l7policies']
        self.assertEqual([], listed[field])
        self.assertEqual(policy['targets'], listed['targets'])

        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual([], self.get(path).json['l7policy'][field])
        mirrors = [first, mirror, mirror]
        self.put(path, {'l7policy': {'admin_state_up': True, field: mirrors}})
        self._dispatch('update_l7policy')
        snapshot, = update.call_args.args
        self.assertIn(copy['id'], [pool.id for pool in
                                   snapshot.listeners[0].pools])
        self.assertEqual(mirrors,
                         snapshot.listeners[0].l7policies[0].request_mirrors)
        pool_path = self.POOL_PATH.format(pool_id=copy['id'])
        self.delete(pool_path, status=409)

        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=[])
        self.put(pool_path, {'pool': {'admin_state_up': False}})
        self._dispatch('update_pool')
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.rpc.cast.assert_not_called()
        self.put(path, {'l7policy': {
            field: [first], 'targets': [target]}})
        self._dispatch('update_l7policy')
        retained = self.get(path).json['l7policy']
        self.assertEqual([first], retained[field])
        self.assertEqual([target], retained['targets'])
        self.delete(pool_path, status=409)
        self.put(path, {'l7policy': {field: None}})
        self._dispatch('update_l7policy')
        self.assertEqual([], self.get(path).json['l7policy'][field])
        self.delete(pool_path)

    def test_fixed_response_request_transforms_with_mirrors(self):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_http_request_mirror_providers=['amphora'],
            enabled_request_header_operation_providers=['amphora'],
            enabled_request_url_rewrite_providers=['amphora'])
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        headers = [{'operation': 'SET', 'name': 'x-copy', 'value': 'rule'}]
        rewrite = {'replace_full_path': '/copy'}
        fixed = dict(action='FIXED_RESPONSE', redirect_prefix=None,
                     fixed_response={'status_code': 500})
        mirror = {'pool_id': pool['id'], 'numerator': 1, 'denominator': 1}
        filters = dict(request_header_operations=headers,
                       request_url_rewrite=rewrite)
        self._post_policy(status=400, **fixed, **filters)
        self.rpc.cast.assert_not_called()
        policy = self._post_policy(
            request_mirrors=[mirror], **fixed, **filters)['l7policy']
        self._dispatch('create_l7policy')
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])

        for primary in (
                {'action': 'REDIRECT_TO_POOL', 'redirect_pool_id': pool['id']},
                {'action': 'WEIGHTED_TARGETS', 'targets': [
                    {'weight': 1, 'fixed_response': {'status_code': 500}}]}):
            with self.subTest(action=primary['action']):
                self.put(path, {'l7policy': primary})
                self._dispatch('update_l7policy')
                self.put(path, {'l7policy': fixed})
                self._dispatch('update_l7policy')
                stored = self.get(path).json['l7policy']
                self.assertEqual([mirror], stored['request_mirrors'])
                self.assertEqual(headers, stored['request_header_operations'])
                self.assertEqual(rewrite, stored['request_url_rewrite'])

        self.put(path, {'l7policy': {'request_mirrors': []}})
        self._dispatch('update_l7policy')
        self.put(path, {'l7policy': {'name': 'retained'}})
        self._dispatch('update_l7policy')
        stored = self.get(path).json['l7policy']
        self.assertEqual([], stored['request_mirrors'])
        self.assertEqual(headers, stored['request_header_operations'])
        self.assertEqual(rewrite, stored['request_url_rewrite'])

    def test_batch_activation_validates_request_mirrors(self):
        primary = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        copy = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=['amphora'])
        mirrors = [dict(pool_id=copy['id'], numerator=0, denominator=1)]
        path, request = self._prepare_activation_group(
            action='REDIRECT_TO_POOL', redirect_prefix=None,
            redirect_pool_id=primary['id'], request_mirrors=mirrors)
        graph = self.get(path).json['l7policy_activation']
        self.assertCountEqual({primary['id'], copy['id']},
                              [item['pool']['id'] for item in graph['pools']])
        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=[])
        self.post(path, request, status=501)
        self.rpc.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=['amphora'])
        self.post(path, request, status=204)
        self._dispatch('activate_l7policies')
        self.assertEqual([True, True, False], [
            policy['admin_state_up'] for policy in
            self._activation_policies(path)])

    @mock.patch.object(driver_utils, 'REQUEST_CORS_PAYLOAD_AVAILABLE', False)
    def test_cors_cleanup_with_pre_cors_provider_payload(self):
        self.conf.config(group='api_settings',
                         enabled_request_cors_providers=['amphora'])
        pool = self.create_pool(self.lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL', redirect_pool_id=pool['id'],
            request_cors={}, status=501)
        self.rpc.cast.assert_not_called()
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=pool['id'])['l7policy']
        self.assertNotIn('request_cors', policy)
        self._dispatch('create_l7policy')
        # Represent a stored policy after restarting with an older octavia-lib.
        with self.session.begin():
            self.l7policy_repo.update(self.session, policy['id'],
                                      request_cors={})

        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual({}, self.get(path).json['l7policy']['request_cors'])
        cleared = self.put(path, {'l7policy': {'request_cors': None}})
        self.assertNotIn('request_cors', cleared.json['l7policy'])
        for payload in self.rpc.cast.call_args.kwargs.values():
            self.assertNotIn('request_cors', payload)
        self._dispatch('update_l7policy')
        stored = self.get(path).json['l7policy']
        self.assertNotIn('request_cors', stored)
        self.assertEqual('ACTIVE', stored['provisioning_status'])

    def test_rule_quota_reusable_after_parent_delete(self):
        self._authenticated_project()
        policy = self._post_policy()['l7policy']
        self._dispatch('create_l7policy')
        self._post_policy(status=403)
        self.rpc.cast.assert_not_called()

        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.delete(path)
        self._dispatch('delete_l7policy')
        self.get(path, status=404)
        with self.session.begin():
            quotas = repositories.QuotasRepository().get(
                self.session, project_id=self.project_id)
            self.assertEqual((0, 0), (quotas.in_use_l7policy,
                                      quotas.in_use_l7rule))
        replacement = self._post_policy()['l7policy']
        self.assertEqual(2, len(replacement['rules']))
        self._dispatch('create_l7policy')

    def test_rule_creation_requires_separate_permission(self):
        self._authenticated_project()
        enforcer = policy.Policy(use_conf=False)
        enforcer.set_rules(oslo_policy.Rules.from_dict({
            f'{constants.RBAC_L7POLICY}{constants.RBAC_POST}':
                'project_id:%(project_id)s and role:member',
            f'{constants.RBAC_L7RULE}{constants.RBAC_POST}': '!',
        }), use_conf=False)
        with mock.patch.object(policy, 'get_enforcer', return_value=enforcer):
            self._post_policy(status=403)
            self.rpc.cast.assert_not_called()
            self._post_policy(rules=[])

    def test_rule_insert_failure_rolls_back_rows_and_quota(self):
        self._authenticated_project()
        create_rule = repositories.L7RuleRepository.create

        def fail_on_second(repo, session, **kwargs):
            if kwargs['type'] == 'PATH':
                self.assertEqual(1, repo.count(session))
                raise RuntimeError('second insert failed')
            return create_rule(repo, session, **kwargs)

        with mock.patch.object(repositories.L7RuleRepository, 'create',
                               autospec=True, side_effect=fail_on_second):
            self._post_policy(status=500)
        self.rpc.cast.assert_not_called()
        with self.session.begin():
            self.assertEqual(0, self.l7policy_repo.count(self.session))
            self.assertEqual(0, self.l7rule_repo.count(self.session))
            quotas = repositories.QuotasRepository().get(
                self.session, project_id=self.project_id)
            self.assertFalse(quotas.in_use_l7policy)
            self.assertFalse(quotas.in_use_l7rule)
            self.assertEqual('ACTIVE', self.lb_repo.get(
                self.session, id=self.lb_id).provisioning_status)
        self._post_policy()

    def test_json_rule_types_and_boolean_defaults(self):
        for bad_policy in (
            {'rules': {}},
            {'rules': [None]},
            {'rules': [True]},
            {'admin_state_up': 'false'},
            {'admin_state_up': 0},
            {'admin_state_up': None},
            {'rules': [dict(self.rules[0], invert='false')]},
            {'rules': [dict(self.rules[0], invert=None)]},
            {'rules': [dict(self.rules[0], admin_state_up=0)]},
            {'rules': [dict(self.rules[0], admin_state_up=None)]},
        ):
            with self.subTest(bad_policy=bad_policy):
                self._post_policy(status=400, **bad_policy)
        self.rpc.cast.assert_not_called()
        with self.session.begin():
            self.assertEqual(0, self.l7policy_repo.count(self.session))
            self.assertEqual(0, self.l7rule_repo.count(self.session))
        rule = {key: self.rules[0][key]
                for key in ('type', 'compare_type', 'value')}
        created = self._post_policy(rules=[rule])['l7policy']
        path = self.L7RULES_PATH.format(l7policy_id=created['id'])
        saved, = self.get(path).json['rules']
        self.assertTrue(saved['admin_state_up'])
        self.assertFalse(saved['invert'])

    def test_replayed_create_ignores_active_policy_after_rule_removed(self):
        policy = self._post_policy()['l7policy']
        payload = self.rpc.cast.call_args.kwargs['l7policy']
        self._dispatch('create_l7policy')
        removed, remaining = policy['rules']
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=removed['id'])
        self.delete(rule_path)
        self._dispatch('delete_l7rule')

        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update') as update:
            endpoints.Endpoints().create_l7policy({}, payload)
        update.assert_not_called()
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        result = self.get(path).json['l7policy']
        self.assertEqual(('ACTIVE', [remaining]),
                         (result['provisioning_status'], result['rules']))

    def test_worker_failure_marks_policy_and_initial_rules_error(self):
        policy = self._post_policy()['l7policy']
        payload = self.rpc.cast.call_args.kwargs['l7policy']
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=RuntimeError('update')):
            with self.assertRaisesRegex(RuntimeError, 'update'):
                endpoints.Endpoints().create_l7policy({}, payload)

        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        saved = self.get(path).json['l7policy']
        self.assertEqual('ERROR', saved['provisioning_status'])
        self.assertFalse(saved['admin_state_up'])
        rules_path = self.L7RULES_PATH.format(l7policy_id=policy['id'])
        rules = self.get(rules_path).json['rules']
        self.assertEqual({'ERROR'}, {r['provisioning_status'] for r in rules})

    def test_initial_rules_require_disabled_policy_and_allow_stock_calls(self):
        self._post_policy(status=400, admin_state_up=True)
        self.conf.config(group='api_settings',
                         enabled_l7policy_initial_rules_providers=[])
        self._post_policy(status=400)
        self.rpc.cast.assert_not_called()

        policy = self._post_policy(rules=[], admin_state_up=True)['l7policy']
        self.rpc.cast.assert_called_once()
        self.assertNotIn('rules', self.rpc.cast.call_args.kwargs['l7policy'])
        self.set_lb_status(self.lb_id)
        self.rpc.cast.reset_mock()
        self.create_l7rule(policy['id'], 'PATH', 'EQUAL_TO', '/stock')
        self.rpc.cast.assert_called_once()
        self.assertEqual('create_l7rule', self.rpc.cast.call_args.args[1])


class TestL7Policy(base.BaseAPITest):

    root_tag = 'l7policy'
    root_tag_list = 'l7policies'
    root_tag_links = 'l7policies_links'

    def setUp(self):
        super().setUp()
        # A few tests use mock provider capabilities to isolate API behavior.
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[
                             'noop_driver', 'noop_driver-alt'])
        self.lb = self.create_load_balancer(uuidutils.generate_uuid())
        self.lb_id = self.lb.get('loadbalancer').get('id')
        self.project_id = self.lb.get('loadbalancer').get('project_id')
        self.set_lb_status(self.lb_id)
        self.listener = self.create_listener(
            constants.PROTOCOL_HTTP, 80, lb_id=self.lb_id)
        self.listener_id = self.listener.get('listener').get('id')
        self.set_lb_status(self.lb_id)
        self.pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN)
        self.pool_id = self.pool.get('pool').get('id')
        self.set_lb_status(self.lb_id)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_request_header_operations', True)
    def test_request_header_operations_read_replace_and_clear(self):
        field = 'request_header_operations'
        operations = [
            {'operation': 'SET', 'name': 'x-tenant', 'value': 'blue'},
            {'operation': 'ADD', 'name': 'x-extra', 'value': ''},
            {'operation': 'REMOVE', 'name': 'x-old'}]
        self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id, status=501,
            **{field: operations})
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=['noop_driver'])
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id,
            **{field: operations})['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual(operations, self.get(path).json['l7policy'][field])
        listing = self.get(self.L7POLICIES_PATH, params={'fields': field})
        self.assertEqual([{field: operations}], listing.json['l7policies'])
        self.get(self.L7POLICIES_PATH, params={
            'sort': field, 'marker': policy['id']}, status=400)
        self.get(self.L7POLICIES_PATH, params={field: 'value'}, status=400)
        self.set_lb_status(self.lb_id)
        renamed = self.put(path, {'l7policy': {'name': 'same filter'}})
        self.assertEqual(operations, renamed.json['l7policy'][field])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {field: [
            {'operation': 'SET', 'name': 'X-Tenant', 'value': 'blue'},
            {'operation': 'REMOVE', 'name': 'x-tenant'}]}}, status=400)
        self.put(path, {'l7policy': {'action': 'REJECT'}}, status=400)
        self.put(path, {'l7policy': {field: None}}, status=400)
        self.assertEqual(operations, self.get(path).json['l7policy'][field])
        replaced = self.put(path, {'l7policy': {field: operations[:1]}})
        self.assertEqual(operations[:1], replaced.json['l7policy'][field])
        self.set_lb_status(self.lb_id)
        self.conf.config(group='api_settings',
                         enabled_request_header_operation_providers=[])
        self.put(path, {'l7policy': {field: operations}}, status=501)
        response = self.put(path, {'l7policy': {
            'action': 'REJECT', field: []}})
        self.assertEqual([], response.json['l7policy'][field])
        self.assertEqual([], self.get(path).json['l7policy'][field])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {field: []}})

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_response_header_operations', True)
    def test_response_operations_require_opt_in_and_can_be_cleared(self):
        field = 'response_header_operations'
        operations = [{'operation': 'SET', 'name': 'x-color', 'value': 'blue'}]
        self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id, status=501, **{field: operations})
        self.conf.config(group='api_settings',
                         enabled_response_header_operation_providers=[
                             'noop_driver'])
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id, **{field: operations})['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual(operations, self.get(path).json['l7policy'][field])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {'name': 'retained'}})
        self.assertEqual(operations, self.get(path).json['l7policy'][field])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {field: [
            {'operation': 'REMOVE', 'name': 'Content-Length'}]}}, status=400)
        self.conf.config(group='api_settings',
                         enabled_response_header_operation_providers=[])
        self.create_l7rule(policy['id'], 'PATH', 'EQUAL_TO', '/', status=501)
        self.put(path, {'l7policy': {field: []}})
        self.assertEqual([], self.get(path).json['l7policy'][field])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_request_header_operations', True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_response_header_operations', True)
    def test_loadbalancer_reopen_checks_active_header_operations(self):
        group = 'api_settings'
        request_flag = 'enabled_request_header_operation_providers'
        response_flag = 'enabled_response_header_operation_providers'
        self.conf.config(group=group, **{
            request_flag: ['noop_driver'], response_flag: ['noop_driver']})
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id,
            request_header_operations=[
                {'operation': 'REMOVE', 'name': 'x-request'}],
            response_header_operations=[
                {'operation': 'SET', 'name': 'x-response', 'value': 'blue'}]
        )['l7policy']
        self.set_lb_status(self.lb_id)
        self.create_l7rule(policy['id'], 'PATH', 'EQUAL_TO', '/')
        self.set_lb_status(self.lb_id)
        lb_path = self.LB_PATH.format(lb_id=self.lb_id)
        listener_path = self.LISTENER_PATH.format(listener_id=self.listener_id)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])

        def set_admin_state(path, resource, enabled, status=200):
            self.put(path, {resource: {'admin_state_up': enabled}},
                     status=status)
            if status == 200:
                self.set_lb_status(self.lb_id)

        set_admin_state(lb_path, 'loadbalancer', False)
        for missing in (response_flag, request_flag):
            self.conf.config(group=group, **{missing: []})
            set_admin_state(lb_path, 'loadbalancer', True, status=501)
            self.assertFalse(
                self.get(lb_path).json['loadbalancer']['admin_state_up'])
            self.conf.config(group=group, **{missing: ['noop_driver']})

        self.conf.config(group=group, **{request_flag: [], response_flag: []})
        set_admin_state(listener_path, 'listener', False)
        set_admin_state(lb_path, 'loadbalancer', True)
        set_admin_state(lb_path, 'loadbalancer', False)
        set_admin_state(policy_path, 'l7policy', False)
        set_admin_state(listener_path, 'listener', True)
        set_admin_state(lb_path, 'loadbalancer', True)

    def test_request_header_operations_require_driver_support(self):
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=['noop_driver'])
        self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id, status=501,
            request_header_operations=[
                {'operation': 'REMOVE', 'name': 'x-old'}])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_request_header_operations', True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_response_header_operations', True)
    def test_nested_policy_returns_independent_header_operations(self):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=[],
            enabled_request_header_operation_providers=['noop_driver'],
            enabled_response_header_operation_providers=['noop_driver'])
        operations = [{'operation': 'REMOVE', 'name': 'X-Old'}]
        response_ops = [{'operation': 'ADD', 'name': 'x-result', 'value': ''}]
        response = self.post(self.LBS_PATH, {'loadbalancer': {
            'project_id': self.project_id,
            'vip_subnet_id': uuidutils.generate_uuid(),
            'listeners': [{
                'protocol': 'HTTP', 'protocol_port': 80,
                'l7policies': [{
                    'action': 'REDIRECT_TO_POOL',
                    'redirect_pool': {'name': 'echo', 'protocol': 'HTTP',
                                      'lb_algorithm': 'ROUND_ROBIN'},
                    'request_header_operations': operations,
                    'response_header_operations': response_ops,
                }],
            }],
        }}).json['loadbalancer']
        policy = response['listeners'][0]['l7policies'][0]
        self.assertEqual([{'operation': 'REMOVE', 'name': 'x-old'}],
                         policy['request_header_operations'])
        self.assertEqual(response_ops, policy['response_header_operations'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_request_header_operations', True)
    def test_stored_header_policy_reactivation_requires_opt_in(self):
        field = 'request_header_operations'
        header_fleets = ['noop_driver']
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=header_fleets)
        operations = [{'operation': 'SET', 'name': 'x-color', 'value': 'blue'}]
        policy_id = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id,
            **{field: operations})['l7policy']['id']
        self.set_lb_status(self.lb_id)
        rule_id = self.create_l7rule(
            policy_id, 'PATH', 'EQUAL_TO', '/shop')['rule']['id']
        self.set_lb_status(self.lb_id)
        self.conf.config(group='api_settings',
                         enabled_request_header_operation_providers=[])
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy_id, l7rule_id=rule_id)
        self.create_l7rule(policy_id, 'PATH', 'EQUAL_TO', '/orders',
                           status=501)
        self.put(rule_path, {'rule': {'value': '/orders'}}, status=501)
        self.put(rule_path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(rule_path, {'rule': {'admin_state_up': True}}, status=501)
        listener_path = self.LISTENER_PATH.format(listener_id=self.listener_id)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}},
                 status=501)
        self.put(policy_path, {'l7policy': {
            'admin_state_up': True, field: []}})
        self.set_lb_status(self.lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}})
        self.set_lb_status(self.lb_id)
        self.put(rule_path, {'rule': {'admin_state_up': True}})
        self.set_lb_status(self.lb_id)
        self.delete(policy_path)

    def test_get(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT,
            tags=['test_tag']).get(self.root_tag)
        response = self.get(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id'))).json.get(self.root_tag)
        self.assertEqual(api_l7policy, response)

    def test_get_authorized(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member', 'member'],
            'user_id': None,
            'is_admin': False,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': self.project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            response = self.get(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')))
            response = response.json.get(self.root_tag)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(api_l7policy, response)

    def test_get_not_authorized(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            response = self.get(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')), status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, response.json)

    def test_get_deleted_gives_404(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)

        self.set_object_status(self.l7policy_repo, api_l7policy.get('id'),
                               provisioning_status=constants.DELETED)
        self.get(self.L7POLICY_PATH.format(l7policy_id=api_l7policy.get('id')),
                 status=404)

    def test_bad_get(self):
        self.get(self.L7POLICY_PATH.format(
            l7policy_id=uuidutils.generate_uuid()), status=404)

    def test_get_all(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            tags=['test_tag']
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        policies = self.get(self.L7POLICIES_PATH).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(1, len(policies))
        self.assertEqual(api_l7policy.get('id'), policies[0].get('id'))
        self.assertEqual(api_l7policy['tags'], policies[0]['tags'])

    def test_get_all_admin(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        listener1 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb1_id)
        listener1_id = listener1.get('listener').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(lb1_id, constants.PROTOCOL_HTTP,
                                 constants.LB_ALGORITHM_ROUND_ROBIN)
        pool1_id = pool1.get('pool').get('id')
        self.set_lb_status(lb1_id)
        api_l7p_a = self.create_l7policy(
            listener1_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_b = self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=pool1_id).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_c = self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            position=3, redirect_url='http://localhost/').get(self.root_tag)
        self.set_lb_status(lb1_id)
        policies = self.get(self.L7POLICIES_PATH).json.get(self.root_tag_list)
        self.assertEqual(3, len(policies))
        policy_id_actions = [(p.get('id'), p.get('action')) for p in policies]
        self.assertIn((api_l7p_a.get('id'), api_l7p_a.get('action')),
                      policy_id_actions)
        self.assertIn((api_l7p_b.get('id'), api_l7p_b.get('action')),
                      policy_id_actions)
        self.assertIn((api_l7p_c.get('id'), api_l7p_c.get('action')),
                      policy_id_actions)

    def test_get_all_non_admin(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        listener1 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb1_id)
        listener1_id = listener1.get('listener').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(lb1_id, constants.PROTOCOL_HTTP,
                                 constants.LB_ALGORITHM_ROUND_ROBIN)
        pool1_id = pool1.get('pool').get('id')
        self.set_lb_status(lb1_id)
        self.create_l7policy(
            listener1_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=pool1_id).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_c = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/').get(self.root_tag)
        self.set_lb_status(lb1_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings',
                         auth_strategy=constants.KEYSTONE)
        test_context = octavia.common.context.RequestContext(
            project_id=api_l7p_c.get('project_id'))
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            override_credentials = {
                'service_user_id': None,
                'user_domain_id': None,
                'is_admin_project': True,
                'service_project_domain_id': None,
                'service_project_id': None,
                'roles': ['load-balancer_member', 'member'],
                'user_id': None,
                'is_admin': False,
                'service_user_domain_id': None,
                'project_domain_id': None,
                'service_roles': [],
                'project_id': self.project_id}
            with mock.patch(
                    "oslo_context.context.RequestContext.to_policy_values",
                    return_value=override_credentials):
                policies = self.get(
                    self.L7POLICIES_PATH).json.get(self.root_tag_list)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assertEqual(1, len(policies))
        policy_id_actions = [(p.get('id'), p.get('action')) for p in policies]
        self.assertIn((api_l7p_c.get('id'), api_l7p_c.get('action')),
                      policy_id_actions)

    def test_get_all_unscoped_token(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        listener1 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb1_id)
        listener1_id = listener1.get('listener').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(lb1_id, constants.PROTOCOL_HTTP,
                                 constants.LB_ALGORITHM_ROUND_ROBIN)
        pool1_id = pool1.get('pool').get('id')
        self.set_lb_status(lb1_id)
        self.create_l7policy(
            listener1_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=pool1_id).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/').get(self.root_tag)
        self.set_lb_status(lb1_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings',
                         auth_strategy=constants.KEYSTONE)
        test_context = octavia.common.context.RequestContext(
            project_id=None)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            override_credentials = {
                'service_user_id': None,
                'user_domain_id': None,
                'is_admin_project': True,
                'service_project_domain_id': None,
                'service_project_id': None,
                'roles': ['load-balancer_member'],
                'user_id': None,
                'is_admin': False,
                'service_user_domain_id': None,
                'project_domain_id': None,
                'service_roles': [],
                'project_id': None}
            with mock.patch(
                    "oslo_context.context.RequestContext.to_policy_values",
                    return_value=override_credentials):
                result = self.get(self.L7POLICIES_PATH, status=403).json
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, result)

    def test_get_all_non_admin_global_observer(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        listener1 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb1_id)
        listener1_id = listener1.get('listener').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(lb1_id, constants.PROTOCOL_HTTP,
                                 constants.LB_ALGORITHM_ROUND_ROBIN)
        pool1_id = pool1.get('pool').get('id')
        self.set_lb_status(lb1_id)
        api_l7p_a = self.create_l7policy(
            listener1_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_b = self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=pool1_id).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_c = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/').get(self.root_tag)
        self.set_lb_status(lb1_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings',
                         auth_strategy=constants.KEYSTONE)
        test_context = octavia.common.context.RequestContext(
            project_id=api_l7p_c.get('project_id'))
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            override_credentials = {
                'service_user_id': None,
                'user_domain_id': None,
                'is_admin_project': True,
                'service_project_domain_id': None,
                'service_project_id': None,
                'roles': ['admin'],
                'user_id': None,
                'is_admin': False,
                'service_user_domain_id': None,
                'project_domain_id': None,
                'service_roles': [],
                'project_id': self.project_id}
            with mock.patch(
                    "oslo_context.context.RequestContext.to_policy_values",
                    return_value=override_credentials):
                policies = self.get(
                    self.L7POLICIES_PATH).json.get(self.root_tag_list)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assertEqual(3, len(policies))
        policy_id_actions = [(p.get('id'), p.get('action')) for p in policies]
        self.assertIn((api_l7p_a.get('id'), api_l7p_a.get('action')),
                      policy_id_actions)
        self.assertIn((api_l7p_b.get('id'), api_l7p_b.get('action')),
                      policy_id_actions)
        self.assertIn((api_l7p_c.get('id'), api_l7p_c.get('action')),
                      policy_id_actions)

    def test_get_all_not_authorized(self):
        self.create_l7policy(self.listener_id,
                             constants.L7POLICY_ACTION_REJECT,
                             ).get(self.root_tag)
        self.set_lb_status(self.lb_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            policies = self.get(self.L7POLICIES_PATH, status=403).json

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, policies)

    def test_get_all_hides_deleted(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)

        response = self.get(self.L7POLICIES_PATH)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 1)
        self.set_object_status(self.l7policy_repo, api_l7policy.get('id'),
                               provisioning_status=constants.DELETED)
        response = self.get(self.L7POLICIES_PATH)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 0)

    def test_get_by_project_id(self):
        project1_id = uuidutils.generate_uuid()
        project2_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project1_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        lb2 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb2',
                                        project_id=project2_id)
        lb2_id = lb2.get('loadbalancer').get('id')
        self.set_lb_status(lb2_id)
        listener1 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb1_id)
        listener1_id = listener1.get('listener').get('id')
        self.set_lb_status(lb1_id)
        listener2 = self.create_listener(constants.PROTOCOL_HTTP, 80,
                                         lb2_id)
        listener2_id = listener2.get('listener').get('id')
        self.set_lb_status(lb2_id)
        pool1 = self.create_pool(lb1_id, constants.PROTOCOL_HTTP,
                                 constants.LB_ALGORITHM_ROUND_ROBIN)
        pool1_id = pool1.get('pool').get('id')
        self.set_lb_status(lb1_id)
        api_l7p_a = self.create_l7policy(
            listener1_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_b = self.create_l7policy(
            listener1_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=pool1_id).get(self.root_tag)
        self.set_lb_status(lb1_id)
        api_l7p_c = self.create_l7policy(
            listener2_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/').get(self.root_tag)
        self.set_lb_status(lb2_id)
        policies = self.get(
            self.L7POLICIES_PATH,
            params={'project_id': project1_id}).json.get(self.root_tag_list)

        self.assertEqual(2, len(policies))
        policy_id_actions = [(p.get('id'), p.get('action')) for p in policies]
        self.assertIn((api_l7p_a.get('id'), api_l7p_a.get('action')),
                      policy_id_actions)
        self.assertIn((api_l7p_b.get('id'), api_l7p_b.get('action')),
                      policy_id_actions)
        policies = self.get(
            self.L7POLICIES_PATH,
            params={'project_id': project2_id}).json.get(self.root_tag_list)
        self.assertEqual(1, len(policies))
        policy_id_actions = [(p.get('id'), p.get('action')) for p in policies]
        self.assertIn((api_l7p_c.get('id'), api_l7p_c.get('action')),
                      policy_id_actions)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    def test_weighted_targets_list_projection_and_query_fields(self):
        targets = [{'weight': 1, 'fixed_response': {'status_code': 500}}]
        self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                             targets=targets)
        result = self.get(self.L7POLICIES_PATH, params={'fields': 'targets'})
        self.assertEqual([{'targets': targets}], result.json['l7policies'])
        for query in ({'sort': 'targets'}, {'sort_key': 'targets.weight'},
                      {'targets': 'value'}):
            with self.subTest(query=query):
                self.get(self.L7POLICIES_PATH, params=query, status=400)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_fixed_http_responses', True)
    def test_fixed_response_list_projection_and_query_fields(self):
        response = {'status_code': 500}
        policy_id = self.create_l7policy(
            self.listener_id, 'FIXED_RESPONSE',
            fixed_response=response)['l7policy']['id']
        listing = self.get(
            self.L7POLICIES_PATH, params={'fields': 'fixed_response'})
        self.assertEqual([{'fixed_response': response}],
                         listing.json['l7policies'])
        for query in (
                {'fixed_response': 'value'},
                {'fixed_response.status_code': '500'},
                {'sort': 'fixed_response'},
                {'sort_key': 'fixed_response.status_code',
                 'marker': policy_id}):
            with self.subTest(query=query):
                self.get(self.L7POLICIES_PATH, params=query, status=400)

    def test_get_all_sorted(self):
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            name='policy3').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=self.pool_id,
            name='policy2').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/',
            name='policy1').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        response = self.get(self.L7POLICIES_PATH,
                            params={'sort': 'position:desc'})
        policies_desc = response.json.get(self.root_tag_list)
        response = self.get(self.L7POLICIES_PATH,
                            params={'sort': 'position:asc'})
        policies_asc = response.json.get(self.root_tag_list)

        self.assertEqual(3, len(policies_desc))
        self.assertEqual(3, len(policies_asc))

        policy_id_names_desc = [(policy.get('id'), policy.get('position'))
                                for policy in policies_desc]
        policy_id_names_asc = [(policy.get('id'), policy.get('position'))
                               for policy in policies_asc]
        self.assertEqual(policy_id_names_asc,
                         list(reversed(policy_id_names_desc)))

    def test_get_all_limited(self):
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            name='policy1').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=self.pool_id,
            name='policy2').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/',
            name='policy3').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        # First two -- should have 'next' link
        first_two = self.get(self.L7POLICIES_PATH, params={'limit': 2}).json
        objs = first_two[self.root_tag_list]
        links = first_two[self.root_tag_links]
        self.assertEqual(2, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('next', links[0]['rel'])

        # Third + off the end -- should have previous link
        third = self.get(self.L7POLICIES_PATH, params={
            'limit': 2,
            'marker': first_two[self.root_tag_list][1]['id']}).json
        objs = third[self.root_tag_list]
        links = third[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('previous', links[0]['rel'])

        # Middle -- should have both links
        middle = self.get(self.L7POLICIES_PATH, params={
            'limit': 1,
            'marker': first_two[self.root_tag_list][0]['id']}).json
        objs = middle[self.root_tag_list]
        links = middle[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(2, len(links))
        self.assertCountEqual(['previous', 'next'],
                              [link['rel'] for link in links])

    def test_get_all_fields_filter(self):
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            name='policy1').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=self.pool_id,
            name='policy2').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/',
            name='policy3').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7pos = self.get(self.L7POLICIES_PATH, params={
            'fields': ['id', 'project_id']}).json
        for l7po in l7pos['l7policies']:
            self.assertIn('id', l7po)
            self.assertIn('project_id', l7po)
            self.assertNotIn('description', l7po)

    def test_get_one_fields_filter(self):
        l7p1 = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            name='policy1').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7po = self.get(
            self.L7POLICY_PATH.format(l7policy_id=l7p1.get('id')),
            params={'fields': ['id', 'project_id']}).json.get(self.root_tag)
        self.assertIn('id', l7po)
        self.assertIn('project_id', l7po)
        self.assertNotIn('description', l7po)

    def test_get_all_filter(self):
        policy1 = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            name='policy1').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=self.pool_id,
            name='policy2').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/',
            name='policy3').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7pos = self.get(self.L7POLICIES_PATH, params={
            'id': policy1['id']}).json
        self.assertEqual(1, len(l7pos['l7policies']))
        self.assertEqual(policy1['id'],
                         l7pos['l7policies'][0]['id'])

    def test_get_all_tags_filter(self):
        policy1 = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT,
            tags=['test_tag1', 'test_tag2']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        policy2 = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            position=2, redirect_pool_id=self.pool_id,
            tags=['test_tag2', 'test_tag3']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        policy3 = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://localhost/',
            tags=['test_tag4', 'test_tag5']).get(self.root_tag)
        self.set_lb_status(self.lb_id)

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(2, len(policies))
        self.assertEqual(
            [policy1.get('id'), policy2.get('id')],
            [policy.get('id') for policy in policies]
        )

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'tags': ['test_tag2', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(1, len(policies))
        self.assertEqual(
            [policy2.get('id')],
            [policy.get('id') for policy in policies]
        )

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'tags-any': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(2, len(policies))
        self.assertEqual(
            [policy1.get('id'), policy2.get('id')],
            [policy.get('id') for policy in policies]
        )

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(1, len(policies))
        self.assertEqual(
            [policy3.get('id')],
            [policy.get('id') for policy in policies]
        )

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'not-tags-any': ['test_tag2', 'test_tag4']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(0, len(policies))

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'tags': 'test_tag2',
                    'tags-any': ['test_tag1', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(2, len(policies))
        self.assertEqual(
            [policy1.get('id'), policy2.get('id')],
            [policy.get('id') for policy in policies]
        )

        policies = self.get(
            self.L7POLICIES_PATH,
            params={'tags': 'test_tag2', 'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(policies, list)
        self.assertEqual(0, len(policies))

    def test_empty_get_all(self):
        response = self.get(self.L7POLICIES_PATH).json.get(self.root_tag_list)
        self.assertIsInstance(response, list)
        self.assertEqual(0, len(response))

    def test_create_reject_policy(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REJECT,
                         api_l7policy['action'])
        self.assertEqual(1, api_l7policy['position'])
        self.assertIsNone(api_l7policy['redirect_pool_id'])
        self.assertIsNone(api_l7policy['redirect_url'])
        self.assertTrue(api_l7policy['admin_state_up'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_CREATE,
            l7policy_op_status=constants.OFFLINE)

    def test_create_policy_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)

        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member', 'member'],
            'user_id': None,
            'is_admin': False,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': self.project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            api_l7policy = self.create_l7policy(
                self.listener_id,
                constants.L7POLICY_ACTION_REJECT).get(self.root_tag)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(constants.L7POLICY_ACTION_REJECT,
                         api_l7policy['action'])
        self.assertEqual(1, api_l7policy['position'])
        self.assertIsNone(api_l7policy['redirect_pool_id'])
        self.assertIsNone(api_l7policy['redirect_url'])
        self.assertTrue(api_l7policy['admin_state_up'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_CREATE,
            l7policy_op_status=constants.OFFLINE)

    def test_create_policy_not_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)

        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            api_l7policy = self.create_l7policy(
                self.listener_id,
                constants.L7POLICY_ACTION_REJECT, status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, api_l7policy)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_amphora_gateway_actions_require_opt_in(self, get_client):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.set_lb_status(lb['id'])
        listener = self.create_listener('HTTP', 80, lb['id'])['listener']
        self.set_lb_status(lb['id'])
        policy = self.create_l7policy(
            listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb['id'])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        response = {'status_code': 500}
        get_client.return_value.cast.reset_mock()
        for action, fields in (
                ('FIXED_RESPONSE', {'fixed_response': response}),
                ('WEIGHTED_TARGETS', {
                    'targets': [{'weight': 1, 'fixed_response': response}]})):
            with self.subTest(action=action):
                self.create_l7policy(listener['id'], action,
                                     status=501, **fields)
                self.put(policy_path, {'l7policy': {'action': action,
                                                    **fields}}, status=501)
        get_client.return_value.cast.assert_not_called()
        self.assertEqual('REJECT',
                         self.get(policy_path).json['l7policy']['action'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_request_redirect_round_trip_and_regional_lifecycle(self, rpc):
        lb_response = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')
        lb = lb_response['loadbalancer']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        redirect = {'scheme': 'https', 'port': 443, 'replace_prefix': {
            'match': '/old', 'replacement': ''}}
        stock = self.create_l7policy(
            listener, 'REDIRECT_PREFIX',
            redirect_prefix='https://legacy.example.test')['l7policy']
        self.set_lb_status(lb)
        self.assertNotIn('redirect_request', stock)
        path = self.L7POLICY_PATH.format(l7policy_id=stock['id'])
        values = {'action': 'REDIRECT_REQUEST', 'redirect_request': redirect}
        rpc.return_value.cast.reset_mock()
        self.create_l7policy(listener, 'REDIRECT_REQUEST',
                             redirect_request=redirect, status=501)
        self.put(path, {'l7policy': values}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_http_request_redirect_providers=['amphora'])
        for invalid in ({'port': '443'}, {'hostname': 'example.test:443'},
                        {'replace_full_path': '/'}, {'template': '%[url]'}):
            with self.subTest(invalid=invalid):
                self.create_l7policy(listener, 'REDIRECT_REQUEST', status=400,
                                     redirect_request=redirect | invalid)
        result = self.put(path, {'l7policy': values}).json['l7policy']
        self.assertIsNone(result['redirect_prefix'])
        self.assertEqual(302, result['redirect_http_code'])
        self.assertEqual(redirect, result['redirect_request'])
        self.set_lb_status(lb)
        rule = self.create_l7rule(stock['id'], 'PATH', 'STARTS_WITH', '/')
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=stock['id'], l7rule_id=rule['rule']['id'])
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'redirect_http_code': 308}})
        self.set_lb_status(lb)
        self.assertEqual(redirect, self.get(path).json['l7policy'][
            'redirect_request'])
        self.conf.config(group='api_settings',
                         enabled_http_request_redirect_providers=[])
        rpc.return_value.cast.reset_mock()
        self.put(path, {'l7policy': {'redirect_http_code': 307}}, status=501)
        self.put(rule_path, {'rule': {'value': '/new'}}, status=501)
        self.assertEqual(308, self.get(path).json['l7policy'][
            'redirect_http_code'])
        rpc.return_value.cast.assert_not_called()
        listener_path = self.LISTENER_PATH.format(listener_id=listener)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        lb_path = self.LB_PATH.format(lb_id=lb)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': False}})
        self.set_lb_status(lb)
        # Reopen the listener with the extension temporarily enrolled so
        # reopening the load balancer exercises the active redirect check.
        self.conf.config(group='api_settings',
                         enabled_http_request_redirect_providers=['amphora'])
        self.put(listener_path, {'listener': {'admin_state_up': True}})
        self.set_lb_status(lb)
        self.conf.config(group='api_settings',
                         enabled_http_request_redirect_providers=[])
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}},
                 status=501)
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        stock_update = {'l7policy': {
            'redirect_url': 'https://stock.example.test/new'}}
        result = self.put(path, stock_update).json['l7policy']
        self.assertEqual('REDIRECT_TO_URL', result['action'])
        self.assertNotIn('redirect_request', result)
        self.set_lb_status(lb)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_redirect_scope_withdrawal_blocks_widening_of_active_policy(
            self, cert_data, rpc):
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='cert 1')}
        self.conf.config(
            group='api_settings',
            enabled_https_listener_isolation_providers=['amphora'],
            enabled_gateway_action_providers=['amphora'],
            enabled_http_request_redirect_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.set_lb_status(lb['id'])
        listener = self.create_listener(
            'TERMINATED_HTTPS', 443, lb['id'],
            default_tls_container_ref=uuidutils.generate_uuid(),
            default_http_response={'status_code': 404},
            https_virtual_hosts=['a.example.test', 'b.example.test']
        )['listener']
        self.set_lb_status(lb['id'])
        policy = self.create_l7policy(
            listener['id'], 'REDIRECT_REQUEST',
            redirect_request={'scheme': 'https', 'port': 443},
            https_listener_hostname='a.example.test')['l7policy']
        self.set_lb_status(lb['id'])
        rule = self.create_l7rule(
            policy['id'], 'PATH', 'EQUAL_TO', '/protected')['rule']
        self.set_lb_status(lb['id'])
        self.create_l7rule(policy['id'], 'HEADER', 'EQUAL_TO', 'yes',
                           key='x-test')
        self.set_lb_status(lb['id'])
        rule_path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                            l7rule_id=rule['id'])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        self.conf.config(group='api_settings',
                         enabled_http_request_redirect_providers=[])
        rpc.return_value.cast.reset_mock()
        self.put(rule_path, {'rule': {'admin_state_up': False}}, status=501)
        self.delete(rule_path, status=501)
        self.put(policy_path, {'l7policy': {
            'https_listener_hostname': 'b.example.test'}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertTrue(self.get(rule_path).json['rule']['admin_state_up'])
        self.assertEqual('a.example.test', self.get(policy_path).json[
            'l7policy']['https_listener_hostname'])
        self.put(rule_path, {'rule': {'tags': ['maintenance']}})
        self.set_lb_status(lb['id'])
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb['id'])
        self.delete(rule_path)
        self.set_lb_status(lb['id'])
        self.delete(policy_path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_weighted_target_filters_round_trip_and_cleanup(self, rpc):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb = lb['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        action = 'WEIGHTED_TARGETS'
        ordinary = {'weight': 1, 'pool_id': pool}
        stock = self.create_l7policy(listener, action, targets=[ordinary])
        self.assertEqual([ordinary], stock['l7policy']['targets'])
        self.set_lb_status(lb)

        operations = [{'operation': 'SET', 'name': 'x-filter',
                       'value': 'second'}]
        targets = [
            ordinary | {'request_url_rewrite': {'hostname': 'first.example'}},
            ordinary | {'request_header_operations': operations},
            {'weight': 1, 'fixed_response': {'status_code': 500}}]
        rpc.return_value.cast.reset_mock()
        self.create_l7policy(listener, action, targets=targets, status=501)
        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[
                             'amphora'])
        self.create_l7policy(
            listener, action, status=400,
            targets=[targets[2] | {'request_header_operations': operations}])
        self.create_l7policy(
            listener, action, status=400,
            targets=[ordinary | {'request_url_rewrite': {
                'hostname': '*.invalid'}}])
        self.create_l7policy(
            listener, action, status=400,
            targets=[targets[0] | {'request_header_operations': [
                {'operation': 'ADD', 'name': 'HOST', 'value': 'other.test'}]}])
        rpc.return_value.cast.assert_not_called()

        policy = self.create_l7policy(
            listener, action, targets=targets)['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])
        self.set_lb_status(lb)
        # Both scopes can rewrite different parts of the URL.
        rewrite = {'replace_full_path': '/policy'}
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=['amphora'])
        updated = self.put(path, {'l7policy': {
            'request_url_rewrite': rewrite, 'targets': targets}}).json
        self.assertEqual(rewrite, updated['l7policy']['request_url_rewrite'])
        self.assertEqual(targets, rpc.return_value.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES]['targets'])
        self.set_lb_status(lb)
        rpc.return_value.cast.reset_mock()
        self.put(path, {'l7policy': {'targets': [
            ordinary | {'request_url_rewrite': {'replace_prefix': {
                'match': '/', 'replacement': '/target'}}}]}}, status=400)
        self.put(path, {'l7policy': {'request_url_rewrite': {
            'hostname': 'second.example'}}}, status=400)
        rpc.return_value.cast.assert_not_called()

        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[])
        self.put(path, {'l7policy': {'targets': [targets[0]]}}, status=501)
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])
        # Withdrawing A's rewrite leaves B's selected range and headers intact.
        remaining = [ordinary, targets[1], targets[2]]
        self.put(path, {'l7policy': {'targets': remaining}})
        self.set_lb_status(lb)
        self.assertEqual(remaining, self.get(path).json['l7policy']['targets'])
        self.put(path, {'l7policy': {'targets': [
            targets[1], ordinary, targets[2]]}}, status=501)

        narrower = [ordinary | {'weight': 2}, targets[1],
                    targets[2] | {'weight': 2}]
        self.put(path, {'l7policy': {'targets': narrower}})
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'targets': remaining}}, status=501)

        # A filter on a zero-weight occurrence stays dormant on activation.
        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[
                             'amphora'])
        dormant = [ordinary, targets[1] | {'weight': 0}]
        self.put(path, {'l7policy': {'targets': dormant,
                                     'admin_state_up': False}})
        self.set_lb_status(lb)
        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[])
        self.put(path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb)
        state = self.get(path).json['l7policy']
        self.assertTrue(state['admin_state_up'])
        self.assertEqual(dormant, state['targets'])
        self.put(path, {'l7policy': {'targets': [ordinary, targets[1]]}},
                 status=501)
        cleared = self.put(path, {'l7policy': {'targets': [ordinary]}}).json
        self.assertEqual([ordinary], cleared['l7policy']['targets'])
        self.assertEqual(
            [ordinary], self.get(path).json['l7policy']['targets'])
        self.set_lb_status(lb)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_weighted_target_filters_withdrawal_preserves_routing(self, rpc):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_weighted_target_request_filter_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb = lb['id']
        self.set_lb_status(lb)

        def pool():
            pool_id = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
            self.set_lb_status(lb)
            return pool_id

        default_pool, filtered_pool = pool(), pool()
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)

        def policy(action, **options):
            policy_id = self.create_l7policy(
                listener, action, **options)['l7policy']['id']
            self.set_lb_status(lb)
            rule = self.create_l7rule(
                policy_id, 'PATH', 'STARTS_WITH', '/original')['rule']
            self.set_lb_status(lb)
            return (self.L7POLICY_PATH.format(l7policy_id=policy_id),
                    self.L7RULE_PATH.format(l7policy_id=policy_id,
                                            l7rule_id=rule['id']))

        blocker, blocker_rule = policy(
            'REDIRECT_TO_POOL', redirect_pool_id=default_pool)
        filtered, filtered_rule = policy(
            'WEIGHTED_TARGETS', targets=[
                {'weight': 1, 'pool_id': filtered_pool,
                 'request_url_rewrite': {'replace_full_path': '/new'}}])
        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[])
        rpc.return_value.cast.reset_mock()
        self.delete(blocker_rule, status=501)
        self.delete(blocker, status=501)
        self.put(blocker, {'l7policy': {'position': 2}}, status=501)
        self.put(filtered_rule, {'rule': {'value': '/other'}}, status=501)
        rpc.return_value.cast.assert_not_called()

        pool_path = self.POOL_PATH.format(pool_id=filtered_pool)
        self.put(pool_path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(filtered, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(filtered, {'l7policy': {'admin_state_up': True}}, status=501)
        self.delete(filtered_rule)
        self.set_lb_status(lb)
        self.delete(filtered)
        self.set_lb_status(lb)
        self.delete(blocker)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_cors_withdrawal_protects_unavailable_targets(self, rpc):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_request_cors_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb = lb['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        pool = self.create_pool(
            lb, 'HTTP', 'ROUND_ROBIN', admin_state_up=False)['pool']['id']
        self.set_lb_status(lb)

        blocker = self.create_l7policy(
            listener, 'REJECT', position=1)['l7policy']['id']
        self.set_lb_status(lb)
        self.create_l7rule(blocker, 'PATH', 'STARTS_WITH', '/hidden')
        self.set_lb_status(lb)
        cors = {'allow_origins': ['https://client.test']}
        policy = self.create_l7policy(
            listener, 'WEIGHTED_TARGETS', position=2, request_cors=cors,
            targets=[{'weight': 1, 'pool_id': pool}])['l7policy']
        self.set_lb_status(lb)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        rule = self.create_l7rule(
            policy['id'], 'PATH', 'STARTS_WITH', '/')['rule']
        self.set_lb_status(lb)
        self.create_l7rule(
            policy['id'], 'HEADER', 'EQUAL_TO', 'yes', key='X-Custom')
        self.set_lb_status(lb)

        self.conf.config(group='api_settings',
                         enabled_request_cors_providers=[])
        rpc.return_value.cast.reset_mock()
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=rule['id'])
        self.put(rule_path, {'rule': {'value': '/different'}}, status=501)
        self.delete(rule_path, status=501)
        self.delete(self.L7POLICY_PATH.format(l7policy_id=blocker),
                    status=501)
        self.put(policy_path, {'l7policy': {'request_cors': {
            'allow_origins': ['*']}}}, status=501)
        rpc.return_value.cast.assert_not_called()

        listener_path = self.LISTENER_PATH.format(listener_id=listener)
        lb_path = self.LB_PATH.format(lb_id=lb)
        for path, resource in ((listener_path, 'listener'),
                               (lb_path, 'loadbalancer'),
                               (policy_path, 'l7policy')):
            self.put(path, {resource: {'admin_state_up': False}})
            self.set_lb_status(lb)
            self.put(path, {resource: {'admin_state_up': True}}, status=501)
            self.conf.config(group='api_settings',
                             enabled_request_cors_providers=['amphora'])
            self.put(path, {resource: {'admin_state_up': True}})
            self.set_lb_status(lb)
            self.conf.config(group='api_settings',
                             enabled_request_cors_providers=[])

        stored = self.get(policy_path).json['l7policy']
        self.assertEqual(cors, stored['request_cors'])
        self.put(policy_path, {'l7policy': {'request_cors': None}})
        self.set_lb_status(lb)
        self.delete(rule_path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_cors_withdrawal_accounts_for_closed_backend_tls_pool(self, rpc):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_backend_tls_h2_alpn_providers=['amphora'],
            enabled_request_cors_providers=['amphora'])
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']['id']
        self.set_lb_status(lb_id)

        tag = constants.GATEWAY_BACKEND_TLS_POOL_TAG
        pool = self.create_pool(
            lb_id, 'HTTP', 'ROUND_ROBIN', tls_enabled=True,
            ca_tls_container_ref=uuidutils.generate_uuid(),
            backend_tls_hostname='backend.example.test',
            backend_tls_require_h2=True, tags=[tag])['pool']
        self.assertIs(True, pool['backend_tls_require_h2'])
        self.set_lb_status(lb_id)
        sibling = self.create_pool(lb_id, 'HTTP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)

        policy_paths = []
        for position, pool_id in enumerate((pool['id'], sibling['id']), 1):
            policy = self.create_l7policy(
                listener, 'REDIRECT_TO_POOL', redirect_pool_id=pool_id,
                position=position, request_cors={})['l7policy']
            self.set_lb_status(lb_id)
            self.create_l7rule(policy['id'], 'PATH', 'STARTS_WITH', '/')
            self.set_lb_status(lb_id)
            policy_paths.append(self.L7POLICY_PATH.format(
                l7policy_id=policy['id']))
        blocker, fallback = policy_paths
        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        self.conf.config(group='api_settings',
                         enabled_request_cors_providers=[])

        def put_pool(**updates):
            self.put(pool_path, {'pool': updates})
            self.set_lb_status(lb_id)

        # Both disabling and reopening preserve the first policy's choice.
        put_pool(admin_state_up=False)
        put_pool(admin_state_up=True)
        put_pool(admin_state_up=False)
        rpc.return_value.cast.reset_mock()
        self.delete(blocker, status=501)
        remove_tls = dict(backend_tls_hostname=None, tls_enabled=False,
                          ca_tls_container_ref=None)
        self.put(pool_path, {'pool': dict(
            remove_tls, backend_tls_require_h2=False, tags=[])},
            status=501)
        rpc.return_value.cast.assert_not_called()

        # Draining strict h2 preserves both CORS routing markers.
        put_pool(backend_tls_require_h2=False)
        self.assertIs(False, self.get(pool_path).json['pool'][
            'backend_tls_require_h2'])

        # Either marker suffices. Removing the last one changes selection.
        put_pool(**remove_tls)
        rpc.return_value.cast.reset_mock()
        self.delete(blocker, status=501)
        self.put(pool_path, {'pool': {'tags': []}}, status=501)
        rpc.return_value.cast.assert_not_called()

        self.put(fallback, {'l7policy': {'request_cors': None}})
        self.set_lb_status(lb_id)
        put_pool(tags=[])
        # Reattaching a marker would expose the first policy's dormant CORS.
        self.put(pool_path, {'pool': {'tags': [tag]}}, status=501)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_request_url_rewrite_round_trip_and_withdrawal(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        field = 'request_url_rewrite'
        rewrite = {'hostname': 'backend.example', 'replace_prefix': {
            'match': '/one', 'replacement': ''}}
        target = {'redirect_pool_id': pool}
        self.create_l7policy(listener, 'REDIRECT_TO_POOL', status=501,
                             **target, request_url_rewrite=rewrite)
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=['amphora'])
        for invalid in ({}, {'scheme': 'https'}, {'hostname': '*.example'},
                        {'replace_full_path': 42},
                        {'replace_prefix': {'match': '/x%2fy',
                                            'replacement': '/'}},
                        rewrite | {'replace_full_path': '/'}):
            with self.subTest(invalid=invalid):
                self.create_l7policy(
                    listener, 'REDIRECT_TO_POOL', status=400, **target,
                    request_url_rewrite=invalid)
        self.create_l7policy(listener, 'REJECT', status=400,
                             request_url_rewrite=rewrite)
        tcp = self.create_listener('TCP', 81, lb)['listener']['id']
        self.set_lb_status(lb)
        self.create_l7policy(tcp, 'REDIRECT_TO_POOL', status=400, **target,
                             request_url_rewrite=rewrite)

        policy = self.create_l7policy(listener, 'REDIRECT_TO_POOL',
                                      **target)['l7policy']
        self.assertNotIn(field, policy)
        self.set_lb_status(lb)
        policy_id = policy['id']
        path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        rpc.return_value.cast.reset_mock()
        persisted = self.put(path, {'l7policy': {field: rewrite}})
        self.assertEqual(rewrite, persisted.json['l7policy'][field])
        self.assertEqual(rewrite, self.get(path).json['l7policy'][field])
        updates = rpc.return_value.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES]
        self.assertEqual(rewrite, updates[field])
        self.set_lb_status(lb)
        rule = self.create_l7rule(policy_id, 'PATH', 'STARTS_WITH', '/one')
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy_id, l7rule_id=rule['rule']['id'])
        self.set_lb_status(lb)
        self.create_l7rule(policy_id, 'HEADER', 'EQUAL_TO', 'yes', key='x-test')
        self.set_lb_status(lb)

        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=[])
        rpc.return_value.cast.reset_mock()
        self.put(rule_path, {'rule': {'value': '/two'}}, status=501)
        self.put(rule_path, {'rule': {'admin_state_up': False}}, status=501)
        self.delete(rule_path, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertTrue(self.get(rule_path).json['rule']['admin_state_up'])
        self.assertEqual(rewrite, self.get(path).json['l7policy'][field])

        lb_path = self.LB_PATH.format(lb_id=lb)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}},
                 status=501)
        pool_path = self.POOL_PATH.format(pool_id=pool)
        self.put(pool_path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}})
        self.set_lb_status(lb)
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        listener_path = self.LISTENER_PATH.format(listener_id=listener)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(listener_path, {'listener': {'admin_state_up': True}})
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        rpc.return_value.cast.reset_mock()
        cleared = self.put(path, {'l7policy': {field: None}})
        self.assertNotIn(field, cleared.json['l7policy'])
        updates = rpc.return_value.cast.call_args.kwargs[
            constants.L7POLICY_UPDATES]
        self.assertIsNone(updates[field])
        self.set_lb_status(lb)
        self.delete(rule_path)
        self.set_lb_status(lb)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_withdrawal_protects_rewrite_behind_an_ordinary_policy(self, rpc):
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=['amphora'],
                         enabled_http_request_redirect_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb = lb['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        rewrite_pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']
        rewrite_pool = rewrite_pool['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)

        def policy(pool_id, *, prefix='/one', **fields):
            policy_id = self.create_l7policy(
                listener, 'REDIRECT_TO_POOL', redirect_pool_id=pool_id,
                **fields)['l7policy']['id']
            self.set_lb_status(lb)
            rule = self.create_l7rule(
                policy_id, 'PATH', 'STARTS_WITH', prefix)['rule']
            self.set_lb_status(lb)
            return policy_id, self.L7RULE_PATH.format(
                l7policy_id=policy_id, l7rule_id=rule['id'])

        blocker, blocker_rule = policy(pool, position=1,
                                       prefix='/one/protected')
        rewrite, _ = policy(rewrite_pool, position=2,
                            request_url_rewrite={'hostname': 'next.example'})
        lower, _ = policy(pool, position=3)
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=[])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=blocker)
        rpc.return_value.cast.reset_mock()
        self.put(policy_path, {'l7policy': {'position': 2}}, status=501)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}},
                 status=501)
        self.put(blocker_rule, {'rule': {'value': '/different'}}, status=501)
        self.create_l7rule(blocker, 'HEADER', 'EQUAL_TO', 'yes',
                           key='x-narrow', status=501)
        self.delete(blocker_rule, status=501)
        self.delete(policy_path, status=501)
        self.put(self.POOL_PATH.format(pool_id=pool),
                 {'pool': {'admin_state_up': False}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.delete(self.L7POLICY_PATH.format(l7policy_id=lower))
        self.set_lb_status(lb)
        legacy = self.create_l7policy(
            listener, 'REDIRECT_TO_URL',
            redirect_url='https://legacy.example')['l7policy']['id']
        self.set_lb_status(lb)
        self.create_l7rule(legacy, 'PATH', 'STARTS_WITH', '/one')
        self.set_lb_status(lb)
        structured = self.create_l7policy(
            listener, 'REDIRECT_REQUEST',
            redirect_request={'scheme': 'https', 'port': 443})['l7policy']
        self.set_lb_status(lb)
        rpc.return_value.cast.reset_mock()
        self.create_l7rule(
            structured['id'], 'PATH', 'STARTS_WITH', '/one', status=501)
        rpc.return_value.cast.assert_not_called()
        self.put(self.L7POLICY_PATH.format(l7policy_id=rewrite),
                 {'l7policy': {'request_url_rewrite': None}})
        self.set_lb_status(lb)
        self.delete(policy_path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_withdrawal_protects_wildcard_rewrite_when_exact_host_is_removed(
            self, cert_data, rpc):
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='cert 1')}
        self.conf.config(
            group='api_settings',
            enabled_request_url_rewrite_providers=['amphora'],
            enabled_https_listener_isolation_providers=['amphora'],
            enabled_gateway_action_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb = lb['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        listener = self.create_listener(
            'TERMINATED_HTTPS', 443, lb,
            default_tls_container_ref=uuidutils.generate_uuid(),
            default_http_response={'status_code': 404},
            https_virtual_hosts=['exact.example.test', '*.example.test'],
        )['listener']['id']
        self.set_lb_status(lb)
        policy = self.create_l7policy(
            listener, 'REDIRECT_TO_POOL', redirect_pool_id=pool,
            https_listener_hostname='*.example.test',
            request_url_rewrite={'hostname': 'next.example'})['l7policy']['id']
        self.set_lb_status(lb)
        rule = self.create_l7rule(policy, 'PATH', 'STARTS_WITH', '/')['rule']
        self.set_lb_status(lb)
        self.conf.config(group='api_settings',
                         enabled_request_url_rewrite_providers=[])
        path = self.LISTENER_PATH.format(listener_id=listener)
        rpc.return_value.cast.reset_mock()
        self.put(path, {'listener': {
            'https_virtual_hosts': ['*.example.test']}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.put(self.L7RULE_PATH.format(
            l7policy_id=policy, l7rule_id=rule['id']),
            {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(path, {'listener': {
            'https_virtual_hosts': ['*.example.test'], 'admin_state_up': False}})
        self.set_lb_status(lb)
        self.put(path, {'listener': {'admin_state_up': True}})
        self.assertEqual({'hostname': 'next.example'}, self.get(
            self.L7POLICY_PATH.format(l7policy_id=policy)).json[
                'l7policy']['request_url_rewrite'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_amphora_stored_actions_can_be_removed_after_disabling(self, _rpc):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.set_lb_status(lb['id'])
        listener = self.create_listener('HTTP', 80, lb['id'])['listener']
        self.set_lb_status(lb['id'])
        response = {'status_code': 500}
        targets = [{'weight': 1, 'fixed_response': response}]
        fixed = self.create_l7policy(listener['id'], 'FIXED_RESPONSE',
                                     fixed_response=response)['l7policy']
        self.set_lb_status(lb['id'])
        weighted = self.create_l7policy(listener['id'], 'WEIGHTED_TARGETS',
                                        targets=targets)['l7policy']
        self.set_lb_status(lb['id'])
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[])
        fixed_path = self.L7POLICY_PATH.format(l7policy_id=fixed['id'])
        weighted_path = self.L7POLICY_PATH.format(l7policy_id=weighted['id'])
        self.put(fixed_path, {'l7policy': {
            'fixed_response': {'status_code': 404}}}, status=501)
        self.put(weighted_path, {'l7policy': {
            'targets': [{'weight': 2, 'fixed_response': response}]}},
            status=501)
        retained = self.put(weighted_path, {
            'l7policy': {'name': 'retained'}}).json['l7policy']
        self.assertEqual(targets, retained['targets'])
        self.set_lb_status(lb['id'])
        cleared = self.put(fixed_path, {'l7policy': {
            'action': 'REJECT', 'fixed_response': None}}).json['l7policy']
        self.assertEqual('REJECT', cleared['action'])
        self.assertIsNone(cleared.get('fixed_response'))
        self.set_lb_status(lb['id'])
        self.delete(weighted_path)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_fixed_http_responses', True)
    def test_extended_policy_activation_and_matching_require_opt_in(self):
        policy_id = self.create_l7policy(
            self.listener_id, 'FIXED_RESPONSE',
            fixed_response={'status_code': 500})['l7policy']['id']
        self.set_lb_status(self.lb_id)
        rule_id = self.create_l7rule(
            policy_id, 'PATH', 'EQUAL_TO', '/original')['rule']['id']
        self.set_lb_status(self.lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        rule_path = self.L7RULE_PATH.format(l7policy_id=policy_id,
                                            l7rule_id=rule_id)
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[])
        self.create_l7rule(policy_id, 'PATH', 'EQUAL_TO', '/new', status=501)
        self.put(rule_path, {'rule': {'value': '/changed'}}, status=501)
        listener_path = self.LISTENER_PATH.format(listener_id=self.listener_id)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        self.put(rule_path, {'rule': {'tags': ['metadata']}})
        self.set_lb_status(self.lb_id)
        self.put(rule_path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(rule_path, {'rule': {'admin_state_up': True}}, status=501)
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        self.delete(rule_path)
        self.set_lb_status(self.lb_id)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.'
                'AmphoraProviderDriver.create_vip_port')
    def test_nested_gateway_actions_require_opt_in_before_vip(
            self, create_vip, rpc):
        fixed = {'status_code': 500}
        for fields in (
                {'default_http_response': fixed},
                {'l7policies': [{'action': 'FIXED_RESPONSE',
                                 'fixed_response': fixed}]},
                {'l7policies': [{'action': 'WEIGHTED_TARGETS',
                                 'targets': [{'weight': 1,
                                              'fixed_response': fixed}]}]},
                {'l7policies': [{
                    'action': 'REDIRECT_TO_POOL',
                    'redirect_pool': {'name': 'echo', 'protocol': 'HTTP',
                                      'lb_algorithm': 'ROUND_ROBIN'},
                    'request_header_operations': [
                        {'operation': 'REMOVE', 'name': 'x-old'}],
                }]}):
            with self.subTest(fields=fields):
                self.post(self.LBS_PATH, {'loadbalancer': {
                    'project_id': self.project_id,
                    'provider': 'amphora',
                    'vip_subnet_id': uuidutils.generate_uuid(),
                    'listeners': [{'protocol': 'HTTP', 'protocol_port': 80,
                                   **fields}],
                }}, status=501)
        create_vip.assert_not_called()
        rpc.return_value.cast.assert_not_called()

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_fixed_http_responses', True)
    def test_fixed_response_policy_update_and_restore_pool(self):
        response = {'status_code': 500}
        policy = self.create_l7policy(
            self.listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=self.pool_id)['l7policy']
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {
            'action': 'FIXED_RESPONSE', 'fixed_response': response}})
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {'name': 'renamed'}})
        policy = self.get(path).json['l7policy']
        self.assertEqual('FIXED_RESPONSE', policy['action'])
        self.assertEqual(response, policy['fixed_response'])
        self.assertIsNone(policy['redirect_pool_id'])
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {'fixed_response': None}}, status=400)
        self.put(path, {'l7policy': {
            'redirect_pool_id': self.pool_id, 'fixed_response': response}},
            status=400)
        for extra_fields in ({}, {'fixed_response': None},
                             {'action': 'REDIRECT_TO_POOL'}):
            with self.subTest(extra_fields=extra_fields):
                self.put(path, {'l7policy': {
                    'redirect_pool_id': self.pool_id, **extra_fields}})
                policy = self.get(path).json['l7policy']
                self.assertEqual('REDIRECT_TO_POOL', policy['action'])
                self.assertIsNone(policy.get('fixed_response'))
                self.assertEqual(self.pool_id, policy['redirect_pool_id'])
                self.set_lb_status(self.lb_id)
                self.put(path, {'l7policy': {
                    'action': 'FIXED_RESPONSE', 'fixed_response': response}})
                self.set_lb_status(self.lb_id)

    def test_rejects_fixed_response_policy_with_conflicting_target(self):
        self.create_l7policy(
            self.listener_id, 'FIXED_RESPONSE', status=400,
            fixed_response={'status_code': 500}, redirect_pool_id=self.pool_id)

    def test_fixed_response_policy_rejected_by_unsupported_provider(self):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='noop_driver-alt')
        lb_id = lb['loadbalancer']['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        response = {'status_code': 500}
        self.create_l7policy(listener['id'], 'FIXED_RESPONSE', status=501,
                             fixed_response=response)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.put(path, {'l7policy': {
            'action': 'FIXED_RESPONSE', 'fixed_response': response}},
            status=501)
        self.assertEqual('REJECT', self.get(path).json['l7policy']['action'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_create_amphora_with_nested_local_http_responses(self, get_client):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        listener_request = {
            'protocol': 'HTTP',
            'protocol_port': 80,
            'default_http_response': {'status_code': 404},
            'l7policies': [{
                'action': 'FIXED_RESPONSE',
                'fixed_response': {'status_code': 500},
                'rules': [{'type': 'PATH', 'compare_type': 'EQUAL_TO',
                           'value': '/missing'}],
            }],
        }
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora',
            listeners=[listener_request])['loadbalancer']
        listener = lb['listeners'][0]
        policy = listener['l7policies'][0]
        self.assertEqual({'status_code': 404},
                         listener['default_http_response'])
        self.assertEqual({'status_code': 500}, policy['fixed_response'])
        rpc_call = get_client.return_value.cast.call_args
        self.assertEqual('create_load_balancer', rpc_call.args[1])
        self.assertEqual(lb['id'],
                         rpc_call.kwargs['loadbalancer']['loadbalancer_id'])
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual({'status_code': 500},
                         self.get(path).json['l7policy']['fixed_response'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_nested_filtered_pool_requires_existing_lb(self, rpc):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        listener = {'protocol': 'HTTP', 'protocol_port': 80, 'l7policies': [
            {'action': 'WEIGHTED_TARGETS', 'targets': [
                {'weight': 1, 'pool_id': uuidutils.generate_uuid(),
                 'request_url_rewrite': {'hostname': 'backend.example'}}]}]}
        body = {'loadbalancer': {'project_id': self.project_id,
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(group='api_settings',
                         enabled_weighted_target_request_filter_providers=[
                             'amphora'])
        self.post(self.LBS_PATH, body, status=400)
        rpc.return_value.cast.assert_not_called()

    def test_nested_fixed_responses_validated_before_vip_creation(self):
        default = {'default_http_response': {'status_code': 404}}
        policy = {'l7policies': [{'action': 'FIXED_RESPONSE',
                                  'fixed_response': {'status_code': 500}}]}
        invalid_policy = {'l7policies': [{
            'action': 'REJECT', 'fixed_response': {'status_code': 500}}]}
        cases = [(default, 'HTTP', False, 501),
                 (policy, 'HTTP', False, 501),
                 (default, 'TCP', True, 400),
                 (policy, 'TCP', True, 400),
                 (invalid_policy, 'HTTP', True, 400)]
        for fields, protocol, supported, status in cases:
            with (
                self.subTest(fields=fields, protocol=protocol),
                mock.patch.object(noop_driver.NoopProviderDriver,
                                  'supports_fixed_http_responses', supported),
                mock.patch.object(noop_driver.NoopProviderDriver,
                                  'create_vip_port') as create_vip,
            ):
                result = self.post(self.LBS_PATH, {'loadbalancer': {
                    'project_id': self.project_id,
                    'provider': 'noop_driver-alt',
                    'vip_subnet_id': uuidutils.generate_uuid(),
                    'listeners': [{'protocol': protocol, 'protocol_port': 80,
                                   **fields}],
                }}, status=status)
                create_vip.assert_not_called()
                if status == 501:
                    self.assertIn('noop_driver-alt',
                                  result.json['faultstring'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_fixed_http_responses', True)
    def test_weighted_targets_create_replace_and_restore(self):
        targets = [{'weight': 3, 'pool_id': self.pool_id},
                   {'weight': 1, 'fixed_response': {'status_code': 500}}]
        policy = self.create_l7policy(
            self.listener_id, 'WEIGHTED_TARGETS', targets=targets)['l7policy']
        policy_id = policy['id']
        path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        self.assertEqual(targets, policy['targets'])
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])
        listed = self.get(self.L7POLICIES_PATH).json['l7policies']
        self.assertEqual(targets, next(
            policy['targets'] for policy in listed
            if policy['id'] == policy_id))

        self.set_lb_status(self.lb_id)
        policy = self.put(path, {'l7policy': {'name': 'edited'}}).json
        self.assertEqual(targets, policy['l7policy']['targets'])
        self.set_lb_status(self.lb_id)
        replacement = [{'weight': 5, 'fixed_response': {'status_code': 404}},
                       {'weight': 0, 'pool_id': self.pool_id}]
        self.put(path, {'l7policy': {'targets': replacement}})
        self.assertEqual(replacement,
                         self.get(path).json['l7policy']['targets'])

        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {'redirect_pool_id': self.pool_id}})
        policy = self.get(path).json['l7policy']
        self.assertEqual('REDIRECT_TO_POOL', policy['action'])
        self.assertNotIn('targets', policy)
        self.assertEqual(self.pool_id, policy['redirect_pool_id'])

        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {
            'action': 'WEIGHTED_TARGETS', 'targets': targets}})
        self.set_lb_status(self.lb_id)
        self.put(path, {'l7policy': {
            'action': 'FIXED_RESPONSE',
            'fixed_response': {'status_code': 500}}})
        policy = self.get(path).json['l7policy']
        self.assertEqual('FIXED_RESPONSE', policy['action'])
        self.assertNotIn('targets', policy)
        self.assertEqual({'status_code': 500}, policy['fixed_response'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    def test_rejects_malformed_weighted_targets(self):
        error = {'fixed_response': {'status_code': 500}}
        for targets in (
            None, [], {}, [None], [{'weight': 0, **error}],
            [{'weight': True, **error}], [{'weight': 1.0, **error}],
            [{'weight': '1', **error}], [{'weight': 1000001, **error}],
            [{'weight': 1, **error}] * 17,
            [{'weight': 1, 'pool_id': self.pool_id, **error}],
            [{'weight': 1, 'pool_id': 'invalid'}],
            [{'weight': 1, 'fixed_response': {'status_code': '500'}}],
            [{'weight': 1, 'fixed_response': {'status_code': 418}}],
        ):
            with self.subTest(targets=targets):
                self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                                     targets=targets, status=400)

        targets = [{'weight': 1, **error}]
        self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                             targets=targets, redirect_pool_id=self.pool_id,
                             status=400)
        self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                             targets=targets, **error, status=400)
        self.create_l7policy(self.listener_id, 'REJECT', targets=targets,
                             status=400)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    def test_weighted_targets_reject_incompatible_pool_on_create_and_update(
            self):
        tcp_pool = self.create_pool(
            self.lb_id, 'TCP', constants.LB_ALGORITHM_ROUND_ROBIN)['pool']
        self.set_lb_status(self.lb_id)
        invalid_targets = [{'weight': 1, 'pool_id': tcp_pool['id']}]
        self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                             targets=invalid_targets, status=400)
        targets = [{'weight': 1, 'pool_id': self.pool_id}]
        policy = self.create_l7policy(
            self.listener_id, 'WEIGHTED_TARGETS', targets=targets)['l7policy']
        self.set_lb_status(self.lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        with mock.patch.object(noop_driver.NoopProviderDriver,
                               'l7policy_update') as update:
            self.put(path, {'l7policy': {'targets': invalid_targets}},
                     status=400)
            update.assert_not_called()
        self.put(path, {'l7policy': {'targets': None}}, status=400)
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    def test_weighted_target_replacement_rolls_back_if_provider_rejects(self):
        targets = [{'weight': 1, 'pool_id': self.pool_id}]
        policy = self.create_l7policy(
            self.listener_id, 'WEIGHTED_TARGETS', targets=targets)['l7policy']
        self.set_lb_status(self.lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        replacement = [{'weight': 1, 'fixed_response': {'status_code': 500}}]
        with mock.patch.object(noop_driver.NoopProviderDriver,
                               'l7policy_update',
                               side_effect=lib_exceptions.DriverError):
            self.put(path, {'l7policy': {'targets': replacement}}, status=500)
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])
        self.put(path, {'l7policy': {'targets': replacement}})
        self.assertEqual(replacement,
                         self.get(path).json['l7policy']['targets'])

    def test_weighted_targets_require_provider_support(self):
        targets = [{'weight': 1, 'fixed_response': {'status_code': 500}}]
        self.create_l7policy(self.listener_id, 'WEIGHTED_TARGETS',
                             targets=targets, status=501)
        policy = self.create_l7policy(self.listener_id, 'REJECT')['l7policy']
        self.set_lb_status(self.lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.put(path, {'l7policy': {
            'action': 'WEIGHTED_TARGETS', 'targets': targets}}, status=501)
        self.assertEqual('REJECT', self.get(path).json['l7policy']['action'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_create_amphora_with_nested_http_request_policy(self, _rpc):
        self.conf.config(
            group='api_settings',
            enabled_http_request_policy_providers=['amphora'],
            enabled_http_retry_backoff_providers=['amphora'])
        field = 'http_request_policy'
        data = {'backend_request_timeout_ms': 100, 'retry': {'backoff_ms': 0}}
        policy = {
            'action': 'REDIRECT_TO_POOL',
            'redirect_pool': {'name': 'destination'},
            field: data,
            'rules': [{'type': 'PATH', 'compare_type': 'EQUAL_TO',
                       'value': '/policy'}],
        }
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora',
            pools=[{'name': 'destination', 'protocol': 'HTTP',
                    'lb_algorithm': 'ROUND_ROBIN'}],
            listeners=[{'protocol': 'HTTP', 'protocol_port': 80,
                        'l7policies': [policy]}])['loadbalancer']
        stored, = lb['listeners'][0]['l7policies']
        self.assertEqual(data, stored[field])
        path = self.L7POLICY_PATH.format(l7policy_id=stored['id'])
        self.assertEqual(data, self.get(path).json['l7policy'][field])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_create_amphora_with_nested_fixed_weighted_targets(self, _client):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        targets = [{'weight': 1, 'fixed_response': {'status_code': 500}}]
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora', listeners=[{
                'protocol': 'HTTP', 'protocol_port': 80,
                'l7policies': [{'action': 'WEIGHTED_TARGETS',
                                'targets': targets}],
            }])['loadbalancer']
        policy = lb['listeners'][0]['l7policies'][0]
        self.assertEqual(targets, policy['targets'])
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual(targets, self.get(path).json['l7policy']['targets'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_amphora_rpc_carries_current_and_replacement_weighted_targets(
            self, get_client):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(lb_id, 'HTTP',
                                constants.LB_ALGORITHM_ROUND_ROBIN)['pool']
        self.set_lb_status(lb_id)
        targets = [{'weight': 3, 'pool_id': pool['id']},
                   {'weight': 1, 'fixed_response': {'status_code': 500}}]
        policy = self.create_l7policy(
            listener['id'], 'WEIGHTED_TARGETS', targets=targets)['l7policy']
        created = get_client.return_value.cast.call_args
        self.assertEqual('create_l7policy', created.args[1])
        self.assertEqual(targets, created.kwargs['l7policy'].get('targets'))

        self.set_lb_status(lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        replacement = [{'weight': 1, 'pool_id': pool['id']}]
        self.put(path, {'l7policy': {'targets': replacement}})
        updated = get_client.return_value.cast.call_args
        self.assertEqual('update_l7policy', updated.args[1])
        self.assertEqual(targets,
                         updated.kwargs['original_l7policy']['targets'])
        self.assertEqual(replacement,
                         updated.kwargs['l7policy_updates']['targets'])

    def test_nested_weighted_targets_checked_before_vip_allocation(self):
        fixed = [{'weight': 1, 'fixed_response': {'status_code': 500}}]
        pool = [{'weight': 1, 'pool_id': self.pool_id}]
        for protocol, supported, targets, status in (
                ('HTTP', False, fixed, 501),
                ('TCP', True, fixed, 400),
                ('HTTP', True, pool, 400)):
            with (
                self.subTest(protocol=protocol, targets=targets),
                mock.patch.object(noop_driver.NoopProviderDriver,
                                  'supports_weighted_targets', supported,
                                  create=True),
                mock.patch.object(noop_driver.NoopProviderDriver,
                                  'create_vip_port') as create_vip,
            ):
                self.post(self.LBS_PATH, {'loadbalancer': {
                    'project_id': self.project_id,
                    'provider': 'noop_driver-alt',
                    'vip_subnet_id': uuidutils.generate_uuid(),
                    'listeners': [{
                        'protocol': protocol, 'protocol_port': 80,
                        'l7policies': [{'action': 'WEIGHTED_TARGETS',
                                        'targets': targets}],
                    }],
                }}, status=status)
                create_vip.assert_not_called()

    def test_nested_mirrors_checked_before_vip_allocation(self):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_http_request_mirror_providers=['amphora'])
        mirror = {'pool_id': self.pool_id, 'numerator': 0, 'denominator': 1}
        rule = {'action': 'FIXED_RESPONSE',
                'fixed_response': {'status_code': 500},
                'request_mirrors': [mirror]}
        weighted = {'action': 'WEIGHTED_TARGETS', 'targets': [
            {'weight': 1, 'pool_id': self.pool_id,
             'request_mirrors': [mirror]}]}
        with mock.patch(
                'octavia.api.drivers.amphora_driver.v2.driver.'
                'AmphoraProviderDriver.create_vip_port') as create_vip:
            for policy_data in (rule, weighted):
                with self.subTest(action=policy_data['action']):
                    self.post(self.LBS_PATH, {'loadbalancer': {
                        'project_id': self.project_id, 'provider': 'amphora',
                        'vip_subnet_id': uuidutils.generate_uuid(),
                        'listeners': [{
                            'protocol': 'HTTP', 'protocol_port': 80,
                            'l7policies': [policy_data],
                        }],
                    }}, status=400)
            create_vip.assert_not_called()

    def test_create_redirect_to_pool(self):
        api_l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            redirect_pool_id=self.pool_id).get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
                         api_l7policy['action'])
        self.assertEqual(1, api_l7policy['position'])
        self.assertEqual(self.pool_id, api_l7policy['redirect_pool_id'])
        self.assertIsNone(api_l7policy['redirect_url'])
        self.assertTrue(api_l7policy['admin_state_up'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_CREATE,
            l7policy_op_status=constants.OFFLINE)

    def test_create_redirect_to_url(self):
        api_l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://www.example.com').get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                         api_l7policy['action'])
        self.assertEqual(1, api_l7policy['position'])
        self.assertIsNone(api_l7policy.get('redirect_pool_id'))
        self.assertEqual('http://www.example.com',
                         api_l7policy['redirect_url'])
        self.assertTrue(api_l7policy['admin_state_up'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_CREATE,
            l7policy_op_status=constants.OFFLINE)

    def test_create_with_redirect_http_code(self):
        action_key_values = {
            constants.L7POLICY_ACTION_REDIRECT_PREFIX: {
                'redirect_prefix': 'https://example.com',
                'redirect_http_code': 302},
            constants.L7POLICY_ACTION_REDIRECT_TO_URL: {
                'redirect_url': 'http://www.example.com',
                'redirect_http_code': 301}}
        count = 1
        # First, test with redirect actions
        for action in [constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                       constants.L7POLICY_ACTION_REDIRECT_PREFIX]:
            api_l7policy = self.create_l7policy(
                self.listener_id, action,
                **action_key_values[action]).get(self.root_tag)
            self.assertEqual(action, api_l7policy['action'])
            self.assertEqual(count, api_l7policy['position'])
            self.assertIsNone(api_l7policy.get('redirect_pool_id'))
            if api_l7policy.get('redirect_url'):
                self.assertEqual(action_key_values[action]['redirect_url'],
                                 api_l7policy['redirect_url'])
            elif api_l7policy.get('redirect_prefix'):
                self.assertEqual(action_key_values[action]['redirect_prefix'],
                                 api_l7policy['redirect_prefix'])
            self.assertEqual(action_key_values[action]['redirect_http_code'],
                             api_l7policy['redirect_http_code'])
            self.assert_correct_status(
                lb_id=self.lb_id, listener_id=self.listener_id,
                l7policy_id=api_l7policy.get('id'),
                lb_prov_status=constants.PENDING_UPDATE,
                listener_prov_status=constants.PENDING_UPDATE,
                l7policy_prov_status=constants.PENDING_CREATE,
                l7policy_op_status=constants.OFFLINE)
            self.set_lb_status(self.lb_id)
            count += 1

        # test with redirect_pool action
        api_l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            redirect_pool_id=self.pool_id,
            redirect_http_code=308).get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
                         api_l7policy['action'])
        self.assertEqual(self.pool_id, api_l7policy.get('redirect_pool_id'))
        self.assertIsNone(api_l7policy.get('redirect_url'))
        self.assertIsNone(api_l7policy.get('redirect_prefix'))
        self.assertIsNone(api_l7policy.get('redirect_http_code'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_CREATE,
            l7policy_op_status=constants.OFFLINE)

    def test_bad_create(self):
        l7policy = {'listener_id': self.listener_id,
                    'name': 'test1'}
        self.post(self.L7POLICIES_PATH, self._build_body(l7policy), status=400)

    def test_bad_create_redirect_to_pool(self):
        l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            'listener_id': self.listener_id,
            'redirect_pool_id': uuidutils.generate_uuid()}
        self.post(self.L7POLICIES_PATH, self._build_body(l7policy), status=404)

    def test_bad_create_redirect_to_url(self):
        l7policy = {'listener_id': self.listener_id,
                    'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                    'redirect_url': 'bad url'}
        self.post(self.L7POLICIES_PATH, self._build_body(l7policy), status=400)

    def test_bad_create_with_redirect_http_code(self):
        for test_code in [1, '', 'HTTPCODE']:
            l7policy = {'listener_id': self.listener_id,
                        'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                        'redirect_url': 'http://www.example.com',
                        'redirect_http_code': test_code}
            self.post(self.L7POLICIES_PATH, self._build_body(l7policy),
                      status=400)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_create_with_bad_provider(self, mock_provider):
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        l7policy = {'listener_id': self.listener_id,
                    'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                    'redirect_url': 'http://a.com'}
        response = self.post(self.L7POLICIES_PATH, self._build_body(l7policy),
                             status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_create_over_quota(self):
        self.start_quota_mock(data_models.L7Policy)
        l7policy = {'listener_id': self.listener_id,
                    'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                    'redirect_url': 'http://a.com'}
        self.post(self.L7POLICIES_PATH, self._build_body(l7policy), status=403)

    def test_negative_create_prometheus_listener(self):
        prometheus_listener = self.create_listener(
            lib_consts.PROTOCOL_PROMETHEUS, 8123, lb_id=self.lb_id)
        prometheus_listener_id = prometheus_listener.get('listener').get('id')
        self.set_lb_status(self.lb_id)
        l7policy = {'listener_id': prometheus_listener_id, 'name': 'test1'}
        self.post(self.L7POLICIES_PATH, self._build_body(l7policy), status=400)

    def test_update(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            tags=['old_tag']
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com',
            'tags': ['new_tag']}
        response = self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy)).json.get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                         response.get('action'))
        self.assertEqual(['new_tag'], response['tags'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE)

    def test_update_authorized(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member', 'member'],
            'user_id': None,
            'is_admin': False,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': self.project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            response = self.put(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')),
                self._build_body(new_l7policy)).json.get(self.root_tag)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                         response.get('action'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE)

    def test_update_not_authorized(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            response = self.put(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')),
                self._build_body(new_l7policy), status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, response.json)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE)

    def test_bad_update(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        new_l7policy = {'listener_id': self.listener_id,
                        'action': 'bad action'}
        self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy), status=400)

    def test_bad_update_redirect_to_pool(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        new_l7policy = {
            'listener_id': self.listener_id,
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            'redirect_pool_id': uuidutils.generate_uuid()}
        self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy), status=400)

    def test_bad_update_redirect_to_url(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        new_l7policy = {
            'listener_id': self.listener_id,
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'bad url'}
        self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy), status=400)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_update_with_bad_provider(self, mock_provider):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        response = self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy), status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_update_redirect_to_pool_bad_pool_id(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {'redirect_pool_id': uuidutils.generate_uuid()}
        self.put(self.L7POLICY_PATH.format(l7policy_id=api_l7policy.get('id')),
                 self._build_body(new_l7policy), status=404)

    def test_update_redirect_to_pool_minimal(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {'redirect_pool_id': self.pool_id}
        self.put(self.L7POLICY_PATH.format(l7policy_id=api_l7policy.get('id')),
                 self._build_body(new_l7policy))

    def test_update_redirect_to_url_bad_url(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {'listener_id': self.listener_id,
                        'redirect_url': 'bad-url'}
        self.put(self.L7POLICY_PATH.format(l7policy_id=api_l7policy.get('id')),
                 self._build_body(new_l7policy), status=400)

    def test_update_redirect_to_url_minimal(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {'redirect_url': 'http://www.example.com/'}
        self.put(self.L7POLICY_PATH.format(l7policy_id=api_l7policy.get('id')),
                 self._build_body(new_l7policy))

    def test_update_with_redirect_http_code(self):
        # test from non exist
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com',
            'redirect_http_code': 308}
        response = self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy)).json.get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                         response.get('action'))
        self.assertEqual(308, response.get('redirect_http_code'))
        self.set_lb_status(self.lb_id)

        # test from exist to new
        api_l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            redirect_url='http://www.example.com',
            redirect_http_code=302).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'redirect_http_code': 308}
        response = self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy)).json.get(self.root_tag)
        self.assertEqual(constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                         response.get('action'))
        self.assertEqual(308, response.get('redirect_http_code'))
        self.set_lb_status(self.lb_id)

        # test from exist to null
        new_l7policy = {
            'redirect_http_code': None}
        response = self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy)).json.get(self.root_tag)
        self.assertIsNone(response.get('redirect_http_code'))

    def test_bad_update_with_redirect_http_code(self):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com',
            'redirect_http_code': ''}
        self.put(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')),
            self._build_body(new_l7policy), status=400).json.get(self.root_tag)

    def test_delete(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7policy['provisioning_status'] = constants.ACTIVE
        api_l7policy['operating_status'] = constants.ONLINE
        api_l7policy.pop('updated_at')

        response = self.get(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7policy, response)

        self.delete(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_DELETE)

    def test_delete_authorized(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7policy['provisioning_status'] = constants.ACTIVE
        api_l7policy['operating_status'] = constants.ONLINE
        api_l7policy.pop('updated_at')

        response = self.get(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7policy, response)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member', 'member'],
            'user_id': None,
            'is_admin': False,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': self.project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):

            self.delete(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')))

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_DELETE)

    def test_delete_not_authorized(self):
        api_l7policy = self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7policy['provisioning_status'] = constants.ACTIVE
        api_l7policy['operating_status'] = constants.ONLINE
        api_l7policy.pop('updated_at')

        response = self.get(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7policy, response)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            self.delete(self.L7POLICY_PATH.format(
                l7policy_id=api_l7policy.get('id')), status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=api_l7policy.get('id'),
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE)

    def test_bad_delete(self):
        self.delete(self.L7POLICY_PATH.format(
            l7policy_id=uuidutils.generate_uuid()), status=404)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_delete_with_bad_provider(self, mock_provider):
        api_l7policy = self.create_l7policy(self.listener_id,
                                            constants.L7POLICY_ACTION_REJECT,
                                            ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7policy['provisioning_status'] = constants.ACTIVE
        api_l7policy['operating_status'] = constants.ONLINE
        response = self.get(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id'))).json.get(self.root_tag)

        self.assertIsNone(api_l7policy.pop('updated_at'))
        self.assertIsNotNone(response.pop('updated_at'))
        self.assertEqual(api_l7policy, response)
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        self.delete(self.L7POLICY_PATH.format(
            l7policy_id=api_l7policy.get('id')), status=500)

    def test_create_when_lb_pending_update(self):
        self.create_l7policy(self.listener_id,
                             constants.L7POLICY_ACTION_REJECT,
                             )
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        new_l7policy = {
            'listener_id': self.listener_id,
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}
        self.post(self.L7POLICIES_PATH, body=self._build_body(new_l7policy),
                  status=409)

    def test_update_when_lb_pending_update(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        new_l7policy = {'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
                        'redirect_url': 'http://www.example.com'}
        self.put(self.L7POLICY_PATH.format(
                 l7policy_id=l7policy.get('id')),
                 body=self._build_body(new_l7policy), status=409)

    def test_delete_when_lb_pending_update(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        self.delete(self.L7POLICY_PATH.format(
                    l7policy_id=l7policy.get('id')),
                    status=409)

    def test_create_when_lb_pending_delete(self):
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_l7policy = {
            'listener_id': self.listener_id,
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}
        self.post(self.L7POLICIES_PATH, body=self._build_body(new_l7policy),
                  status=409)

    def test_update_when_lb_pending_delete(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}
        self.put(self.L7POLICY_PATH.format(
                 l7policy_id=l7policy.get('id')),
                 body=self._build_body(new_l7policy), status=409)

    def test_delete_when_lb_pending_delete(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        self.delete(self.L7POLICY_PATH.format(
                    l7policy_id=l7policy.get('id')),
                    status=409)

    def test_update_already_deleted(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        new_l7policy = {
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL,
            'redirect_url': 'http://www.example.com'}
        self.put(self.L7POLICY_PATH.format(l7policy_id=l7policy.get('id')),
                 body=self._build_body(new_l7policy), status=404)

    def test_delete_already_deleted(self):
        l7policy = self.create_l7policy(self.listener_id,
                                        constants.L7POLICY_ACTION_REJECT,
                                        ).get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        self.delete(self.L7POLICY_PATH.format(
                    l7policy_id=l7policy.get('id')),
                    status=404)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_listener_pool_protocol_map_post(self, mock_cert_data):
        cert = data_models.TLSContainer(certificate='cert')
        mock_cert_data.return_value = {'sni_certs': [cert]}
        valid_map = constants.VALID_LISTENER_POOL_PROTOCOL_MAP
        port = 1
        l7policy = {'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL}
        for listener_proto in valid_map:
            for pool_proto in valid_map[listener_proto]:
                port = port + 1
                opts = {}
                if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                    opts['sni_container_refs'] = [uuidutils.generate_uuid()]
                listener = self.create_listener(
                    listener_proto, port, self.lb_id, **opts).get('listener')
                self.set_object_status(self.lb_repo, self.lb_id)
                pool = self.create_pool(
                    self.lb_id, pool_proto,
                    constants.LB_ALGORITHM_ROUND_ROBIN).get('pool')

                l7policy['listener_id'] = listener.get('id')
                l7policy['redirect_pool_id'] = pool.get('id')
                self.set_object_status(self.lb_repo, self.lb_id)
                self.post(self.L7POLICIES_PATH,
                          self._build_body(l7policy), status=201)
                self.set_object_status(self.lb_repo, self.lb_id)

        invalid_map = c_const.INVALID_LISTENER_POOL_PROTOCOL_MAP
        port = 100
        for listener_proto in invalid_map:
            opts = {}
            if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                opts['sni_container_refs'] = [uuidutils.generate_uuid()]
            listener = self.create_listener(
                listener_proto, port, self.lb_id, **opts).get('listener')
            self.set_object_status(self.lb_repo, self.lb_id)
            port = port + 1
            for pool_proto in invalid_map[listener_proto]:
                if pool_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                    pool = self.create_pool(
                        self.lb_id, pool_proto,
                        constants.LB_ALGORITHM_ROUND_ROBIN, status=400)
                    self.assertIn("Invalid input", pool['faultstring'])
                else:
                    pool = self.create_pool(
                        self.lb_id, pool_proto,
                        constants.LB_ALGORITHM_ROUND_ROBIN).get('pool')
                    self.set_object_status(self.lb_repo, self.lb_id)

                    l7policy['listener_id'] = listener.get('id')
                    l7policy['redirect_pool_id'] = pool.get('id')
                    expect_error_msg = (
                        "Validation failure: The pool protocol '%s' is "
                        "invalid while the listener protocol is '%s'.") % (
                        pool_proto, listener_proto)
                    res = self.post(self.L7POLICIES_PATH,
                                    self._build_body(l7policy), status=400)
                    self.assertEqual(expect_error_msg, res.json['faultstring'])
                    self.assert_correct_status(lb_id=self.lb_id)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_listener_pool_protocol_map_put(self, mock_cert_data):
        cert = data_models.TLSContainer(certificate='cert')
        mock_cert_data.return_value = {'sni_certs': [cert]}
        valid_map = constants.VALID_LISTENER_POOL_PROTOCOL_MAP
        port = 1
        new_l7policy = {'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL}
        for listener_proto in valid_map:
            for pool_proto in valid_map[listener_proto]:
                port = port + 1
                opts = {}
                if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                    opts['sni_container_refs'] = [uuidutils.generate_uuid()]
                listener = self.create_listener(
                    listener_proto, port, self.lb_id, **opts).get('listener')
                self.set_object_status(self.lb_repo, self.lb_id)
                pool = self.create_pool(
                    self.lb_id, pool_proto,
                    constants.LB_ALGORITHM_ROUND_ROBIN).get('pool')
                self.set_object_status(self.lb_repo, self.lb_id)
                l7policy = self.create_l7policy(
                    listener.get('id'),
                    constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
                self.set_object_status(self.lb_repo, self.lb_id)
                new_l7policy['redirect_pool_id'] = pool.get('id')

                self.put(
                    self.L7POLICY_PATH.format(l7policy_id=l7policy.get('id')),
                    self._build_body(new_l7policy), status=200)
                self.set_object_status(self.lb_repo, self.lb_id)

        invalid_map = c_const.INVALID_LISTENER_POOL_PROTOCOL_MAP
        port = 100
        for listener_proto in invalid_map:
            opts = {}
            if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                opts['sni_container_refs'] = [uuidutils.generate_uuid()]
            listener = self.create_listener(
                listener_proto, port, self.lb_id, **opts).get('listener')
            self.set_object_status(self.lb_repo, self.lb_id)
            port = port + 1
            for pool_proto in invalid_map[listener_proto]:
                if pool_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                    pool = self.create_pool(
                        self.lb_id, pool_proto,
                        constants.LB_ALGORITHM_ROUND_ROBIN, status=400)
                    self.assertIn("Invalid input", pool['faultstring'])
                else:
                    pool = self.create_pool(
                        self.lb_id, pool_proto,
                        constants.LB_ALGORITHM_ROUND_ROBIN).get('pool')
                    self.set_object_status(self.lb_repo, self.lb_id)
                    l7policy = self.create_l7policy(
                        listener.get('id'),
                        constants.L7POLICY_ACTION_REJECT).get(self.root_tag)
                    self.set_object_status(self.lb_repo, self.lb_id)
                    new_l7policy['redirect_pool_id'] = pool.get('id')
                    expect_error_msg = (
                        "Validation failure: The pool protocol '%s' is "
                        "invalid while the listener protocol is '%s'.") % (
                        pool_proto, listener_proto)
                    res = self.put(self.L7POLICY_PATH.format(
                        l7policy_id=l7policy.get('id')),
                        self._build_body(new_l7policy), status=400)
                    self.assertEqual(expect_error_msg, res.json['faultstring'])
                    self.assert_correct_status(lb_id=self.lb_id)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_https_listener_isolation_lifecycle(self, cert_data, rpc):
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='cert 1')}
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener_options = {
            'default_tls_container_ref': uuidutils.generate_uuid(),
            'https_virtual_hosts': ['*.example.test', 'A.Example.Test'],
            'default_http_response': {'status_code': 404}}
        self.create_listener('TERMINATED_HTTPS', 443, lb_id,
                             status=501, **listener_options)
        self.conf.config(
            group='api_settings',
            enabled_https_listener_isolation_providers=['amphora'],
            enabled_gateway_action_providers=['amphora'])
        self.create_listener('TERMINATED_HTTPS', 443, lb_id, status=400,
                             **dict(listener_options, https_virtual_hosts=[
                                 'a.example.test', 'A.Example.Test']))
        self.create_listener('TERMINATED_HTTPS', 443, lb_id, status=400,
                             **dict(listener_options, default_http_response={
                                 'status_code': 500}))
        listener = self.create_listener(
            'TERMINATED_HTTPS', 443, lb_id, **listener_options)['listener']
        listener_id = listener['id']
        listener_path = self.LISTENER_PATH.format(listener_id=listener_id)
        hosts = ['*.example.test', 'a.example.test']
        self.assertEqual(hosts, listener['https_virtual_hosts'])
        self.assertEqual(
            hosts, rpc.return_value.cast.call_args.kwargs['listener'][
                'https_virtual_hosts'])

        self.set_lb_status(lb_id)
        self.create_l7policy(listener_id, 'REJECT', status=400)
        self.create_l7policy(listener_id, 'REJECT', status=400,
                             https_listener_hostname='other.test')
        policy = self.create_l7policy(
            listener_id, 'REJECT',
            https_listener_hostname='A.EXAMPLE.TEST')['l7policy']
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertEqual('a.example.test', policy['https_listener_hostname'])
        self.assertEqual(
            'a.example.test',
            rpc.return_value.cast.call_args.kwargs['l7policy'][
                'https_listener_hostname'])
        self.set_lb_status(lb_id)

        self.put(listener_path, {'listener': {
            'https_virtual_hosts': ['*.example.test']}}, status=400)
        self.put(policy_path, {'l7policy': {
            'https_listener_hostname': None}}, status=400)
        self.conf.config(group='api_settings',
                         enabled_https_listener_isolation_providers=[])
        self.create_l7rule(
            policy['id'], 'PATH', 'STARTS_WITH', '/', status=501)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        self.delete(policy_path)
        self.set_lb_status(lb_id)
        self.delete(listener_path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_https_listener_isolation_in_initial_graph(self, cert_data, rpc):
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='cert 1')}
        self.conf.config(
            group='api_settings',
            enabled_https_listener_isolation_providers=['amphora'])
        policy = {'action': 'REJECT', 'rules': [{
            'type': 'PATH', 'compare_type': 'STARTS_WITH', 'value': '/'}]}
        listener = {
            'name': 'isolated-https', 'protocol': 'TERMINATED_HTTPS',
            'protocol_port': 443, 'https_virtual_hosts': ['*'],
            'default_tls_container_ref': uuidutils.generate_uuid(),
            'l7policies': [policy]}
        body = {'loadbalancer': {
            'project_id': self.project_id, 'provider': 'amphora',
            'vip_subnet_id': uuidutils.generate_uuid(),
            'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=400)
        policy['https_listener_hostname'] = '*'
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved, = lb['listeners']
        saved_policy, = saved['l7policies']
        self.assertEqual(['*'], saved['https_virtual_hosts'])
        self.assertEqual('*', saved_policy['https_listener_hostname'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tls_sni_admission_and_withdrawal(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('TCP', 443, lb_id)['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(
            lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        target = {'redirect_pool_id': pool['id']}

        rpc.return_value.cast.reset_mock()
        self.create_l7policy(listener['id'], 'REDIRECT_TO_POOL',
                             status=501, **target)
        rpc.return_value.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_tls_sni_providers=['amphora'])
        proxy_pool = self.create_pool(
            lb_id, 'PROXY', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        self.create_l7policy(
            listener['id'], 'REDIRECT_TO_POOL',
            redirect_pool_id=proxy_pool['id'], status=400)
        self.create_l7policy(listener['id'], 'REJECT', status=400)
        rpc.return_value.cast.reset_mock()
        invalid = self.create_l7policy(
            listener['id'], 'REDIRECT_TO_POOL', status=400, **target,
            rules=[{'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                    'value': 'a.example.test'}])
        self.assertIn('/v2/lbaas/l7policies/{id}/rules',
                      invalid['faultstring'])
        rpc.return_value.cast.assert_not_called()
        policy = self.create_l7policy(
            listener['id'], 'REDIRECT_TO_POOL', **target)['l7policy']
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.set_lb_status(lb_id)
        self.create_l7rule(
            policy['id'], 'HOST_NAME', 'EQUAL_TO', 'a.example.test',
            status=400)
        self.create_l7rule(
            policy['id'], 'TLS_SNI', 'EQUAL_TO', '*.example.test',
            status=400)
        rule = self.create_l7rule(
            policy['id'], 'TLS_SNI', 'EQUAL_TO', 'A.example.test')['rule']
        path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                       l7rule_id=rule['id'])
        self.set_lb_status(lb_id)
        self.app.patch_json(self._get_full_path(path),
                            params={'rule': {'value': 'b.example.test'}},
                            status=405)
        self.put(path, {'rule': {'invert': True}}, status=400)
        self.put(path, {'rule': {'type': 'HOST_NAME'}}, status=400)
        unrelated = self.create_l7policy(
            self.listener_id, 'REJECT')['l7policy']
        wrong_parent = self.L7RULE_PATH.format(l7policy_id=unrelated['id'],
                                               l7rule_id=rule['id'])
        self.put(wrong_parent, {'rule': {'type': 'HOST_NAME'}}, status=404)
        self.put(policy_path, {'l7policy': {
            'redirect_pool_id': proxy_pool['id']}}, status=400)
        self.put(policy_path, {'l7policy': {'redirect_pool_id': None}},
                 status=400)
        saved_policy = self.get(policy_path).json['l7policy']
        self.assertEqual(pool['id'], saved_policy['redirect_pool_id'])
        self.put(path, {'rule': {'value': 'b.example.test'}})
        self.set_lb_status(lb_id)
        self.assertEqual('b.example.test',
                         self.get(path).json['rule']['value'])

        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        lb_path = self.LB_PATH.format(lb_id=lb_id)
        self.delete(pool_path, status=409)
        self.put(pool_path, {'pool': {'tls_enabled': True}}, status=400)
        self.conf.config(group='api_settings', enabled_tls_sni_providers=[])
        self.put(lb_path, {'loadbalancer': {'admin_state_up': False}})
        self.set_lb_status(lb_id)

        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}},
                 status=501)
        saved_lb = self.get(lb_path).json['loadbalancer']
        self.assertFalse(saved_lb['admin_state_up'])
        self.put(pool_path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        self.put(path, {'rule': {'value': 'c.example.test'}}, status=501)
        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}},
                 status=501)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(path)
        self.set_lb_status(lb_id)
        self.delete(policy_path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tls_sni_suffix_admission_and_opt_out(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('TCP', 443, lb_id)['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        self.conf.config(group='api_settings',
                         enabled_tls_sni_providers=['amphora'])
        policy = self.create_l7policy(
            listener['id'], 'REDIRECT_TO_POOL',
            redirect_pool_id=pool['id'])['l7policy']
        self.set_lb_status(lb_id)

        rpc.return_value.cast.reset_mock()
        self.create_l7rule(policy['id'], 'TLS_SNI', 'ENDS_WITH',
                           '*.example.test', status=501)
        rpc.return_value.cast.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=['amphora'])
        for value, options in (
                ('example.test', {}),
                ('*.foo.*.test', {}),
                ('*.192.0.2.1', {}),
                ('*.example.test', {'key': 'hostname'}),
                ('*.example.test', {'invert': True})):
            with self.subTest(value=value, options=options):
                self.create_l7rule(policy['id'], 'TLS_SNI', 'ENDS_WITH',
                                   value, status=400, **options)
        rpc.return_value.cast.assert_not_called()
        rule = self.create_l7rule(policy['id'], 'TLS_SNI', 'ENDS_WITH',
                                  '*.Example.test')['rule']
        self.set_lb_status(lb_id)
        self.assertEqual('*.Example.test', rule['value'])
        path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                       l7rule_id=rule['id'])

        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=[])
        self.put(path, {'rule': {'value': '*.new.example.test'}}, status=501)
        self.assertEqual('*.Example.test',
                         self.get(path).json['rule']['value'])
        lb_path = self.LB_PATH.format(lb_id=lb_id)
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        for resource, resource_path in (
                ('loadbalancer', lb_path), ('listener', listener_path),
                ('pool', pool_path), ('l7policy', policy_path),
                ('rule', path)):
            with self.subTest(resource=resource):
                self.put(resource_path, {resource: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                self.put(resource_path, {resource: {'admin_state_up': True}},
                         status=501)
                self.assertFalse(
                    self.get(resource_path).json[resource]['admin_state_up'])
        self.delete(path)
        self.set_lb_status(lb_id)
        exact = self.create_l7rule(policy['id'], 'TLS_SNI', 'EQUAL_TO',
                                   'a.example.test')['rule']
        self.assertEqual('EQUAL_TO', exact['compare_type'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_termination_admission_and_withdrawal(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        cert_ref = 'https://barbican.example.test/v1/secrets/server'
        options = {'tcp_tls_termination': True,
                   'default_tls_container_ref': cert_ref}
        self.set_lb_status(lb_id)
        rpc.return_value.cast.reset_mock()
        self.create_listener('TCP', 443, lb_id, status=501, **options)
        rpc.return_value.cast.assert_not_called()
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora', 'noop_driver'])
        capability = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        self.assertEqual({'gateway_capabilities': ['tcp_tls_termination_v1']},
                         self.get(capability.format('amphora')).json)
        self.assertEqual({'gateway_capabilities': []},
                         self.get(capability.format('noop_driver')).json)
        self.conf.config(group='api_settings',
                         allow_tls_terminated_listeners=False)
        self.assertEqual({'gateway_capabilities': []},
                         self.get(capability.format('amphora')).json)
        self.create_listener('TCP', 443, lb_id, status=501, **options)
        self.conf.config(group='api_settings',
                         allow_tls_terminated_listeners=True)
        self.create_listener('HTTP', 443, lb_id, status=400, **options)
        self.create_listener('TCP', 443, lb_id, status=400,
                             tcp_tls_termination=True)
        self.create_listener('TCP', 443, lb_id, status=400,
                             default_tls_container_ref=cert_ref)
        self.create_listener('TCP', 443, lb_id, status=400,
                             tcp_tls_termination=None)
        get_cert = self.cert_manager_mock.return_value.get_cert
        get_cert.side_effect = RuntimeError('No project access')
        self.create_listener('TCP', 443, lb_id, status=400, **options)
        get_cert.side_effect = None
        created = self.create_listener('TCP', 443, lb_id, **options)
        listener = created['listener']
        self.assertTrue(listener['tcp_tls_termination'])
        self.assertIsNone(listener['alpn_protocols'])
        payload = rpc.return_value.cast.call_args.kwargs['listener']
        self.assertTrue(payload['tcp_tls_termination'])
        self.assertEqual(cert_ref, payload['default_tls_container_ref'])
        self.assertTrue(get_cert.call_args.kwargs['check_only'])
        listener_id = listener['id']
        path = self.LISTENER_PATH.format(listener_id=listener_id)
        lb_path = self.LB_PATH.format(lb_id=lb_id)
        self.set_lb_status(lb_id)
        self.put(path, {'listener': {'tcp_tls_termination': False}},
                 status=400)
        self.put(path, {'listener': {'default_tls_container_ref': None}},
                 status=400)
        self.create_pool(lb_id, 'TCP', 'ROUND_ROBIN', listener_id=listener_id,
                         tls_enabled=True, status=400)
        pool = self.create_pool(
            lb_id, 'TCP', 'ROUND_ROBIN', listener_id=listener_id)['pool']
        self.set_lb_status(lb_id)
        pool_path = self.POOL_PATH.format(pool_id=pool['id'])
        self.put(pool_path, {'pool': {'tls_enabled': True}}, status=400)
        policy = self.create_l7policy(
            listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=pool['id'])['l7policy']
        self.set_lb_status(lb_id)
        self.create_l7rule(
            policy['id'], 'TLS_SNI', 'ENDS_WITH', '*.example.test')
        self.set_lb_status(lb_id)

        for resource, path_to_reopen in (('loadbalancer', lb_path),
                                         ('listener', path)):
            self.put(path_to_reopen, {resource: {'admin_state_up': False}})
            self.set_lb_status(lb_id)
            rpc.return_value.cast.reset_mock()
            get_cert.side_effect = RuntimeError('Certificate access removed')
            self.put(path_to_reopen, {resource: {'admin_state_up': True}},
                     status=400)
            rpc.return_value.cast.assert_not_called()
            self.assertFalse(self.get(path_to_reopen).json[resource][
                'admin_state_up'])
            get_cert.side_effect = None
            self.put(path_to_reopen, {resource: {'admin_state_up': True}})
            self.set_lb_status(lb_id)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_termination_providers=[])
        self.put(lb_path, {'loadbalancer': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}},
                 status=501)
        self.put(path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'listener': {'admin_state_up': True}}, status=501)
        self.put(lb_path, {'loadbalancer': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(path)
        self.assertEqual('delete_listener',
                         rpc.return_value.cast.call_args.args[1])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tls_sni_weighted_pool_admission_and_withdrawal(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_l7policy_initial_rules_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        listener_args = {
            'tcp_tls_termination': True,
            'default_tls_container_ref': uuidutils.generate_uuid(),
        }
        self.set_lb_status(lb_id)
        listener = self.create_listener(
            'TCP', 443, lb_id, **listener_args)['listener']
        self.set_lb_status(lb_id)
        first = self.create_pool(lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        second = self.create_pool(
            lb_id, 'TCP', 'ROUND_ROBIN', admin_state_up=False)['pool']
        self.set_lb_status(lb_id)
        action = 'WEIGHTED_TARGETS'
        listener_id = listener['id']
        targets = [{'pool_id': first['id'], 'weight': 4},
                   {'pool_id': second['id'], 'weight': 1},
                   {'pool_id': second['id'], 'weight': 0}]
        rule = {'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                'value': 'a.example.test'}
        capability = 'tls_sni_weighted_pools_v1'
        capability_path = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        self.assertNotIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.create_l7policy(listener_id, action, targets=targets, status=501)

        self.conf.config(group='api_settings',
                         enabled_tls_sni_weighted_pool_providers=[
                             'amphora', 'noop_driver'])
        self.assertIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.assertNotIn(capability, self.get(capability_path.format(
            'noop_driver')).json['gateway_capabilities'])
        self.create_l7policy(listener_id, action, targets=[
            {'fixed_response': {'status_code': 503}, 'weight': 1}], status=400)
        self.create_l7policy(listener_id, action, targets=[
            {'pool_id': self.pool_id, 'weight': 1}], status=404)
        self.create_l7policy(listener_id, action, targets=targets,
                             tcp_tls_passthrough=True, status=400)
        self.create_l7policy(
            listener_id, action, targets=targets, admin_state_up=False,
            rules=[dict(rule, type='HOST_NAME')], status=400)
        policy = self.create_l7policy(
            listener_id, action, targets=targets, admin_state_up=False,
            rules=[rule])['l7policy']
        self.assertEqual(targets, policy['targets'])
        self.assertEqual(targets, rpc.return_value.cast.call_args.kwargs[
            'l7policy']['targets'])
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        pool_path = self.POOL_PATH.format(pool_id=second['id'])
        self.set_lb_status(lb_id)
        self.put(path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(pool_path, status=409)
        self.put(pool_path, {'pool': {'tls_enabled': True}}, status=400)
        with mock.patch(
                'octavia.api.drivers.amphora_driver.v2.driver.'
                'AmphoraProviderDriver.create_vip_port') as create_vip:
            self.post(self.LBS_PATH, {'loadbalancer': dict(
                vip_subnet_id=uuidutils.generate_uuid(),
                project_id=lb['project_id'], provider='amphora',
                listeners=[dict(listener_args, protocol='TCP',
                                protocol_port=443, l7policies=[{
                                    'action': action, 'targets': targets,
                                    'rules': [rule],
                                }])])}, status=400)
            create_vip.assert_not_called()

        self.conf.config(group='api_settings',
                         enabled_tls_sni_weighted_pool_providers=[])
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(path, {'l7policy': {'targets': targets[:1]}}, status=501)
        self.put(path, {'l7policy': {'redirect_pool_id': first['id']}},
                 status=501)
        self.put(path, {'l7policy': {'targets': targets[:2]}})
        self.set_lb_status(lb_id)
        listener_path = self.LISTENER_PATH.format(listener_id=listener_id)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}},
                 status=501)
        self.put(path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'l7policy': {'admin_state_up': True}}, status=501)
        self.put(listener_path, {'listener': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(path)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_weighted_tls_sni_rule_removal_checks_serving_pools(
            self, _rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_tls_sni_weighted_pool_providers=['amphora'],
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_tcp_tls_backend_auth_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener(
            'TCP', 443, lb_id, tcp_tls_termination=True,
            default_tls_container_ref=uuidutils.generate_uuid())['listener']
        self.set_lb_status(lb_id)
        plain = self.create_pool(lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        secure = self.create_pool(
            lb_id, 'TCP', 'ROUND_ROBIN', tls_enabled=True,
            backend_tls_hostname='backend.example.test',
            ca_tls_container_ref=uuidutils.generate_uuid())['pool']
        self.set_lb_status(lb_id)
        targets = [{'pool_id': plain['id'], 'weight': 3},
                   {'pool_id': secure['id'], 'weight': 1}]
        policy = self.create_l7policy(
            listener['id'], 'WEIGHTED_TARGETS', targets=targets)['l7policy']
        self.set_lb_status(lb_id)
        exact = self.create_l7rule(
            policy['id'], 'TLS_SNI', 'EQUAL_TO', 'a.example.test')['rule']
        self.set_lb_status(lb_id)
        suffix = self.create_l7rule(
            policy['id'], 'TLS_SNI', 'ENDS_WITH', '*.example.test')['rule']
        self.set_lb_status(lb_id)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        exact_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=exact['id'])
        suffix_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=suffix['id'])
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        pool_path = self.POOL_PATH.format(pool_id=secure['id'])

        new_ca_ref = uuidutils.generate_uuid()
        ca_update = {'pool': {'ca_tls_container_ref': new_ca_ref}}
        self.conf.config(group='api_settings',
                         enabled_tls_sni_weighted_pool_providers=[])
        self.put(pool_path, ca_update, status=501)
        self.conf.config(group='api_settings',
                         enabled_tls_sni_weighted_pool_providers=['amphora'])
        self.put(pool_path, ca_update)
        self.set_lb_status(lb_id)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=[])
        self.delete(exact_path, status=501)
        self.put(exact_path, {'rule': {'admin_state_up': False}}, status=501)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}},
                 status=501)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=['amphora'])
        self.put(policy_path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.put(exact_path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(exact_path, {'rule': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        targets[1]['weight'] = 0
        self.put(policy_path, {'l7policy': {'targets': targets}})
        self.set_lb_status(lb_id)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=[])
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(policy_path, {'l7policy': {
            'admin_state_up': True,
            'targets': [targets[0], {'pool_id': self.pool_id, 'weight': 0}],
        }}, status=404)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(listener_path, {'listener': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.put(exact_path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(exact_path, {'rule': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(exact_path)
        database_tasks.DeleteL7RuleInDB().execute(
            {constants.L7RULE_ID: exact['id']})
        self.set_lb_status(lb_id)
        self.delete(suffix_path)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_mixed_mode(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        mode = 'tcp_tls_mixed_mode'
        passthrough = 'tcp_tls_passthrough'
        capability = mode + '_v1'
        capability_path = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        opts = {mode: True, 'tcp_tls_termination': True,
                'default_tls_container_ref': uuidutils.generate_uuid()}
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_mixed_mode_providers=['amphora', 'noop_driver'],
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_tcp_tls_backend_auth_providers=['amphora'],
            enabled_backend_tls_hostname_providers=['amphora'])
        self.assertNotIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.create_listener('TCP', 8883, lb_id, status=501, **opts)
        self.conf.config(group='api_settings',
                         enabled_tls_sni_providers=['amphora'])
        self.assertIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.assertNotIn(capability, self.get(capability_path.format(
            'noop_driver')).json['gateway_capabilities'])

        args = lb_id, 'TCP', 'ROUND_ROBIN'
        plain = self.create_pool(*args)['pool']['id']
        self.set_lb_status(lb_id)
        protected = self.create_pool(
            *args, tls_enabled=True,
            backend_tls_hostname='backend.example.com',
            ca_tls_container_ref=uuidutils.generate_uuid())['pool']['id']
        self.set_lb_status(lb_id)
        self.create_listener('TCP', 8883, lb_id, default_pool_id=plain,
                             status=400, **opts)
        listener = self.create_listener('TCP', 8883, lb_id, **opts)['listener']
        self.assertTrue(listener[mode])
        self.assertTrue(rpc.return_value.cast.call_args.kwargs['listener'][
            mode])
        listener_id = listener['id']
        self.set_lb_status(lb_id)
        path = self.LISTENER_PATH.format(listener_id=listener_id)
        self.assertTrue(self.get(path).json['listener'][mode])
        self.put(path, {'listener': {mode: False}}, status=400)
        self.put(path, {'listener': {'default_pool_id': plain}}, status=400)
        self.create_pool(*args, listener_id=listener_id, status=400)
        self.create_l7policy(listener_id, 'REDIRECT_TO_POOL',
                             redirect_pool_id=protected,
                             tcp_tls_passthrough=True, status=400)
        terminate = self.create_l7policy(
            listener_id, 'REDIRECT_TO_POOL',
            redirect_pool_id=protected)['l7policy']
        self.assertIs(False, terminate[passthrough])
        self.set_lb_status(lb_id)
        self.create_l7rule(terminate['id'], 'TLS_SNI', 'EQUAL_TO',
                           'tls.example.com')
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(
            listener_id, 'REDIRECT_TO_POOL', redirect_pool_id=plain,
            tcp_tls_passthrough=True)['l7policy']
        self.assertTrue(policy[passthrough])
        self.assertTrue(rpc.return_value.cast.call_args.kwargs['l7policy'][
            passthrough])
        self.set_lb_status(lb_id)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.assertIs(True, self.get(policy_path).json['l7policy'][
            passthrough])
        terminate_path = self.L7POLICY_PATH.format(
            l7policy_id=terminate['id'])
        self.assertIs(False, self.get(terminate_path).json['l7policy'][
            passthrough])
        policies = self.get(self.L7POLICIES_PATH, params={
            'listener_id': listener_id}).json['l7policies']
        self.assertEqual({terminate['id']: False, policy['id']: True},
                         {row['id']: row[passthrough] for row in policies})
        self.put(policy_path, {'l7policy': {passthrough: False}}, status=400)
        self.put(policy_path, {'l7policy': {'redirect_pool_id': protected}},
                 status=400)
        self.create_l7rule(policy['id'], 'TLS_SNI', 'ENDS_WITH',
                           '*.example.com', status=501)
        rule = self.create_l7rule(policy['id'], 'TLS_SNI', 'EQUAL_TO',
                                  'abc.example.com')['rule']
        self.set_lb_status(lb_id)
        self.put(self.POOL_PATH.format(pool_id=plain),
                 {'pool': {'tls_enabled': True}}, status=400)
        self.conf.config(group='api_settings',
                         enabled_tcp_tls_mixed_mode_providers=[])
        self.delete(self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=rule['id']))
        self.assertTrue(self.get(path).json['listener'][mode])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_mixed_mode_withdrawal_only(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_tcp_tls_mixed_mode_providers=['amphora'],
            enabled_tls_sni_providers=['amphora'],
            enabled_tls_sni_suffix_providers=['amphora'])
        routes = [
            {'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
             'value': 'abc.example.com'},
            {'type': 'TLS_SNI', 'compare_type': 'ENDS_WITH',
             'value': '*.example.com'},
        ]
        listener = {
            'protocol': 'TCP', 'protocol_port': 443,
            'tcp_tls_termination': True, 'tcp_tls_mixed_mode': True,
            'default_tls_container_ref': uuidutils.generate_uuid(),
            'l7policies': [{
                'action': 'REDIRECT_TO_POOL',
                'redirect_pool': {'name': 'target'},
                'rules': routes, 'tcp_tls_passthrough': True,
            }, {
                'action': 'REDIRECT_TO_POOL',
                'redirect_pool': {'name': 'target'},
                'rules': [{'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                           'value': 'terminate.example.org'}],
            }],
        }
        lb = self.post(self.LBS_PATH, {'loadbalancer': {
            'project_id': uuidutils.generate_uuid(), 'provider': 'amphora',
            'vip_subnet_id': uuidutils.generate_uuid(),
            'listeners': [listener], 'pools': [{
                'name': 'target', 'protocol': 'TCP',
                'lb_algorithm': 'ROUND_ROBIN',
            }],
        }}).json['loadbalancer']
        lb_id = lb['id']
        pool_id = lb['pools'][0]['id']
        pass_policy, term_policy = lb['listeners'][0]['l7policies']
        self.assertIs(True, pass_policy['tcp_tls_passthrough'])
        self.assertIs(False, term_policy['tcp_tls_passthrough'])
        rule_paths = {
            rule['compare_type']: self.L7RULE_PATH.format(
                l7policy_id=pass_policy['id'], l7rule_id=rule['id'])
            for rule in pass_policy['rules']
        }
        match = rule_paths['EQUAL_TO']
        suffix = rule_paths['ENDS_WITH']

        self.set_lb_status(lb_id)
        member = self.create_member(
            pool_id, '192.0.2.10', 443, weight=5)['member']
        self.set_lb_status(lb_id)
        member_path = self.MEMBER_PATH.format(
            pool_id=pool_id, member_id=member['id'])
        members_path = self.MEMBERS_PATH.format(pool_id=pool_id)
        self.conf.config(group='api_settings',
                         enabled_tcp_tls_mixed_mode_providers=[])
        self.put(match, {'rule': {'admin_state_up': False}}, status=501)
        self.delete(match, status=501)
        self.assertTrue(self.get(match).json['rule']['admin_state_up'])

        self.create_member(pool_id, '192.0.2.11', 443, status=501)
        self.put(member_path, {'member': {'weight': 0}})
        self.set_lb_status(lb_id)
        self.put(member_path, {'member': {'weight': 1}}, status=501)
        existing = {'address': '192.0.2.10', 'protocol_port': 443, 'weight': 1}
        self.put(members_path, {'members': [existing]}, status=501)
        new = dict(existing, address='192.0.2.11')
        self.put(members_path + '?additive_only=true',
                 {'members': [new]}, status=501)
        self.put(member_path, {'member': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(member_path,
                 {'member': {'admin_state_up': True, 'weight': 1}},
                 status=501)
        self.put(members_path, {'members': []}, status=202)
        self.set_lb_status(lb_id)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_mixed_mode_providers=['amphora'],
                         enabled_tls_sni_suffix_providers=[])
        self.put(match, {'rule': {'admin_state_up': False}}, status=501)
        self.delete(match, status=501)
        self.assertTrue(self.get(match).json['rule']['admin_state_up'])
        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=['amphora'])
        self.delete(match)
        self.set_lb_status(lb_id)
        self.conf.config(group='api_settings',
                         enabled_tcp_tls_mixed_mode_providers=[])
        self.put(suffix, {'rule': {'admin_state_up': False}})

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_backend_auth_admission_and_withdrawal(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_tcp_tls_backend_auth_providers=['amphora', 'noop_driver'],
            enabled_tls_sni_providers=['amphora'],
            allow_ping_health_monitors=True)
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        capability_path = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        capability = 'tcp_tls_backend_auth_v1'
        self.assertNotIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.set_lb_status(lb_id)
        args = lb_id, 'TCP', 'ROUND_ROBIN'
        protected = {'tls_enabled': True,
                     'backend_tls_hostname': 'abc.example.com',
                     'ca_tls_container_ref': uuidutils.generate_uuid()}
        self.create_pool(*args, **protected, status=501)
        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=['amphora'])
        self.assertIn(capability, self.get(capability_path.format(
            'amphora')).json['gateway_capabilities'])
        self.assertNotIn(capability, self.get(capability_path.format(
            'noop_driver')).json['gateway_capabilities'])
        self.create_pool(*args, **dict(protected, ca_tls_container_ref=None),
                         status=400)
        listener = self.create_listener(
            'TCP', 443, lb_id, tcp_tls_termination=True,
            default_tls_container_ref=uuidutils.generate_uuid())['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(*args, **protected)['pool']
        pool_id = pool['id']
        pool_path = self.POOL_PATH.format(pool_id=pool_id)
        self.set_lb_status(lb_id)
        self.assertEqual('abc.example.com', rpc.return_value.cast.call_args
                         .kwargs['pool']['backend_tls_hostname'])

        passthrough = self.create_listener('TCP', 8443, lb_id)['listener']
        self.set_lb_status(lb_id)
        self.create_listener('TCP', 9443, lb_id, default_pool_id=pool_id,
                             status=400)
        passthrough_path = self.LISTENER_PATH.format(
            listener_id=passthrough['id'])
        self.put(passthrough_path, {'listener': {'default_pool_id': pool_id}},
                 status=400)
        self.create_l7policy(passthrough['id'], 'REDIRECT_TO_POOL',
                             redirect_pool_id=pool_id, status=400)
        self.create_pool(*args, listener_id=passthrough['id'], **protected,
                         status=400)

        self.create_health_monitor(pool_id, 'PING', 5, 2, 2, 2, status=400)
        self.create_health_monitor(pool_id, 'TCP', 5, 2, 2, 2)
        self.set_lb_status(lb_id)
        member = self.create_member(
            pool_id, '192.0.2.10', 8443)['member']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(
            listener['id'], 'REDIRECT_TO_POOL',
            redirect_pool_id=pool_id)['l7policy']
        self.set_lb_status(lb_id)
        rule = self.create_l7rule(
            policy['id'], 'TLS_SNI', 'EQUAL_TO', 'tls.example.com')['rule']
        self.set_lb_status(lb_id)
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        self.put(listener_path, {'listener': {'default_pool_id': pool_id}})
        self.set_lb_status(lb_id)
        self.put(pool_path, {'pool': {'tls_enabled': False}}, status=400)

        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=[])
        ca_ref = protected['ca_tls_container_ref']
        self.put(pool_path, {'pool': {'ca_tls_container_ref': ca_ref}})
        self.set_lb_status(lb_id)
        new_ca_ref = uuidutils.generate_uuid()
        ca_update = {'pool': {'ca_tls_container_ref': new_ca_ref}}
        self.put(pool_path, ca_update, status=501)
        self.assertEqual(ca_ref, self.get(pool_path).json['pool'][
            'ca_tls_container_ref'])
        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=['amphora'])
        self.put(pool_path, ca_update)
        self.set_lb_status(lb_id)
        self.assertEqual(new_ca_ref, self.get(pool_path).json['pool'][
            'ca_tls_container_ref'])
        self.conf.config(group='api_settings',
                         enabled_tcp_tls_backend_auth_providers=[])
        self.create_member(pool_id, '192.0.2.11', 8443, status=501)
        members_path = self.MEMBERS_PATH.format(pool_id=pool_id)
        member_path = self.MEMBER_PATH.format(
            pool_id=pool_id, member_id=member['id'])
        # Older members can have a NULL weight, which uses the default.
        with self.session.begin():
            self.session.get(models.Member, member['id']).weight = None
        self.put(member_path, {'member': {'name': 'draining'}})
        self.set_lb_status(lb_id)
        self.put(member_path, {'member': {'weight': 0}})
        self.set_lb_status(lb_id)
        self.put(member_path, {'member': {'weight': 1}}, status=501)
        self.put(member_path, {'member': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(member_path, {'member': {
            'admin_state_up': True, 'weight': 1}}, status=501)
        candidate = {'address': '192.0.2.10', 'protocol_port': 8443}
        self.put(members_path, {'members': [candidate]}, status=501)
        new_member = dict(candidate, address='192.0.2.12')
        self.put(members_path + '?additive_only=true',
                 {'members': [new_member]}, status=501)
        self.assertEqual([member['id']], [
            row['id'] for row in self.get(members_path).json['members']])
        self.assertFalse(
            self.get(member_path).json['member']['admin_state_up'])
        self.put(members_path, {'members': []}, status=202)
        self.set_lb_status(lb_id)
        rule_path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                            l7rule_id=rule['id'])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        lb_path = self.LB_PATH.format(lb_id=lb_id)
        for resource, path in (
                ('loadbalancer', lb_path), ('listener', listener_path),
                ('l7policy', policy_path), ('rule', rule_path),
                ('pool', pool_path)):
            with self.subTest(resource=resource):
                self.put(path, {resource: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                self.put(path, {resource: {'admin_state_up': True}},
                         status=501)
                current = self.get(path).json[resource]
                self.assertFalse(current['admin_state_up'])
        self.put(pool_path, {'pool': {'backend_tls_hostname': None,
                                      'tls_enabled': False}}, status=400)
        self.put(listener_path, {'listener': {'default_pool_id': None}})
        self.set_lb_status(lb_id)
        self.delete(rule_path)
        self.set_lb_status(lb_id)
        self.delete(policy_path)
        database_tasks.DeleteL7PolicyInDB().execute(
            {constants.L7POLICY_ID: policy['id']})
        self.set_lb_status(lb_id)
        self.put(pool_path, {'pool': {'backend_tls_hostname': None,
                                      'tls_enabled': False}})
        self.set_lb_status(lb_id)
        self.delete(pool_path)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_backend_auth_upgrades_existing_pool(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'],
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_tcp_tls_backend_auth_providers=['amphora'],
            allow_ping_health_monitors=True)
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener(
            'TCP', 443, lb_id, tcp_tls_termination=True,
            default_tls_container_ref=uuidutils.generate_uuid())['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(
            lb_id, 'TCP', 'ROUND_ROBIN', listener_id=listener['id'])['pool']
        pool_id = pool['id']
        self.set_lb_status(lb_id)
        monitor = self.create_health_monitor(
            pool_id, 'PING', 5, 2, 2, 2)['healthmonitor']
        self.set_lb_status(lb_id)
        member = self.create_member(
            pool_id, '192.0.2.10', 8443, monitor_port=9443)['member']
        self.set_lb_status(lb_id)

        monitor_path = self.HM_PATH.format(healthmonitor_id=monitor['id'])
        pool_path = self.POOL_PATH.format(pool_id=pool_id)
        auth = {'pool': {'tls_enabled': True,
                         'backend_tls_hostname': 'abc.example.com',
                         'ca_tls_container_ref': uuidutils.generate_uuid()}}
        self.put(pool_path, auth, status=400)
        self.put(monitor_path, {'healthmonitor': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        result = self.put(pool_path, auth).json['pool']
        self.assertEqual('abc.example.com', result['backend_tls_hostname'])
        self.set_lb_status(lb_id)
        self.put(monitor_path, {'healthmonitor': {'admin_state_up': True}},
                 status=400)
        member_path = self.MEMBER_PATH.format(
            pool_id=pool_id, member_id=member['id'])
        updated = self.put(member_path, {'member': {'weight': 2}}).json[
            'member']
        self.assertEqual(9443, updated['monitor_port'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tcp_tls_termination_nested_create(self, rpc, certs):
        certs.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='test')}
        pool = {'name': 'cleartext', 'protocol': 'TCP',
                'lb_algorithm': 'ROUND_ROBIN'}
        listener = {
            'protocol': 'TCP', 'protocol_port': 443,
            'tcp_tls_termination': True,
            'default_tls_container_ref': uuidutils.generate_uuid(),
            'l7policies': [{
                'action': 'REDIRECT_TO_POOL',
                'redirect_pool': {'name': pool['name']},
                'rules': [{'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                           'value': 'a.example.test'}],
            }],
        }
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener], 'pools': [pool]}}
        rpc.return_value.cast.reset_mock()
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_termination_providers=['amphora'])
        pool['tls_enabled'] = True
        self.post(self.LBS_PATH, body, status=400)
        rpc.return_value.cast.assert_not_called()
        pool['tls_enabled'] = False
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved = lb['listeners'][0]
        self.assertTrue(saved['tcp_tls_termination'])
        policy = saved['l7policies'][0]
        self.assertNotIn('tcp_tls_passthrough', policy)
        self.assertEqual('a.example.test', policy['rules'][0]['value'])
        self.assertEqual(lb['pools'][0]['id'], policy['redirect_pool_id'])
        listener_path = self.LISTENER_PATH.format(listener_id=saved['id'])
        self.assertTrue(self.get(listener_path).json['listener'][
            'tcp_tls_termination'])

        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        pool.update(tls_enabled=True, backend_tls_hostname='abc.example.com',
                    ca_tls_container_ref=uuidutils.generate_uuid())
        listener['default_pool'] = {'name': pool['name']}
        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=['amphora'])
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(
            group='api_settings',
            enabled_tcp_tls_backend_auth_providers=['amphora'])
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        backend = lb['pools'][0]
        self.assertEqual('abc.example.com', backend['backend_tls_hostname'])
        self.assertEqual(backend['id'], lb['listeners'][0]['default_pool_id'])
        self.assertEqual(
            backend['id'],
            lb['listeners'][0]['l7policies'][0]['redirect_pool_id'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_tls_sni_nested_create(self, rpc):
        project_id = uuidutils.generate_uuid()
        pool = {'name': 'passthrough', 'protocol': 'TCP',
                'lb_algorithm': 'ROUND_ROBIN'}
        rule = {'type': 'TLS_SNI', 'compare_type': 'EQUAL_TO',
                'value': 'a.example.test'}
        policy = {'action': 'REDIRECT_TO_POOL',
                  'redirect_pool': {'name': pool['name']}, 'rules': [rule]}
        listener = {'name': 'sni', 'protocol': 'TCP', 'protocol_port': 443,
                    'l7policies': [policy]}
        body = {'loadbalancer': {'project_id': project_id,
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener], 'pools': [pool]}}
        driver = 'octavia.api.drivers.amphora_driver.v2.driver'
        create_vip = f'{driver}.AmphoraProviderDriver.create_vip_port'
        with mock.patch(create_vip) as vip:
            self.post(self.LBS_PATH, body, status=501)
            self.conf.config(group='api_settings',
                             enabled_tls_sni_providers=['amphora'])
            listener['protocol'] = 'HTTP'
            self.post(self.LBS_PATH, body, status=400)
            listener['protocol'] = 'TCP'
            pool['protocol'] = 'PROXY'
            self.post(self.LBS_PATH, body, status=400)
            vip.assert_not_called()
            rpc.return_value.cast.assert_not_called()

        pool['protocol'] = 'TCP'
        load_balancer = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved_policy = load_balancer['listeners'][0]['l7policies'][0]
        self.assertEqual('TLS_SNI', saved_policy['rules'][0]['type'])
        self.assertEqual(load_balancer['pools'][0]['id'],
                         saved_policy['redirect_pool_id'])

        rule.update(compare_type='ENDS_WITH', value='*.example.test')
        with mock.patch(create_vip) as vip:
            self.post(self.LBS_PATH, body, status=501)
            vip.assert_not_called()
        self.conf.config(group='api_settings',
                         enabled_tls_sni_suffix_providers=['amphora'])
        load_balancer = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved_policy = load_balancer['listeners'][0]['l7policies'][0]
        self.assertEqual('ENDS_WITH',
                         saved_policy['rules'][0]['compare_type'])
        self.assertEqual('*.example.test', saved_policy['rules'][0]['value'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_http_method_rule_nested_load_balancer_create(self, rpc):
        rule = {'type': 'HTTP_METHOD', 'compare_type': 'EQUAL_TO',
                'value': 'POST'}
        policy = {'action': 'REJECT', 'rules': [rule]}
        listener = {'protocol': 'HTTP', 'protocol_port': 80,
                    'l7policies': [policy]}
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(group='api_settings',
                         enabled_http_method_match_providers=['amphora'])
        listener['protocol'] = 'TCP'
        self.post(self.LBS_PATH, body, status=400)
        listener['protocol'] = 'HTTP'
        rule['value'] = 'post'
        self.post(self.LBS_PATH, body, status=400)
        rpc.return_value.cast.assert_not_called()
        rule['value'] = 'POST'
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved_rule = lb['listeners'][0]['l7policies'][0]['rules'][0]
        self.assertEqual(rule, {key: saved_rule[key] for key in rule})

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_full_header_rule_nested_load_balancer_create(self, rpc):
        rule = {'type': 'HTTP_HEADER_EXACT', 'compare_type': 'EQUAL_TO',
                'key': 'X-Version', 'value': 'one, other'}
        policy = {'action': 'REJECT', 'rules': [rule]}
        listener = {'protocol': 'HTTP', 'protocol_port': 80,
                    'l7policies': [policy]}
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(group='api_settings',
                         enabled_http_header_exact_providers=['amphora'])
        listener['protocol'] = 'TCP'
        self.post(self.LBS_PATH, body, status=400)
        listener['protocol'] = 'HTTP'
        original_key = rule['key']
        rule['key'] = 'X-' + 'a' * 254
        self.post(self.LBS_PATH, body, status=400)
        rpc.return_value.cast.assert_not_called()
        rule['key'] = original_key
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved_rule = lb['listeners'][0]['l7policies'][0]['rules'][0]
        self.assertEqual(rule, {key: saved_rule[key] for key in rule})

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_query_param_rule_nested_load_balancer_create(self, rpc):
        rule = {'type': 'HTTP_QUERY_PARAM_EXACT', 'compare_type': 'EQUAL_TO',
                'key': 'X&Version', 'value': 'one\r\ntwo'}
        policy = {'action': 'REJECT', 'rules': [rule]}
        listener = {'protocol': 'HTTP', 'protocol_port': 80,
                    'l7policies': [policy]}
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(group='api_settings',
                         enabled_http_query_param_exact_providers=['amphora'])
        listener['protocol'] = 'TCP'
        self.post(self.LBS_PATH, body, status=400)
        rpc.return_value.cast.assert_not_called()
        listener['protocol'] = 'HTTP'
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved_rule = lb['listeners'][0]['l7policies'][0]['rules'][0]
        self.assertEqual(rule, {key: saved_rule[key] for key in rule})

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_grpc_content_type_rule_nested_load_balancer_create(self, rpc):
        rule = {'type': 'GRPC_CONTENT_TYPE', 'compare_type': 'EQUAL_TO',
                'value': 'application/grpc'}
        policy = {'action': 'REDIRECT_TO_POOL', 'rules': [rule],
                  'redirect_pool': {'name': 'grpc-echo', 'protocol': 'HTTP',
                                    'lb_algorithm': 'ROUND_ROBIN'}}
        listener = {'protocol': 'HTTP', 'protocol_port': 80,
                    'l7policies': [policy]}
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(
            group='api_settings',
            enabled_grpc_content_type_providers=['amphora'],
            enabled_response_header_operation_providers=['amphora'])
        listener['protocol'] = 'TCP'
        self.post(self.LBS_PATH, body, status=400)
        listener['protocol'] = 'HTTP'
        metadata = {'operation': 'ADD', 'name': 'trace-bin',
                    'value': ', '.join(['Yg'] * 49)}
        policy['response_header_operations'] = [metadata]
        rejected = self.post(self.LBS_PATH, body, status=400)
        self.assertIn('48 fields', rejected.json['faultstring'])
        rpc.return_value.cast.assert_not_called()
        metadata['value'] = ', '.join(['Yg'] * 48)
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']
        saved = lb['listeners'][0]['l7policies'][0]
        saved_rule = saved['rules'][0]
        self.assertEqual(rule, {key: saved_rule[key] for key in rule})
        self.assertEqual([metadata], saved['response_header_operations'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_grpc_binary_request_fields_on_rule_and_target(self, rpc):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_grpc_content_type_providers=['amphora'],
            enabled_request_header_operation_providers=['amphora'],
            enabled_weighted_target_request_filter_providers=['amphora'],
            enabled_l7policy_initial_rules_providers=['amphora'])
        balancer = self.create_load_balancer(uuidutils.generate_uuid(),
                                             provider='amphora')
        lb = balancer['loadbalancer']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        rule = {'type': 'GRPC_CONTENT_TYPE', 'compare_type': 'EQUAL_TO',
                'value': 'application/grpc'}
        field = 'request_header_operations'
        limit = {'operation': 'SET', 'name': 'trace-bin',
                 'value': ','.join(['YQ'] * 48)}
        over = dict(limit, value=limit['value'] + ',Yg')
        target = {'weight': 1, 'pool_id': pool}
        opts = {'admin_state_up': False, 'targets': [
            target, dict(target, **{field: [limit]})]}
        rpc.return_value.cast.reset_mock()
        self.create_l7policy(listener, 'WEIGHTED_TARGETS', rules=[rule],
                             status=400, **opts, **{field: [over]})
        rpc.return_value.cast.assert_not_called()
        # Each list on a selected request has an independent budget.
        policy = self.create_l7policy(
            listener, 'WEIGHTED_TARGETS', rules=[rule],
            **opts, **{field: [limit]})['l7policy']
        self.set_lb_status(lb)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        bad_targets = [target, dict(target, **{field: [over]})]
        self.put(path, {'l7policy': {'targets': bad_targets}}, status=400)
        self.assertEqual(opts['targets'], self.get(path).json['l7policy'][
            'targets'])
        # An upgraded policy may already have an over-budget occurrence.
        # Removing a sibling can retain it, duplicating it is a new write.
        with self.session.begin():
            self.l7policy_repo.update(self.session, policy['id'],
                                      targets=bad_targets,
                                      request_header_operations=[over])
        legacy_target = bad_targets[1]
        self.put(path, {'l7policy': {'targets': [legacy_target],
                                     field: [over]}})
        self.set_lb_status(lb)
        self.put(path, {'l7policy': {'targets': [legacy_target] * 2}},
                 status=400)
        self.assertEqual([legacy_target],
                         self.get(path).json['l7policy']['targets'])
        self.put(path, {'l7policy': {'targets': [target], field: []}})
        self.set_lb_status(lb)
        # A disabled staged HTTP policy can receive ordinary literal values.
        staged = self.create_l7policy(
            listener, 'WEIGHTED_TARGETS', admin_state_up=False,
            targets=bad_targets)['l7policy']['id']
        self.set_lb_status(lb)
        self.create_l7rule(staged, rule['type'], rule['compare_type'],
                           rule['value'], status=400)
        staged_path = self.L7POLICY_PATH.format(l7policy_id=staged)
        self.put(staged_path, {'l7policy': {'targets': opts['targets']}})
        self.set_lb_status(lb)
        self.create_l7rule(staged, rule['type'], rule['compare_type'],
                           rule['value'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_grpc_binary_request_metadata_withdrawal(self, rpc):
        self.conf.config(
            group='api_settings', enabled_gateway_action_providers=['amphora'],
            enabled_grpc_content_type_providers=['amphora'],
            enabled_request_header_operation_providers=['amphora'],
            enabled_weighted_target_request_filter_providers=['amphora'],
            enabled_l7policy_initial_rules_providers=['amphora'])
        balancer = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')
        lb = balancer['loadbalancer']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        ordinary = {'weight': 1, 'pool_id': pool}
        rule = {'type': 'GRPC_CONTENT_TYPE', 'compare_type': 'EQUAL_TO',
                'value': 'application/grpc'}
        policy = self.create_l7policy(
            listener, 'WEIGHTED_TARGETS', rules=[rule],
            admin_state_up=False, targets=[ordinary])['l7policy']
        self.set_lb_status(lb)
        path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.put(path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb)
        field = 'request_header_operations'
        metadata = {'operation': 'SET', 'name': 'trace-bin',
                    'value': 'YQ==,Yg=='}
        filtered = dict(ordinary, **{field: [metadata]})
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=[])
        rpc.return_value.cast.reset_mock()
        before = self.get(path).json
        for update in ({field: [metadata]}, {'targets': [filtered]}):
            rejected = self.put(path, {'l7policy': update}, status=501)
            self.assertIn('Binary gRPC request metadata',
                          rejected.json['faultstring'])
        rpc.return_value.cast.assert_not_called()
        self.assertEqual(before, self.get(path).json)

        controls = [dict(metadata, value='YQ=='),
                    dict(metadata, name='x-trace')]
        self.put(path, {'l7policy': {field: controls}})
        self.set_lb_status(lb)
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=['amphora'])
        active = {field: [metadata], 'targets': [ordinary, filtered]}
        self.put(path, {'l7policy': active})
        self.set_lb_status(lb)

        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=[])
        self.put(path, {'l7policy': active})
        self.set_lb_status(lb)
        rpc.return_value.cast.reset_mock()
        self.put(path, {'l7policy': {'targets': [filtered]}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertEqual(active['targets'],
                         self.get(path).json['l7policy']['targets'])

        pool_path = self.POOL_PATH.format(pool_id=pool)
        self.put(pool_path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(lb)
        rpc.return_value.cast.reset_mock()
        self.put(pool_path, {'pool': {'admin_state_up': True}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.put(path, {'l7policy': {'targets': [ordinary], field: controls}})
        self.set_lb_status(lb)
        self.put(pool_path, {'pool': {'admin_state_up': True}})
        self.assertEqual(controls, self.get(path).json['l7policy'][field])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.'
                'AmphoraProviderDriver.supports_grpc_binary_request_metadata',
                False)
    def test_grpc_binary_request_metadata_requires_driver_support(self, rpc):
        self.conf.config(
            group='api_settings',
            enabled_grpc_content_type_providers=['amphora'],
            enabled_request_header_operation_providers=['amphora'],
            enabled_l7policy_initial_rules_providers=['amphora'])
        rule = {'type': 'GRPC_CONTENT_TYPE', 'compare_type': 'EQUAL_TO',
                'value': 'application/grpc'}
        headers = [{'operation': 'ADD', 'name': 'trace-bin',
                    'value': 'YQ==,Yg=='}]
        options = {'action': 'REDIRECT_TO_POOL', 'rules': [rule],
                   'request_header_operations': headers}
        listener = {
            'protocol': 'HTTP', 'protocol_port': 80,
            'l7policies': [dict(options, redirect_pool={
                'name': 'grpc-echo', 'protocol': 'HTTP',
                'lb_algorithm': 'ROUND_ROBIN'})]}
        body = {'loadbalancer': {'project_id': uuidutils.generate_uuid(),
                                 'provider': 'amphora',
                                 'vip_subnet_id': uuidutils.generate_uuid(),
                                 'listeners': [listener]}}
        rejected = self.post(self.LBS_PATH, body, status=501)
        self.assertIn('Binary gRPC request metadata',
                      rejected.json['faultstring'])
        rpc.return_value.cast.assert_not_called()

        del body['loadbalancer']['listeners']
        lb = self.post(self.LBS_PATH, body).json['loadbalancer']['id']
        self.set_lb_status(lb)
        listener = self.create_listener('HTTP', 80, lb)['listener']['id']
        self.set_lb_status(lb)
        pool = self.create_pool(lb, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb)
        body = {'l7policy': dict(options, listener_id=listener,
                                 redirect_pool_id=pool, admin_state_up=False)}
        rpc.return_value.cast.reset_mock()
        self.post(self.L7POLICIES_PATH, body, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertEqual([], self.get(self.L7POLICIES_PATH).json['l7policies'])

        # A comma-separated HTTP value can be staged before a native rule.
        del body['l7policy']['rules']
        policy = self.post(self.L7POLICIES_PATH, body).json['l7policy']
        self.set_lb_status(lb)
        rules = self.L7RULES_PATH.format(l7policy_id=policy['id'])
        rpc.return_value.cast.reset_mock()
        self.post(rules, {'rule': rule}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertEqual([], self.get(rules).json['rules'])

        staged = self.post(rules, {'rule': dict(rule, admin_state_up=False)})
        self.set_lb_status(lb)
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=policy['id'], l7rule_id=staged.json['rule']['id'])
        rpc.return_value.cast.reset_mock()
        self.put(rule_path, {'rule': {'admin_state_up': True}}, status=501)
        rpc.return_value.cast.assert_not_called()
        self.assertFalse(self.get(rule_path).json['rule']['admin_state_up'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_grpc_binary_response_header_field_limit(self, rpc):
        self.conf.config(
            group='api_settings',
            enabled_grpc_content_type_providers=['amphora'],
            enabled_response_header_operation_providers=['amphora'],
            enabled_l7policy_initial_rules_providers=['amphora'])
        lb = self.create_load_balancer(uuidutils.generate_uuid(),
                                       provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener_id = self.create_listener('HTTP', 80, lb_id)['listener']['id']
        self.set_lb_status(lb_id)
        pool_id = self.create_pool(lb_id, 'HTTP', 'ROUND_ROBIN')['pool']['id']
        self.set_lb_status(lb_id)
        rule = {'type': 'GRPC_CONTENT_TYPE', 'compare_type': 'EQUAL_TO',
                'value': 'application/grpc'}
        field = 'response_header_operations'
        limit = [{'operation': 'SET', 'name': 'replace-bin',
                  'value': ', '.join(['YQ=='] * 24)},
                 {'operation': 'ADD', 'name': 'trace-bin',
                  'value': ', '.join(['Yg'] * 24)},
                 {'operation': 'REMOVE', 'name': 'x-old'}]
        over = [limit[0], dict(limit[1], value=limit[1]['value'] + ', Yg'),
                limit[2]]
        opts = {'redirect_pool_id': pool_id, 'admin_state_up': False}
        rpc.return_value.cast.reset_mock()
        self.create_l7policy(listener_id, 'REDIRECT_TO_POOL', status=400,
                             rules=[rule], **opts, **{field: over})
        rpc.return_value.cast.assert_not_called()
        policy_id = self.create_l7policy(
            listener_id, 'REDIRECT_TO_POOL', rules=[rule],
            **opts, **{field: limit})['l7policy']['id']
        self.set_lb_status(lb_id)
        path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        self.put(path, {'l7policy': {field: over}}, status=400)
        self.assertEqual(limit, self.get(path).json['l7policy'][field])

        # The same value is literal until an active native rule is installed.
        created = self.create_l7policy(listener_id, 'REDIRECT_TO_POOL',
                                       **opts, **{field: over})
        ordinary = created['l7policy']
        self.assertEqual(over, ordinary[field])
        self.set_lb_status(lb_id)
        ordinary_id = ordinary['id']
        self.create_l7rule(ordinary_id, rule['type'], rule['compare_type'],
                           rule['value'], status=400)
        legacy = self.create_l7rule(ordinary_id, 'PATH', 'EQUAL_TO', '/legacy')
        self.set_lb_status(lb_id)
        rule_path = self.L7RULE_PATH.format(
            l7policy_id=ordinary_id, l7rule_id=legacy['rule']['id'])
        self.put(rule_path, {'rule': rule}, status=400)
        ordinary_path = self.L7POLICY_PATH.format(l7policy_id=ordinary_id)
        self.put(ordinary_path, {'l7policy': {field: limit}})
        self.set_lb_status(lb_id)
        self.put(rule_path, {'rule': rule})
