#    Copyright 2014 Rackspace
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

from unittest import mock

from oslo_utils import uuidutils

from octavia.amphorae.drivers.noop_driver import driver as amphora_noop
from octavia.api.v2.controllers import member
from octavia.common import constants
from octavia.common import exceptions
from octavia.common.jinja.haproxy.combined_listeners import jinja_cfg
from octavia.controller.queue.v2 import endpoints
from octavia.db import api as db_api
from octavia.network import data_models as network_models
from octavia.network.drivers.noop_driver import driver as network_noop
from octavia.tests.functional.api.v2 import base


class TestTCPConnectionRejection(base.BaseAPITest):

    def setUp(self):
        super().setUp()
        rpc = mock.patch('octavia.common.rpc.get_client')
        self.rpc = rpc.start().return_value
        self.addCleanup(rpc.stop)
        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_noop_driver')
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        self.lb_id = lb['id']
        self.set_lb_status(self.lb_id)
        self.listener_id = self.create_listener(
            'TCP', 8080, self.lb_id)['listener']['id']
        self.set_lb_status(self.lb_id)
        self.pool_id = self._create_pool('TCP', listener_id=self.listener_id)
        self.pool_path = self.POOL_PATH.format(pool_id=self.pool_id)
        self.batch_path = self.MEMBERS_PATH.format(pool_id=self.pool_id)
        amphora_id = uuidutils.generate_uuid()
        with db_api.session().begin() as session:
            self.amphora_repo.create(
                session, id=amphora_id,
                load_balancer_id=self.lb_id,
                status=constants.AMPHORA_ALLOCATED, lb_network_ip='192.0.2.10',
                compute_id=uuidutils.generate_uuid())
        nic = network_models.Interface(
            network_id=lb['vip_network_id'], fixed_ips=[
                network_models.FixedIP(subnet_id=lb['vip_subnet_id'])])
        amp_configs = {amphora_id: network_models.AmphoraNetworkConfig()}
        for method, result in [('get_plugged_networks', [nic]),
                               ('get_network_configs', amp_configs)]:
            patch = mock.patch.object(network_noop.NoopNetworkDriver, method,
                                      return_value=result)
            patch.start()
            self.addCleanup(patch.stop)
        self.rpc.cast.reset_mock()

    def _enroll(self, enabled=True):
        self.conf.config(
            group='api_settings', enabled_tcp_connection_rejection_providers=(
                ['amphora', 'noop_driver'] if enabled else []))

    def _create_pool(self, protocol, **kwargs):
        pool = self.create_pool(
            self.lb_id, protocol, 'ROUND_ROBIN', **kwargs)['pool']
        self.set_lb_status(self.lb_id)
        return pool['id']

    def _batch(self, rejection, members=(), status=202):
        self.put(self.batch_path, {
            'members': list(members),
            'tcp_connection_rejection': rejection,
        }, status=status)
        if status == 202:
            args = self.rpc.cast.call_args
            self.assertEqual(({}, 'apply_tcp_member_batch'), args.args)
            return args.kwargs
        return None

    def _pool(self):
        return self.get(self.pool_path).json['pool']

    @staticmethod
    def _render(graph):
        return jinja_cfg.JinjaTemplater().build_config(
            graph.amphorae[0], graph.listeners, {}, ['3', '0'], {})

    def test_batch_rejection_and_members_activate_together(self):
        self._enroll()
        independent_listener = self.create_listener(
            'TCP', 8081, self.lb_id)['listener']['id']
        self.set_lb_status(self.lb_id)
        independent_pool = self._create_pool(
            'TCP', listener_id=independent_listener)
        self.create_member(independent_pool, '192.0.2.99', 9000)
        self.set_lb_status(self.lb_id)
        member_address = {'address': '192.0.2.3', 'protocol_port': 9000}
        one_invalid = {'reject_weight': 1, 'total_weight': 4}
        worker = endpoints.Endpoints()

        rendered = []

        def render(graph):
            config = self._render(graph)
            self.assertIn('192.0.2.99:9000', config)
            rendered.append(config)

        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=render):
            first = self._batch(one_invalid, [member_address])
            self.assertEqual(constants.PENDING_UPDATE,
                             self._pool()['provisioning_status'])
            self.assertEqual(one_invalid,
                             self._pool()['tcp_connection_rejection'])
            self._batch(one_invalid, [member_address], status=409)
            worker.apply_tcp_member_batch({}, **first)
            worker.apply_tcp_member_batch({}, **first)
            self.assertEqual(1, len(rendered))
            self.assertIn('rand(4)', rendered[-1])
            self.assertIn('-m int lt 1', rendered[-1])
            self.assertIn('192.0.2.3:9000', rendered[-1])

            all_invalid = {'reject_weight': 4, 'total_weight': 4}
            worker.apply_tcp_member_batch({}, **self._batch(all_invalid))
            self.assertIn('tcp-request content reject\n', rendered[-1])
            self.assertNotIn('192.0.2.3:9000', rendered[-1])
            self.assertEqual([], self._pool()['members'])

            # This time all member lists are empty before and after update.
            worker.apply_tcp_member_batch({}, **self._batch(
                {'reject_weight': 16000000, 'total_weight': 16000000}))
            self.assertEqual(3, len(rendered))
            self.assertIn('tcp-request content reject\n', rendered[-1])

            zero_rejection = {'reject_weight': 0, 'total_weight': 4}
            worker.apply_tcp_member_batch({}, **self._batch(
                zero_rejection, [member_address]))
            self.assertEqual(zero_rejection,
                             self._pool()['tcp_connection_rejection'])
            self.assertNotIn('tcp-request content reject', rendered[-1])
            self.assertIn('192.0.2.3:9000', rendered[-1])

            self._enroll(False)
            worker.apply_tcp_member_batch({}, **self._batch(
                None, [member_address]))
            self.assertIsNone(self._pool()['tcp_connection_rejection'])
            self.assertEqual(constants.ACTIVE,
                             self._pool()['provisioning_status'])
            listed = {p['id']: p for p in self.get(self.POOLS_PATH).json[
                'pools']}
            self.assertIsNone(
                listed[self.pool_id]['tcp_connection_rejection'])

    def test_default_off_full_batch_and_pool_authorization(self):
        capability = constants.GATEWAY_CAPABILITY_TCP_CONNECTION_REJECTION
        caps_path = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        rejection = {'reject_weight': 1, 'total_weight': 4}
        self.assertNotIn(capability, self.get(
            caps_path.format('amphora')).json['gateway_capabilities'])
        self.assertIsNone(self._pool()['tcp_connection_rejection'])
        self._batch(rejection, status=501)

        self._enroll()
        self.assertIn(capability, self.get(
            caps_path.format('amphora')).json['gateway_capabilities'])
        self.assertNotIn(capability, self.get(
            caps_path.format('noop_driver')).json['gateway_capabilities'])
        for invalid in ({'reject_weight': True, 'total_weight': 4},
                        {'reject_weight': 1, 'total_weight': 4.0},
                        {'reject_weight': 1, 'total_weight': 0},
                        {'reject_weight': 5, 'total_weight': 4},
                        {'reject_weight': 1, 'total_weight': 16000001},
                        {'reject_weight': 1}):
            with self.subTest(rejection=invalid):
                self._batch(invalid, status=400)
        self.put(self.batch_path + '?additive_only=true', {
            'members': [], 'tcp_connection_rejection': None,
        }, status=400)
        http_pool = self._create_pool('HTTP')
        self.put(self.MEMBERS_PATH.format(pool_id=http_pool), {
            'members': [], 'tcp_connection_rejection': rejection,
        }, status=400)

        def authorize(*args, **kwargs):
            if kwargs.get('rbac_type') == constants.RBAC_POOL:
                raise exceptions.PolicyForbidden()

        with mock.patch.object(member.MemberController,
                               '_auth_validate_action', new=authorize):
            self._batch(rejection, status=403)
        self.assertIsNone(self._pool()['tcp_connection_rejection'])

    def test_rollback_retry_and_legacy_omission(self):
        self._enroll()
        member_address = {'address': '192.0.2.3', 'protocol_port': 9000}
        one_invalid = {'reject_weight': 1, 'total_weight': 4}

        self.rpc.cast.side_effect = RuntimeError('messaging unavailable')
        self._batch(one_invalid, [member_address], status=500)
        self.rpc.cast.side_effect = None
        rolled_back = self.rpc.cast.call_args.kwargs
        self.assertIsNone(self._pool()['tcp_connection_rejection'])
        self.assertEqual([], self._pool()['members'])
        self.assertEqual(constants.ACTIVE, self._pool()['provisioning_status'])

        worker = endpoints.Endpoints()
        failed = self._batch(one_invalid, [member_address])
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=RuntimeError('reload')):
            self.assertRaises(RuntimeError, worker.apply_tcp_member_batch,
                              {}, **failed)
        self.assertEqual(one_invalid, self._pool()['tcp_connection_rejection'])
        self.assertEqual(constants.ERROR, self._pool()['provisioning_status'])

        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update') as update:
            # An unrelated admission can put the LB back into PENDING_UPDATE.
            self.set_object_status(self.lb_repo, self.lb_id,
                                   constants.PENDING_UPDATE)
            worker.apply_tcp_member_batch({}, **failed)
            update.assert_not_called()
            self.set_object_status(self.lb_repo, self.lb_id)

            retry = self._batch(one_invalid, [member_address])
            worker.apply_tcp_member_batch({}, **rolled_back)
            worker.apply_tcp_member_batch({}, **failed)
            update.assert_not_called()
            worker.apply_tcp_member_batch({}, **retry)
            update.assert_called_once()
        self.assertEqual(constants.ACTIVE, self._pool()['provisioning_status'])

        self.put(self.batch_path, {'members': [member_address]}, status=202)
        self.assertEqual(({}, 'batch_update_members'),
                         self.rpc.cast.call_args.args)
        self.assertEqual(one_invalid, self._pool()['tcp_connection_rejection'])
