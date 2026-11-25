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

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.amphorae.drivers.noop_driver import driver as amphora_noop
from octavia.common import constants
from octavia.common import policy
from octavia.controller.queue.v2 import endpoints
from octavia.db import api as db_api
from octavia.db import repositories
from octavia.network import data_models as network_models
from octavia.network.drivers.noop_driver import driver as network_noop
from octavia.tests.functional.api.v2 import base


class TestUDPPacketDrop(base.BaseAPITest):

    def setUp(self):
        super().setUp()
        rpc = mock.patch('octavia.common.rpc.get_client')
        self.rpc = rpc.start().return_value
        self.addCleanup(rpc.stop)
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        repositories.QuotasRepository().ensure_project_exists(self.project_id)
        authorize = mock.patch.object(policy, 'get_enforcer')
        authorize.start().return_value.authorize.return_value = True
        self.addCleanup(authorize.stop)
        self.conf.config(group='controller_worker',
                         amphora_driver='amphora_noop_driver')
        self.lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora',
            vip_address='192.0.2.10')['loadbalancer']
        self.lb_id = self.lb['id']
        self.set_lb_status(self.lb_id)
        self.listener_id = self.create_listener(
            'UDP', 8080, self.lb_id)['listener']['id']
        self.set_lb_status(self.lb_id)
        self.pool_id = self.create_pool(
            self.lb_id, 'UDP', 'ROUND_ROBIN',
            listener_id=self.listener_id)['pool']['id']
        self.set_lb_status(self.lb_id)
        self.pool_path = self.POOL_PATH.format(pool_id=self.pool_id)
        self.batch_path = self.MEMBERS_PATH.format(pool_id=self.pool_id)

    def _enroll(self, enabled=True):
        self.conf.config(
            group='api_settings', enabled_udp_packet_drop_providers=(
                ['amphora', 'noop_driver'] if enabled else []))

    def _pool(self):
        return self.get(self.pool_path).json['pool']

    def _batch(self, numerator, denominator, members=(), status=202):
        self.put(self.batch_path, {
            'members': list(members),
            'udp_packet_drop': {'numerator': numerator,
                                'denominator': denominator},
        }, status=status)
        if status == 202:
            args = self.rpc.cast.call_args
            self.assertEqual(({}, 'apply_udp_member_batch'), args.args)
            return args.kwargs
        return None

    def _member_use(self):
        with db_api.session().begin() as session:
            return repositories.QuotasRepository().get_orm(
                session, project_id=self.project_id).in_use_member

    @staticmethod
    def _amphora_support(**kwargs):
        return mock.patch.object(
            amphora_noop.NoopAmphoraLoadBalancerDriver,
            'apply_udp_member_batch', create=True, **kwargs)

    def test_capability_requires_region_and_compatible_driver(self):
        capability = constants.GATEWAY_CAPABILITY_UDP_PACKET_DROP

        def capabilities(provider):
            path = self.PROVIDERS_PATH + f'/{provider}/gateway_capabilities'
            return self.get(path).json['gateway_capabilities']

        self.assertNotIn('udp_packet_drop', self._pool())
        self.assertNotIn(capability, capabilities('amphora'))
        self._enroll()
        self.assertNotIn(capability, capabilities('amphora'))
        self._batch(1, 1, status=501)

        with self._amphora_support():
            self.assertIn(capability, capabilities('amphora'))
            self.assertNotIn(capability, capabilities('noop_driver'))
            for numerator, denominator in ((True, 4), (1, 4.0), (1, 0),
                                           (5, 4), (0, 16000001)):
                with self.subTest(fraction=(numerator, denominator)):
                    self._batch(numerator, denominator, status=400)
            drop = {'numerator': 1, 'denominator': 4}
            member = {'address': '192.0.2.3', 'protocol_port': 9000}
            self._batch(1, 4, status=400)
            self._batch(1, 4, [dict(member, weight=0)], status=400)
            self._batch(1, 4, [dict(member, admin_state_up=False)],
                        status=400)
            self._batch(1, 1, [member], status=400)
            self._batch(1, 4, [dict(member, backup=True)], status=400)
            self.put(self.batch_path + '?additive_only=true', {
                'members': [], 'udp_packet_drop': drop,
            }, status=400)
            self.put(self.batch_path, {
                'members': [], 'udp_packet_drop': None,
            }, status=400)
            self._batch(1, 4, [
                {'address': '2001:db8::1', 'protocol_port': 9000}],
                status=400)
            self._enroll(False)
            self.assertNotIn(capability, capabilities('amphora'))
            self._batch(1, 4, [member], status=501)

        self.put(self.batch_path, {
            'members': [{'address': '192.0.2.3', 'protocol_port': 9000}],
        }, status=202)
        self.assertEqual(({}, 'batch_update_members'),
                         self.rpc.cast.call_args.args)
        self.assertNotIn('udp_packet_drop', self._pool())

    def test_worker_applies_committed_graph_and_retries_failure(self):
        self._enroll()
        amphora_id = uuidutils.generate_uuid()
        with db_api.session().begin() as session:
            self.amphora_repo.create(
                session, id=amphora_id, load_balancer_id=self.lb_id,
                status=constants.AMPHORA_ALLOCATED, lb_network_ip='192.0.2.11',
                compute_id=uuidutils.generate_uuid(),
                role=constants.ROLE_STANDALONE)
        nic = network_models.Interface(
            network_id=self.lb['vip_network_id'], fixed_ips=[
                network_models.FixedIP(subnet_id=self.lb['vip_subnet_id'])])
        amp_configs = {amphora_id: network_models.AmphoraNetworkConfig()}
        self.create_member(self.pool_id, '192.0.2.4', 9000)
        self.set_lb_status(self.lb_id)
        member = {'address': '192.0.2.3', 'protocol_port': 9000}
        observed = []

        def apply(graph, listener_id):
            self.assertEqual(self.listener_id, listener_id)
            listener = next(item for item in graph.listeners
                            if item.id == listener_id)
            pool = listener.default_pool
            desired = {m.ip_address for m in pool.members
                       if m.provisioning_status not in (
                           constants.PENDING_DELETE, constants.DELETED)}
            observed.append((pool.udp_packet_drop, desired))
            return ((amphora_id, constants.ROLE_STANDALONE),)

        with (self._amphora_support(side_effect=apply) as driver,
              mock.patch.object(network_noop.NoopNetworkDriver,
                                'get_plugged_networks', return_value=[nic]),
              mock.patch.object(network_noop.NoopNetworkDriver,
                                'get_network_configs',
                                return_value=amp_configs)):
            worker = endpoints.Endpoints()
            first = self._batch(1, 3, [
                member, {'address': '192.0.2.5', 'protocol_port': 9000}])
            self.assertEqual(2, self._member_use())
            self._enroll(False)
            self._batch(1, 4, [member], status=501)
            self._enroll()
            with db_api.listener_render_lock(self.lb_id) as acquired:
                self.assertTrue(acquired)
                self._batch(1, 3, [
                    member, {'address': '192.0.2.5', 'protocol_port': 9000}],
                    status=409)
                self._batch(1, 4, [member], status=409)
            latest = self._batch(1, 4, [member])
            self.assertNotEqual(first, latest)
            self.assertEqual(latest, self._batch(1, 4, [member]))
            self.assertEqual(1, self._member_use())
            self.assertEqual(constants.PENDING_UPDATE,
                             self._pool()['provisioning_status'])
            worker.apply_tcp_member_batch({}, **latest)
            worker.apply_udp_member_batch({}, **first)
            driver.assert_not_called()
            worker.apply_udp_member_batch({}, **latest)
            worker.apply_udp_member_batch({}, **latest)
            self.assertEqual([({'numerator': 1, 'denominator': 4},
                               {'192.0.2.3'})], observed)
            self.assertEqual(1, len(self._pool()['members']))
            self.assertEqual(constants.ACTIVE,
                             self._pool()['provisioning_status'])

            self.put(self.batch_path, {'members': [member]}, status=400)
            lb_path = self.LB_PATH.format(lb_id=self.lb_id)
            self.assertEqual(constants.ACTIVE, self.get(lb_path).json[
                'loadbalancer']['provisioning_status'])
            self.create_listener('UDP', 8081, self.lb_id, status=400,
                                 default_pool_id=self.pool_id)
            self.assertEqual(constants.ACTIVE, self.get(lb_path).json[
                'loadbalancer']['provisioning_status'])
            self.create_health_monitor(self.pool_id, 'TCP', 5, 3, 2, 2,
                                       status=400)

            failed = self._batch(1, 1)
            driver.side_effect = RuntimeError('reload failed')
            with self.assertRaises(RuntimeError):
                worker.apply_udp_member_batch({}, **failed)
            self.assertEqual(constants.ERROR,
                             self._pool()['provisioning_status'])
            self.assertEqual({'numerator': 1, 'denominator': 1},
                             self._pool()['udp_packet_drop'])

            driver.side_effect = apply
            retry = self._batch(1, 1)
            self.assertNotEqual(failed, retry)
            worker.apply_udp_member_batch({}, **retry)
            self.assertEqual(({'numerator': 1, 'denominator': 1}, set()),
                             observed[-1])
            self.assertEqual([], self._pool()['members'])

            driver.side_effect = None
            driver.return_value = ((amphora_id, constants.ROLE_BACKUP),)
            with self.assertRaises(driver_except.ListenerProvisioningError):
                worker.apply_udp_member_batch(
                    {}, **self._batch(0, 1, [member]))
            self.assertEqual(constants.ERROR,
                             self._pool()['provisioning_status'])
            driver.side_effect = apply
            worker.apply_udp_member_batch({}, **self._batch(0, 1, [member]))
            self.assertEqual(({'numerator': 0, 'denominator': 1},
                              {'192.0.2.3'}), observed[-1])
            self.assertEqual({'numerator': 0, 'denominator': 1},
                             self._pool()['udp_packet_drop'])
            self.assertEqual(constants.ACTIVE,
                             self._pool()['provisioning_status'])

    def test_delete_replaces_pending_batch_after_opt_out(self):
        self._enroll()
        self.create_member(self.pool_id, '192.0.2.4', 9000)
        self.set_lb_status(self.lb_id)
        other_listener_id = self.create_listener(
            'UDP', 8081, self.lb_id)['listener']['id']
        self.set_lb_status(self.lb_id)
        other_pool_id = self.create_pool(
            self.lb_id, 'UDP', 'ROUND_ROBIN',
            listener_id=other_listener_id)['pool']['id']
        self.set_lb_status(self.lb_id)
        self.create_member(other_pool_id, '192.0.2.5', 9000)
        self.set_lb_status(self.lb_id)
        other_pool_path = self.POOL_PATH.format(pool_id=other_pool_id)
        member = {'address': '192.0.2.3', 'protocol_port': 9000}

        with self._amphora_support() as apply:
            abandoned = self._batch(1, 4, [member])
            self._enroll(False)
            self.delete(other_pool_path, status=409)
            with db_api.listener_render_lock(self.lb_id) as acquired:
                self.assertTrue(acquired)
                self.delete(self.pool_path, status=409)
            self.delete(self.pool_path, status=204)
            pending = self.rpc.cast.call_args
            self.assertEqual(({}, 'delete_managed_udp_pool'), pending.args)
            self.assertNotEqual(abandoned['batch_id'],
                                pending.kwargs['batch_id'])
            self.delete(self.pool_path, status=204)
            self.assertEqual(pending, self.rpc.cast.call_args)
            self.assertEqual(constants.PENDING_DELETE,
                             self._pool()['provisioning_status'])
            self.assertEqual(2, self._member_use())
            worker = endpoints.Endpoints()
            worker.apply_udp_member_batch({}, **abandoned)
            apply.assert_not_called()

        def retire(graph, listener_ids):
            self.assertEqual([self.listener_id], listener_ids)
            listener = next(item for item in graph.listeners
                            if item.id == self.listener_id)
            self.assertEqual(constants.PENDING_DELETE,
                             listener.default_pool.provisioning_status)

        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update_udp_pool_listeners', create=True,
                               side_effect=RuntimeError('reload')) as render:
            with self.assertRaises(RuntimeError):
                worker.delete_managed_udp_pool({}, **pending.kwargs)
            self.assertEqual(constants.ERROR,
                             self._pool()['provisioning_status'])
            self.assertEqual(2, self._member_use())
            self.delete(self.pool_path, status=204)
            retry = self.rpc.cast.call_args
            self.assertNotEqual(pending, retry)
            render.reset_mock(side_effect=True)
            render.side_effect = retire
            worker.delete_managed_udp_pool({}, **pending.kwargs)
            worker.delete_managed_udp_pool({}, **retry.kwargs)
            worker.delete_managed_udp_pool({}, **retry.kwargs)
            self.assertEqual(1, render.call_count)
        self.get(self.pool_path, status=404)
        self.assertEqual(1, self._member_use())
        listener = self.get(self.LISTENER_PATH.format(
            listener_id=self.listener_id)).json['listener']
        self.assertIsNone(listener['default_pool_id'])
        self.assertEqual(constants.ACTIVE, listener['provisioning_status'])
        self.assertEqual(constants.ACTIVE, self.get(other_pool_path).json[
            'pool']['provisioning_status'])

    def test_stock_udp_pool_delete_updates_only_its_listener(self):
        self.create_listener('UDP', 8081, self.lb_id)
        self.set_lb_status(self.lb_id)
        self.delete(self.pool_path, status=204)
        pending = self.rpc.cast.call_args
        self.assertEqual(({}, 'delete_pool'), pending.args)
        driver = amphora_noop.NoopAmphoraLoadBalancerDriver
        with (mock.patch.object(driver, 'update_udp_pool_listeners',
                                create=True) as render,
              mock.patch.object(driver, 'update') as update):
            endpoints.Endpoints().delete_pool({}, **pending.kwargs)
            render.assert_called_once()
            self.assertEqual([self.listener_id], render.call_args.args[1])
            update.assert_not_called()
        self.get(self.pool_path, status=404)
