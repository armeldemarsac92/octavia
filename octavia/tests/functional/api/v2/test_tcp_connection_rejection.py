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

import contextlib
import pathlib
import tempfile
from unittest import mock

from oslo_utils import uuidutils
from taskflow import engines
from taskflow.persistence import backends
from taskflow import states

from octavia.amphorae.drivers.noop_driver import driver as amphora_noop
from octavia.api.drivers import driver_factory
from octavia.api.v2.controllers import member
from octavia.common import constants
from octavia.common import exceptions
from octavia.common.jinja.haproxy.combined_listeners import jinja_cfg
from octavia.common import policy
from octavia.common import utils
from octavia.controller.queue.v2 import endpoints
from octavia.controller.worker.v2.flows import flow_utils
from octavia.controller.worker.v2.tasks import amphora_driver_tasks
from octavia.controller.worker.v2.tasks import database_tasks
from octavia.controller.worker.v2.tasks import network_tasks
from octavia.db import api as db_api
from octavia.db import repositories
from octavia.network import data_models as network_models
from octavia.network.drivers.noop_driver import driver as network_noop
from octavia.tests.functional.api.v2 import base


class WorkerInterrupted(BaseException):
    """Stop both TaskFlow engines without reverting the Neutron attachment."""


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

        def render(graph, *, tcp_member_batch):
            self.assertTrue(tcp_member_batch)
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
            self.assertEqual(first, self._batch(one_invalid, [member_address]))
            self._batch(one_invalid, [dict(member_address, weight=2)],
                        status=409)
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
            # An authorized sibling mutation puts the LB into PENDING_UPDATE
            # under a new owner. An old delivery cannot complete it.
            sibling = self.create_pool(
                self.lb_id, 'TCP', 'ROUND_ROBIN')['pool']['id']
            worker.apply_tcp_member_batch({}, **failed)
            update.assert_not_called()
            self.set_object_status(self.pool_repo, sibling)
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

    def test_pending_batch_fences_ordinary_completion_and_redispatches(self):
        self._enroll()
        victim_id = self.create_member(
            self.pool_id, '192.0.2.3', 9000)['member']['id']
        self.set_lb_status(self.lb_id)
        sibling = self._create_pool('TCP')
        full = {'reject_weight': 1, 'total_weight': 1}
        delivery = self._batch(full)
        worker = endpoints.Endpoints()

        with mock.patch.object(amphora_driver_tasks.ApplyTCPMemberBatch,
                               '_owned', side_effect=RuntimeError('db read')):
            self.assertRaises(RuntimeError, worker.apply_tcp_member_batch,
                              {}, **delivery)

        database_tasks.MarkMemberActiveInDB().execute(
            {constants.MEMBER_ID: victim_id})
        database_tasks.MarkPoolActiveInDB().execute(self.pool_id)
        database_tasks.MarkLBAndListenersActiveInDB().execute(self.lb_id, [{
            constants.LISTENER_ID: self.listener_id,
        }])
        self.put(self.MEMBERS_PATH.format(pool_id=sibling), {'members': []},
                 status=409)
        victim = self.get(f'{self.batch_path}/{victim_id}').json['member']
        self.assertEqual(constants.PENDING_DELETE,
                         victim['provisioning_status'])
        self.assertEqual(constants.PENDING_UPDATE,
                         self._pool()['provisioning_status'])

        self._enroll(False)
        self.assertEqual(delivery, self._batch(full))
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update') as update:
            amphora_driver_tasks.ListenersUpdate().execute(self.lb_id)
            update.assert_not_called()
            worker.apply_tcp_member_batch({}, **delivery)
            amphora_driver_tasks.ListenersUpdate().execute(self.lb_id)
            update.assert_called_once()
        self.assertEqual([], self._pool()['members'])

    def test_failed_withdrawal_retains_unbilled_member_for_restoration(self):
        repo = repositories.Repositories()
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        self.conf.config(group='quotas', default_member_quota=1)
        repo.quotas.ensure_project_exists(self.project_id)
        auth = mock.patch.object(policy, 'get_enforcer')
        auth.start().return_value.authorize.return_value = True
        self.addCleanup(auth.stop)
        self._enroll()
        worker = endpoints.Endpoints()
        member_address = {'address': '192.0.2.3', 'protocol_port': 9000}
        one_invalid = {'reject_weight': 1, 'total_weight': 4}
        worker.apply_tcp_member_batch({}, **self._batch(
            one_invalid, [member_address]))
        with db_api.session().begin() as session:
            self.assertEqual(1, repo.quotas.get(
                session, project_id=self.project_id).in_use_member)

        withdrawal = self._batch({'reject_weight': 1, 'total_weight': 1})
        with mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                               'update', side_effect=RuntimeError('reload')):
            self.assertRaises(RuntimeError, worker.apply_tcp_member_batch,
                              {}, **withdrawal)
        with db_api.session().begin() as session:
            self.assertEqual(0, repo.quotas.get(
                session, project_id=self.project_id).in_use_member)
            self.assertEqual((0, 0), self.pool_repo.get_children_count(
                session, self.pool_id))
            self.assertEqual(1, self.member_repo.count(
                session, pool_id=self.pool_id))

        worker.apply_tcp_member_batch({}, **self._batch(
            one_invalid, [member_address]))
        with db_api.session().begin() as session:
            self.assertEqual(1, repo.quotas.get(
                session, project_id=self.project_id).in_use_member)
            self.assertEqual((0, 1), self.pool_repo.get_children_count(
                session, self.pool_id))

    def test_fresh_null_is_legacy_and_registered_alias_has_null_readback(self):
        self.rpc.cast.reset_mock()
        self.put(self.batch_path, {'members': [],
                                   'tcp_connection_rejection': None},
                 status=202)
        self.rpc.cast.assert_not_called()
        item = {'address': '192.0.2.3', 'protocol_port': 9000}
        self.put(self.batch_path, {'members': [item],
                                   'tcp_connection_rejection': None},
                 status=202)
        self.assertEqual(({}, 'batch_update_members'),
                         self.rpc.cast.call_args.args)
        self.set_lb_status(self.lb_id)

        provider = 'site-amphora'
        managed = self.conf.conf.api_settings.enabled_provider_drivers
        self.conf.config(group='api_settings',
                         enabled_provider_drivers={**managed, provider: ''},
                         enabled_tcp_connection_rejection_providers=[provider])
        factory = driver_factory.stevedore_driver.DriverManager

        def alias(*args, **kwargs):
            if kwargs.get('name') == provider:
                kwargs['name'] = 'amphora'
            return factory(*args, **kwargs)

        with db_api.session().begin() as session:
            self.lb_repo.update(session, self.lb_id, provider=provider)
        with mock.patch.object(driver_factory.stevedore_driver,
                               'DriverManager', side_effect=alias):
            caps = self.get(self.PROVIDERS_PATH +
                            f'/{provider}/gateway_capabilities').json
            capability = constants.GATEWAY_CAPABILITY_TCP_CONNECTION_REJECTION
            self.assertIn(capability, caps['gateway_capabilities'])
            self.assertIsNone(self._pool()['tcp_connection_rejection'])
            self._batch({'reject_weight': 1, 'total_weight': 1})

    def _place_member_on_new_network(self):
        self._enroll()
        subnet_id = uuidutils.generate_uuid()
        subnet = network_models.Subnet(
            id=subnet_id, network_id='member-network', cidr='192.0.2.0/24')
        existing_subnet = network_models.Subnet(
            id='existing-subnet', network_id=subnet.network_id,
            cidr='198.51.100.0/24')
        fixed_ip = network_models.FixedIP(
            subnet_id=subnet_id, ip_address='192.0.2.5')
        with db_api.session().begin() as session:
            self.amphora_repo.create(
                session, id=uuidutils.generate_uuid(),
                load_balancer_id=self.lb_id,
                status=constants.AMPHORA_ALLOCATED, lb_network_ip='192.0.2.11',
                compute_id=uuidutils.generate_uuid())
            lb = self.lb_repo.get(session, id=self.lb_id)

        # Per-compute Neutron view persists across reconstructed engines.
        interfaces = {
            amp.compute_id: [
                network_models.Interface(
                    network_id=lb.vip.network_id,
                    fixed_ips=[network_models.FixedIP(
                        subnet_id=lb.vip.subnet_id)]),
                network_models.Interface(network_id='old-member-network'),
            ] for amp in lb.amphorae
        }
        shared_port = network_models.Port(
            id='already-attached', network_id=subnet.network_id,
            fixed_ips=[network_models.FixedIP(
                subnet_id=existing_subnet.id, ip_address='198.51.100.5')])
        interfaces[lb.amphorae[1].compute_id].append(network_models.Interface(
            network_id=shared_port.network_id, port_id=shared_port.id,
            fixed_ips=shared_port.fixed_ips))
        ports = {shared_port.id: shared_port}
        subnets = {subnet.id: subnet, existing_subnet.id: existing_subnet}
        network = mock.Mock()
        network.get_plugged_networks.side_effect = interfaces.__getitem__
        network.get_subnet.side_effect = (
            lambda subnet_id, **kwargs: subnets[subnet_id])
        network.get_network.return_value = network_models.Network(
            id=subnet.network_id)
        network.get_network_configs.return_value = {
            amp.id: network_models.AmphoraNetworkConfig()
            for amp in lb.amphorae
        }

        def create_port(network_id, *, name, fixed_ips, vnic_type):
            port = network_models.Port(
                id=name, network_id=network_id, fixed_ips=[fixed_ip],
                vnic_type=vnic_type)
            ports[port.id] = port
            return port

        def plug_port(amp, port):
            interfaces[amp.compute_id].append(network_models.Interface(
                network_id=port.network_id, port_id=port.id,
                fixed_ips=port.fixed_ips))

        def plug_fixed_ip(port_id, subnet_id):
            port = ports[port_id]
            port.fixed_ips.append(fixed_ip)
            return port

        network.create_port.side_effect = create_port
        network.plug_port.side_effect = plug_port
        network.plug_fixed_ip.side_effect = plug_fixed_ip
        network.get_port.side_effect = ports.__getitem__
        patch = mock.patch.object(utils, 'get_network_driver',
                                  return_value=network)
        patch.start()
        self.addCleanup(patch.stop)
        return network, {'address': '192.0.2.3', 'protocol_port': 9000,
                         'subnet_id': subnet_id}

    def _interrupt_persisted_batch(self, delivery, persistence):
        engine = engines.load_from_factory(
            flow_utils.get_apply_tcp_member_batch_flow,
            backend=persistence, engine='serial', store=delivery)
        attach = network_tasks.HandleNetworkDeltas.execute

        def interrupt(task, *args, **kwargs):
            attach(task, *args, **kwargs)
            raise WorkerInterrupted()

        with mock.patch.object(network_tasks.HandleNetworkDeltas,
                               'execute', new=interrupt):
            self.assertRaises(WorkerInterrupted, engine.run)
        with contextlib.closing(persistence.get_connection()) as connection:
            detail = connection.get_flow_details(engine.storage.flow_uuid)
        apply = next(atom for atom in detail
                     if atom.name.endswith('.ApplyTCPMemberBatch'))
        self.assertEqual(states.RUNNING, apply.state)
        self.assertEqual(constants.PENDING_UPDATE,
                         self._pool()['provisioning_status'])
        return engines.load_from_detail(
            detail, backend=persistence, engine='serial')

    @contextlib.contextmanager
    def _persistent_network_batch(self):
        calls = mock.Mock()
        with (tempfile.TemporaryDirectory() as directory,
              backends.backend(
                  f'sqlite:///{pathlib.Path(directory) / "taskflow.sqlite"}')
              as persistence,
              mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                                'post_network_plug', calls.post_plug),
              mock.patch.object(amphora_noop.NoopAmphoraLoadBalancerDriver,
                                'update', calls.reload)):
            yield persistence, calls

    def test_resumed_jobboard_batch_configures_attached_ports_before_reload(
            self):
        network, member_address = self._place_member_on_new_network()
        delivery = self._batch(
            {'reject_weight': 1, 'total_weight': 4}, [member_address])
        with self._persistent_network_batch() as (persistence, calls):
            resumed = self._interrupt_persisted_batch(delivery, persistence)
            network.plug_port.assert_called_once()
            network.plug_fixed_ip.assert_called_once()
            calls.post_plug.assert_not_called()
            calls.reload.assert_not_called()

            def verify_pending(*args, **kwargs):
                self.assertEqual(constants.PENDING_UPDATE,
                                 self._pool()['provisioning_status'])

            calls.reload.side_effect = verify_pending
            resumed.run()
            self.assertEqual(constants.ACTIVE,
                             self._pool()['provisioning_status'])
            self.assertEqual(
                ['post_plug', 'post_plug', 'reload'],
                [call[0] for call in calls.mock_calls])
            self.assertEqual(2, len({
                call.args[0].id for call in calls.post_plug.call_args_list
            }))
            self.assertEqual({1, 2}, {
                len(call.args[1].fixed_ips)
                for call in calls.post_plug.call_args_list
            })
            network.plug_port.assert_called_once()
            network.plug_fixed_ip.assert_called_once()
            network.unplug_network.assert_not_called()
            network.unplug_fixed_ip.assert_not_called()

    def test_redispatch_reports_post_plug_failure_and_fences_old_job(self):
        network, member_address = self._place_member_on_new_network()
        one_invalid = {'reject_weight': 1, 'total_weight': 4}
        delivery = self._batch(one_invalid, [member_address])
        worker = endpoints.Endpoints()
        with self._persistent_network_batch() as (persistence, calls):
            stale = self._interrupt_persisted_batch(delivery, persistence)
            self.assertEqual(delivery, self._batch(
                one_invalid, [member_address]))
            calls.post_plug.side_effect = [None, RuntimeError('post plug')]
            self.assertRaises(RuntimeError, worker.apply_tcp_member_batch,
                              {}, **delivery)
            self.assertEqual(2, calls.post_plug.call_count)
            calls.reload.assert_not_called()
            self.assertEqual(constants.ERROR,
                             self._pool()['provisioning_status'])

            replacement = self._batch(
                {'reject_weight': 2, 'total_weight': 4}, [member_address])
            network.reset_mock()
            calls.reset_mock(side_effect=True)
            stale.run()
            self.assertEqual([], calls.mock_calls)
            self.assertEqual([], network.mock_calls)
            self.assertEqual(constants.PENDING_UPDATE,
                             self._pool()['provisioning_status'])

            worker.apply_tcp_member_batch({}, **replacement)
            self.assertEqual(
                ['post_plug', 'post_plug', 'reload'],
                [call[0] for call in calls.mock_calls])
            network.plug_port.assert_not_called()
            network.plug_fixed_ip.assert_not_called()
            network.unplug_network.assert_not_called()
            network.unplug_fixed_ip.assert_not_called()
            self.assertEqual(constants.ACTIVE,
                             self._pool()['provisioning_status'])
