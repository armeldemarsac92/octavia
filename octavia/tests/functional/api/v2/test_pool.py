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

from octavia_lib.common import constants as lib_constants
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.api.drivers.noop_driver import driver as noop_driver
from octavia.api.drivers import utils as driver_utils
from octavia.common import constants
import octavia.common.context
from octavia.common import data_models
from octavia.common import exceptions
from octavia.db import api as db_api
from octavia.db import repositories
from octavia.tests.common import constants as c_const
from octavia.tests.common import sample_certs
from octavia.tests.functional.api.v2 import base


class TestPool(base.BaseAPITest):

    root_tag = 'pool'
    root_tag_list = 'pools'
    root_tag_links = 'pools_links'

    def setUp(self):
        super().setUp()

        self.lb = self.create_load_balancer(
            uuidutils.generate_uuid()).get('loadbalancer')
        self.lb_id = self.lb.get('id')
        self.project_id = self.lb.get('project_id')

        self.set_lb_status(self.lb_id)

        self.listener = self.create_listener(
            constants.PROTOCOL_HTTP, 80,
            self.lb_id).get('listener')
        self.listener_id = self.listener.get('id')

        self.set_lb_status(self.lb_id)
        self._setup_udp_lb_resources()

    def _setup_udp_lb_resources(self):
        self.udp_lb = self.create_load_balancer(uuidutils.generate_uuid()).get(
            'loadbalancer')
        self.udp_lb_id = self.udp_lb.get('id')
        self.set_lb_status(self.udp_lb_id)

        self.udp_listener = self.create_listener(
            constants.PROTOCOL_UDP, 8888,
            self.udp_lb_id).get('listener')
        self.udp_listener_id = self.udp_listener.get('id')
        self.set_lb_status(self.udp_lb_id)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_retry_budget', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver, 'pool_update',
                       autospec=True)
    def test_backend_retry_budget_round_trip(self, provider_update):
        field = 'backend_retry_budget'
        capability = constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET
        caps_path = (self.PROVIDERS_PATH +
                     '/noop_driver/gateway_capabilities')
        budget = dict(service_uid='service-uid', budget_percent=20,
                      budget_interval_ms=10000, min_retry_count=10,
                      min_retry_interval_ms=1000)
        args = (self.lb_id, 'HTTP', 'ROUND_ROBIN')
        self.assertNotIn(
            capability, self.get(caps_path).json['gateway_capabilities'])
        self.create_pool(*args, backend_retry_budget=budget, status=501)
        self.conf.config(
            group='api_settings',
            enabled_backend_retry_budget_providers=['noop_driver'])
        self.assertIn(
            capability, self.get(caps_path).json['gateway_capabilities'])
        with mock.patch.object(driver_utils,
                               'BACKEND_RETRY_BUDGET_PAYLOAD_AVAILABLE',
                               False):
            self.assertNotIn(
                capability, self.get(caps_path).json['gateway_capabilities'])
        self.create_pool(self.lb_id, 'TCP', 'ROUND_ROBIN',
                         backend_retry_budget=budget, status=400)
        self.create_pool(
            *args, status=400,
            backend_retry_budget=dict(budget, budget_percent=True))
        pool = self.create_pool(*args, backend_retry_budget=budget)['pool']
        self.assertEqual(budget, pool[field])
        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.assertEqual(budget, self.get(path).json['pool'][field])

        self.set_lb_status(self.lb_id)
        replacement = dict(budget, min_retry_interval_ms=250)
        updated = self.put(path, {'pool': {field: replacement}}).json['pool']
        self.assertEqual(replacement, updated[field])
        self.assertEqual(replacement,
                         provider_update.call_args.args[2].to_dict()[field])

        self.set_lb_status(self.lb_id)
        preserved = self.put(path, {'pool': {'name': 'renamed'}}).json['pool']
        self.assertEqual(replacement, preserved[field])
        self.assertNotIn(field, provider_update.call_args.args[2].to_dict())

        self.set_lb_status(self.lb_id)
        self.conf.config(group='api_settings',
                         enabled_backend_retry_budget_providers=[])
        cleared = self.put(path, {'pool': {field: None}}).json['pool']
        self.assertNotIn(field, cleared)
        self.assertIsNone(provider_update.call_args.args[2].to_dict()[field])
        self.assertNotIn(field, self.get(path).json['pool'])

    def test_get(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id, tags=['test_tag']).get(self.root_tag)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

    def test_get_authorized(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')
        self.set_lb_status(lb_id=self.lb_id)

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
            response = self.get(self.POOL_PATH.format(
                pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

    def test_get_not_authorized(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')
        self.set_lb_status(lb_id=self.lb_id)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            response = self.get(self.POOL_PATH.format(
                pool_id=api_pool.get('id')), status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, response.json)

    def test_get_deleted_gives_404(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)

        self.set_object_status(self.pool_repo, api_pool.get('id'),
                               provisioning_status=constants.DELETED)
        self.get(self.POOL_PATH.format(pool_id=api_pool.get('id')), status=404)

    def test_bad_get(self):
        self.get(self.POOL_PATH.format(pool_id=uuidutils.generate_uuid()),
                 status=404)

    def test_get_all(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id, tags=['test_tag']).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        pools = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.assertIsInstance(pools, list)
        self.assertEqual(1, len(pools))
        self.assertEqual(api_pool.get('id'), pools[0].get('id'))
        self.assertEqual(['test_tag'], pools[0]['tags'])

    def test_get_all_hides_deleted(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)

        response = self.get(self.POOLS_PATH)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 1)
        self.set_object_status(self.pool_repo, api_pool.get('id'),
                               provisioning_status=constants.DELETED)
        response = self.get(self.POOLS_PATH)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 0)

    def test_get_all_admin(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool2 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool3 = self.create_pool(
            lb1_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pools = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.assertEqual(3, len(pools))
        pool_id_protocols = [(p.get('id'), p.get('protocol')) for p in pools]
        self.assertIn((pool1.get('id'), pool1.get('protocol')),
                      pool_id_protocols)
        self.assertIn((pool2.get('id'), pool2.get('protocol')),
                      pool_id_protocols)
        self.assertIn((pool3.get('id'), pool3.get('protocol')),
                      pool_id_protocols)

    def test_get_all_non_admin(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool3 = self.create_pool(
            self.lb_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(self.lb_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings',
                         auth_strategy=constants.KEYSTONE)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
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
                pools = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assertEqual(1, len(pools))
        pool_id_protocols = [(p.get('id'), p.get('protocol')) for p in pools]
        self.assertIn((pool3.get('id'), pool3.get('protocol')),
                      pool_id_protocols)

    def test_get_all_unscoped_token(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_pool(
            self.lb_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(self.lb_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings',
                         auth_strategy=constants.KEYSTONE)
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
            result = self.get(self.POOLS_PATH, status=403).json
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, result)

    def test_get_all_non_admin_global_observer(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        pool1 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool2 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool3 = self.create_pool(
            lb1_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
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
            pools = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assertEqual(3, len(pools))
        pool_id_protocols = [(p.get('id'), p.get('protocol')) for p in pools]
        self.assertIn((pool1.get('id'), pool1.get('protocol')),
                      pool_id_protocols)
        self.assertIn((pool2.get('id'), pool2.get('protocol')),
                      pool_id_protocols)
        self.assertIn((pool3.get('id'), pool3.get('protocol')),
                      pool_id_protocols)

    def test_get_all_not_authorized(self):
        project_id = uuidutils.generate_uuid()
        lb1 = self.create_load_balancer(uuidutils.generate_uuid(), name='lb1',
                                        project_id=project_id)
        lb1_id = lb1.get('loadbalancer').get('id')
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        self.create_pool(
            lb1_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)

        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            pools = self.get(self.POOLS_PATH, status=403).json

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, pools)

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
        pool1 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool2 = self.create_pool(
            lb1_id, constants.PROTOCOL_HTTPS,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb1_id)
        pool3 = self.create_pool(
            lb2_id, constants.PROTOCOL_TCP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.set_lb_status(lb2_id)
        pools = self.get(
            self.POOLS_PATH,
            params={'project_id': project1_id}).json.get(self.root_tag_list)

        self.assertEqual(2, len(pools))
        pool_id_protocols = [(p.get('id'), p.get('protocol')) for p in pools]
        self.assertIn((pool1.get('id'), pool1.get('protocol')),
                      pool_id_protocols)
        self.assertIn((pool2.get('id'), pool2.get('protocol')),
                      pool_id_protocols)
        pools = self.get(
            self.POOLS_PATH,
            params={'project_id': project2_id}).json.get(self.root_tag_list)
        self.assertEqual(1, len(pools))
        pool_id_protocols = [(p.get('id'), p.get('protocol')) for p in pools]
        self.assertIn((pool3.get('id'), pool3.get('protocol')),
                      pool_id_protocols)

    def test_get_all_with_listener(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.assertIsInstance(response, list)
        self.assertEqual(1, len(response))
        self.assertEqual(api_pool.get('id'), response[0].get('id'))

    def test_get_all_sorted(self):
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool2')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool3')
        self.set_lb_status(lb_id=self.lb_id)

        response = self.get(self.POOLS_PATH,
                            params={'sort': 'name:desc'})
        pools_desc = response.json.get(self.root_tag_list)
        response = self.get(self.POOLS_PATH,
                            params={'sort': 'name:asc'})
        pools_asc = response.json.get(self.root_tag_list)

        self.assertEqual(3, len(pools_desc))
        self.assertEqual(3, len(pools_asc))

        pool_id_names_desc = [(pool.get('id'), pool.get('name'))
                              for pool in pools_desc]
        pool_id_names_asc = [(pool.get('id'), pool.get('name'))
                             for pool in pools_asc]
        self.assertEqual(pool_id_names_asc,
                         list(reversed(pool_id_names_desc)))

    def test_get_all_limited(self):
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool2')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool3')
        self.set_lb_status(lb_id=self.lb_id)

        # First two -- should have 'next' link
        first_two = self.get(self.POOLS_PATH, params={'limit': 2}).json
        objs = first_two[self.root_tag_list]
        links = first_two[self.root_tag_links]
        self.assertEqual(2, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('next', links[0]['rel'])

        # Third + off the end -- should have previous link
        third = self.get(self.POOLS_PATH, params={
            'limit': 2,
            'marker': first_two[self.root_tag_list][1]['id']}).json
        objs = third[self.root_tag_list]
        links = third[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('previous', links[0]['rel'])

        # Middle -- should have both links
        middle = self.get(self.POOLS_PATH, params={
            'limit': 1,
            'marker': first_two[self.root_tag_list][0]['id']}).json
        objs = middle[self.root_tag_list]
        links = middle[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(2, len(links))
        self.assertCountEqual(['previous', 'next'],
                              [link['rel'] for link in links])

    def test_get_all_fields_filter(self):
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool2')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool3')
        self.set_lb_status(lb_id=self.lb_id)

        pools = self.get(self.POOLS_PATH, params={
            'fields': ['id', 'project_id']}).json
        for pool in pools['pools']:
            self.assertIn('id', pool)
            self.assertIn('project_id', pool)
            self.assertNotIn('description', pool)

    def test_get_one_fields_filter(self):
        pool1 = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1').get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)

        pool = self.get(
            self.POOL_PATH.format(pool_id=pool1.get('id')),
            params={'fields': ['id', 'project_id']}).json.get(self.root_tag)
        self.assertIn('id', pool)
        self.assertIn('project_id', pool)
        self.assertNotIn('description', pool)

    def test_get_all_filter(self):
        po1 = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1').get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        hm = self.create_health_monitor(po1['id'],
                                        constants.HEALTH_MONITOR_HTTP,
                                        1, 1, 1, 1).get('healthmonitor')
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool2').get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool3').get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)

        pools = self.get(self.POOLS_PATH, params={
            'id': po1['id'], 'healthmonitor_id': hm['id']}).json
        self.assertEqual(1, len(pools['pools']))
        self.assertEqual(po1['id'],
                         pools['pools'][0]['id'])

    def test_get_all_tags_filter(self):
        po1 = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool1',
            tags=['test_tag1', 'test_tag2']
        ).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        po2 = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool2',
            tags=['test_tag2', 'test_tag3']
        ).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        po3 = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            name='pool3',
            tags=['test_tag4', 'test_tag5']
        ).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)

        pos = self.get(
            self.POOLS_PATH,
            params={'tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(2, len(pos))
        self.assertEqual(
            [po1.get('id'), po2.get('id')],
            [po.get('id') for po in pos]
        )

        pos = self.get(
            self.POOLS_PATH,
            params={'tags': ['test_tag2', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(1, len(pos))
        self.assertEqual(
            [po2.get('id')],
            [po.get('id') for po in pos]
        )

        pos = self.get(
            self.POOLS_PATH,
            params={'tags-any': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(2, len(pos))
        self.assertEqual(
            [po1.get('id'), po2.get('id')],
            [po.get('id') for po in pos]
        )

        pos = self.get(
            self.POOLS_PATH,
            params={'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(1, len(pos))
        self.assertEqual(
            [po3.get('id')],
            [po.get('id') for po in pos]
        )

        pos = self.get(
            self.POOLS_PATH,
            params={'not-tags-any': ['test_tag2', 'test_tag4']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(0, len(pos))

        pos = self.get(
            self.POOLS_PATH,
            params={'tags': 'test_tag2',
                    'tags-any': ['test_tag1', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(2, len(pos))
        self.assertEqual(
            [po1.get('id'), po2.get('id')],
            [po.get('id') for po in pos]
        )

        pos = self.get(
            self.POOLS_PATH,
            params={'tags': 'test_tag2', 'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(pos, list)
        self.assertEqual(0, len(pos))

    def test_empty_get_all(self):
        response = self.get(self.POOLS_PATH).json.get(self.root_tag_list)
        self.assertIsInstance(response, list)
        self.assertEqual(0, len(response))

    def test_create(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tags=['test_tag']).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(constants.PROTOCOL_HTTP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assertEqual(['test_tag'], api_pool['tags'])
        self.assertIsNotNone(api_pool.get('created_at'))
        self.assertIsNone(api_pool.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_authorized(self):
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

            api_pool = self.create_pool(
                self.lb_id,
                constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN,
                listener_id=self.listener_id).get(self.root_tag)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(constants.PROTOCOL_HTTP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assertIsNotNone(api_pool.get('created_at'))
        self.assertIsNone(api_pool.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_not_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)

        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            api_pool = self.create_pool(
                self.lb_id,
                constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN,
                listener_id=self.listener_id, status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, api_pool)

    def test_create_with_proxy_protocol(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_PROXY,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(constants.PROTOCOL_PROXY, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assertIsNotNone(api_pool.get('created_at'))
        self.assertIsNone(api_pool.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_with_proxy_v2_protocol(self):
        api_pool = self.create_pool(
            self.lb_id,
            lib_constants.PROTOCOL_PROXYV2,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(lib_constants.PROTOCOL_PROXYV2,
                         api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assertIsNotNone(api_pool.get('created_at'))
        self.assertIsNone(api_pool.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_sans_listener(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN).get(self.root_tag)
        self.assertEqual(constants.PROTOCOL_HTTP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        # Make sure listener status is unchanged, but LB status is changed.
        # LB should still be locked even with pool and subordinate object
        # updates.
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.ACTIVE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)

    def test_create_sans_loadbalancer_id(self):
        api_pool = self.create_pool(
            None,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.assertEqual(constants.PROTOCOL_HTTP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)

    def test_create_with_listener_id_in_pool_dict(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(constants.PROTOCOL_HTTP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_with_project_id(self):
        optionals = {
            'listener_id': self.listener_id,
            'project_id': self.project_id}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.assertEqual(self.project_id, api_pool.get('project_id'))

    def test_create_udp_case_source_ip(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0'}
        api_pool = self.create_pool(
            None,
            constants.PROTOCOL_UDP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.udp_listener_id,
            session_persistence=sp).get(self.root_tag)
        self.assertEqual(constants.PROTOCOL_UDP, api_pool.get('protocol'))
        self.assertEqual(constants.LB_ALGORITHM_ROUND_ROBIN,
                         api_pool.get('lb_algorithm'))
        self.assertEqual(constants.SESSION_PERSISTENCE_SOURCE_IP,
                         api_pool.get('session_persistence')['type'])
        self.assertEqual(3, api_pool.get(
            'session_persistence')['persistence_timeout'])
        self.assertEqual('255.255.255.0', api_pool.get(
            'session_persistence')['persistence_granularity'])
        self.assertIsNone(api_pool.get(
            'session_persistence')['cookie_name'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)

    def test_create_with_tls_enabled_only(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_enabled=True).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertTrue(api_pool.get('tls_enabled'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_create_with_tls_container_ref(self, mock_cert_data):
        tls_container_ref = uuidutils.generate_uuid()
        pool_cert = data_models.TLSContainer(certificate='pool cert')
        mock_cert_data.return_value = {'tls_cert': pool_cert,
                                       'sni_certs': [],
                                       'client_ca_cert': None}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_container_ref=tls_container_ref).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(tls_container_ref, api_pool.get('tls_container_ref'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_create_with_ca_and_crl(self, mock_cert_data):
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]

        ca_tls_container_ref = uuidutils.generate_uuid()
        crl_container_ref = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_container_ref,
            crl_container_ref=crl_container_ref).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        self.assertEqual(ca_tls_container_ref,
                         api_pool.get('ca_tls_container_ref'))
        self.assertEqual(crl_container_ref,
                         api_pool.get('crl_container_ref'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    def test_create_with_bad_tls_container_ref(self):
        tls_container_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_cert.side_effect = [Exception(
            "bad cert")]
        self.cert_manager_mock().get_secret.side_effect = [Exception(
            "bad secret")]
        api_pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_container_ref=tls_container_ref, status=400)
        self.assertIn(tls_container_ref, api_pool['faultstring'])

    def test_create_with_bad_ca_tls_container_ref(self):
        ca_tls_container_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_cert.side_effect = [Exception(
            "bad ca cert")]
        self.cert_manager_mock().get_secret.side_effect = [Exception(
            "bad ca secret")]
        api_pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_container_ref, status=400)
        self.assertIn(ca_tls_container_ref, api_pool['faultstring'])

    def test_create_with_unreachable_crl(self):
        ca_tls_container_ref = uuidutils.generate_uuid()
        crl_container_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_cert.side_effect = [
            'cert 1', Exception('unknow/bad cert')]
        self.cert_manager_mock().get_secret.side_effect = [Exception(
            'bad secret')]
        api_pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_container_ref,
            crl_container_ref=crl_container_ref, status=400)
        self.assertIn(crl_container_ref, api_pool['faultstring'])

    def test_create_with_crl_only(self):
        crl_container_ref = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            crl_container_ref=crl_container_ref, status=400)
        self.assertIn(
            'A CA certificate reference is required to specify a '
            'revocation list.', api_pool['faultstring'])

    def test_negative_create_udp_case(self):
        # Error create pool with udp protocol but non-udp-type
        sp = {"type": constants.SESSION_PERSISTENCE_HTTP_COOKIE,
              "cookie_name": 'test-cookie-name'}
        req_dict = {
            'listener_id': self.udp_listener_id,
            'protocol': constants.PROTOCOL_UDP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        expect_error_msg = ("Validation failure: Cookie names are not "
                            "supported for %s pools.") % (
                                "/".join((constants.PROTOCOL_UDP,
                                          lib_constants.PROTOCOL_SCTP)))
        res = self.post(self.POOLS_PATH, self._build_body(req_dict),
                        status=400, expect_errors=True)
        self.assertEqual(expect_error_msg, res.json['faultstring'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

        # Error create pool with any non-udp-types and udp session persistence
        # options.
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0'}
        req_dict = {
            'listener_id': self.udp_listener_id,
            'protocol': constants.PROTOCOL_UDP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': None}
        for type in [constants.SESSION_PERSISTENCE_HTTP_COOKIE,
                     constants.SESSION_PERSISTENCE_APP_COOKIE]:
            expect_error_msg = ("Validation failure: Session persistence of "
                                "type %s is not supported for %s protocol "
                                "pools.") % (
                                    type,
                                    "/".join((constants.PROTOCOL_UDP,
                                              lib_constants.PROTOCOL_SCTP)))
            sp.update({'type': type})
            req_dict['session_persistence'] = sp
            res = self.post(self.POOLS_PATH, self._build_body(req_dict),
                            status=400,
                            expect_errors=True)
            self.assertEqual(expect_error_msg, res.json['faultstring'])
            self.assert_correct_status(
                lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

        # Error create pool with source ip session persistence and wrong
        # options.
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0',
              "cookie_name": 'test-cookie-name'}
        req_dict = {
            'listener_id': self.udp_listener_id,
            'protocol': constants.PROTOCOL_UDP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        expect_error_msg = (
            "Validation failure: session_persistence %s type for %s "
            "protocols only accepts: type, persistence_timeout, "
            "persistence_granularity.") % (
            constants.SESSION_PERSISTENCE_SOURCE_IP,
            " and ".join((constants.PROTOCOL_UDP,
                          lib_constants.PROTOCOL_SCTP)))
        res = self.post(self.POOLS_PATH, self._build_body(req_dict),
                        status=400, expect_errors=True)
        self.assertEqual(expect_error_msg, res.json['faultstring'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

        # Error create non-udp pool with udp session persistence
        sps = [{"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
                "persistence_timeout": 3,
                "persistence_granularity": '255.255.255.0'},
               {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
                "persistence_timeout": 3,
                "persistence_granularity": '255.255.255.0'}]
        req_dict = {
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN}
        expect_error_msg = ("Validation failure: persistence_timeout and "
                            "persistence_granularity is only for %s protocol "
                            "pools.") % (
                                " and ".join((constants.PROTOCOL_UDP,
                                              lib_constants.PROTOCOL_SCTP)))
        for s in sps:
            req_dict.update({'session_persistence': s})
            res = self.post(self.POOLS_PATH, self._build_body(req_dict),
                            status=400, expect_errors=True)
            self.assertEqual(expect_error_msg, res.json['faultstring'])
            self.assert_correct_status(
                lb_id=self.lb_id, listener_id=self.listener_id)

    def test_bad_create(self):
        pool = {'name': 'test1'}
        self.post(self.POOLS_PATH, self._build_body(pool), status=400)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id)

    def test_create_with_listener_with_default_pool_id_set(self):
        self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id)
        self.set_lb_status(self.lb_id)
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=409)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_fixed_http_responses', True)
    def test_pool_attachment_requires_listener_without_fixed_default(self):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['noop_driver'])
        listener_id = self.create_listener(
            'HTTP', 81, self.lb_id,
            default_http_response={'status_code': 404})['listener']['id']
        self.set_lb_status(self.lb_id)
        fields = {'listener_id': listener_id, 'protocol': 'HTTP',
                  'lb_algorithm': 'ROUND_ROBIN'}
        with mock.patch.object(noop_driver.NoopProviderDriver,
                               'pool_create') as dispatch:
            self.post(self.POOLS_PATH, {'pool': fields}, status=400)
            dispatch.assert_not_called()
        path = self.LISTENER_PATH.format(listener_id=listener_id)
        listener = self.get(path).json['listener']
        self.assertEqual({'status_code': 404},
                         listener['default_http_response'])
        self.assertIsNone(listener['default_pool_id'])

        self.put(path, {'listener': {'default_http_response': None}})
        self.set_lb_status(self.lb_id)
        pool = self.post(self.POOLS_PATH, {'pool': fields}).json['pool']
        self.assertEqual(pool['id'],
                         self.get(path).json['listener']['default_pool_id'])

    def test_create_bad_protocol(self):
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'protocol': 'STUPID_PROTOCOL',
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_create_with_bad_provider(self, mock_provider):
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        response = self.post(self.POOLS_PATH, self._build_body(lb_pool),
                             status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_create_over_quota(self):
        self.start_quota_mock(data_models.Pool)
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=403)

    def test_negative_create_prometheus_listener(self):
        stats_listener = self.create_listener(
            lib_constants.PROTOCOL_PROMETHEUS, 8123,
            self.lb_id).get('listener')
        stats_listener_id = stats_listener.get('id')
        self.set_lb_status(self.lb_id)

        lb_pool = {
            'listener_id': stats_listener_id,
            'protocol': 'HTTP',
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    def test_update(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id, tags=['old_tag']).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'name': 'new_name', 'tags': ['new_tag']}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual('new_name', response.get('name'))
        self.assertEqual(['new_tag'], response['tags'])
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_authorized(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'name': 'new_name'}

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

            self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                     self._build_body(new_pool))

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual('new_name', response.get('name'))
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_not_authorized(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'name': 'new_name'}

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            api_pool = self.put(
                self.POOL_PATH.format(pool_id=api_pool.get('id')),
                self._build_body(new_pool), status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, api_pool.json)
        self.assert_correct_lb_status(self.lb_id, constants.ONLINE,
                                      constants.ACTIVE)

    def test_update_get_session_persistence_from_db_if_no_request(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0'}
        optionals = {"listener_id": self.udp_listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            None,
            constants.PROTOCOL_UDP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.udp_lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        ty = sess_p.pop('type')
        sess_p['persistence_timeout'] = 4
        sess_p['persistence_granularity'] = "255.255.0.0"
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        sess_p['type'] = ty
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(sess_p, response.get('session_persistence'))
        self.assert_correct_status(
            listener_id=self.udp_listener_id,
            pool_id=api_pool.get('id'),
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

    def test_update_udp_case_source_ip(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0'}
        optionals = {"listener_id": self.udp_listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            None,
            constants.PROTOCOL_UDP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.udp_lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['persistence_timeout'] = 4
        sess_p['persistence_granularity'] = "255.255.0.0"
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(sess_p, response.get('session_persistence'))
        self.assert_correct_status(
            listener_id=self.udp_listener_id,
            pool_id=api_pool.get('id'),
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

        self.set_lb_status(self.udp_lb_id)
        self.set_object_status(self.pool_repo, api_pool.get('id'))
        # Negative cases
        # Error during update pool with non-UDP type and cookie_name.
        expect_error_msg = (
            "Validation failure: Cookie names are not supported for %s"
            " pools.") % ("/".join((constants.PROTOCOL_UDP,
                                    lib_constants.PROTOCOL_SCTP)))
        sess_p['type'] = constants.SESSION_PERSISTENCE_HTTP_COOKIE
        sess_p['cookie_name'] = 'test-cookie-name'
        new_pool = {'session_persistence': sess_p}
        res = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                       self._build_body(new_pool), status=400,
                       expect_errors=True)
        self.assertEqual(expect_error_msg, res.json['faultstring'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

        # Error during update pool with source ip type and more options.
        expect_error_msg = (
            "Validation failure: session_persistence %s type for %s protocols "
            "only accepts: type, persistence_timeout, "
            "persistence_granularity.") % (
            constants.SESSION_PERSISTENCE_SOURCE_IP,
            " and ".join((constants.PROTOCOL_UDP,
                          lib_constants.PROTOCOL_SCTP)))
        sess_p['type'] = constants.SESSION_PERSISTENCE_SOURCE_IP
        sess_p['cookie_name'] = 'test-cookie-name'
        sess_p['persistence_timeout'] = 4
        sess_p['persistence_granularity'] = "255.255.0.0"
        res = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                       self._build_body(new_pool), status=400,
                       expect_errors=True)
        self.assertEqual(expect_error_msg, res.json['faultstring'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

        # Error during update pool with non-UDP session persistence type.
        sess_p['cookie_name'] = None
        for ty in [constants.SESSION_PERSISTENCE_APP_COOKIE,
                   constants.SESSION_PERSISTENCE_HTTP_COOKIE]:
            expect_error_msg = ("Validation failure: Session persistence of "
                                "type %s is not supported for %s protocol "
                                "pools.") % (
                                    ty,
                                    "/".join((constants.PROTOCOL_UDP,
                                              lib_constants.PROTOCOL_SCTP)))
            sess_p['type'] = ty
            res = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                           self._build_body(new_pool), status=400,
                           expect_errors=True)
            self.assertEqual(expect_error_msg, res.json['faultstring'])
            self.assert_correct_status(
                lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

    def test_update_with_tls_enabled_only(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertFalse(api_pool['tls_enabled'])
        new_pool = {'tls_enabled': True}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertTrue(response.get('tls_enabled'))
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_with_tls_enabled_only_on_pool_certs_exist(
            self, mock_cert_data):
        tls_container_ref = uuidutils.generate_uuid()
        ca_tls_container_ref = uuidutils.generate_uuid()
        crl_container_ref = uuidutils.generate_uuid()
        pool_cert = data_models.TLSContainer(certificate='pool cert')
        mock_cert_data.return_value = {'tls_cert': pool_cert,
                                       'sni_certs': [],
                                       'client_ca_cert': None}
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_container_ref=tls_container_ref,
            ca_tls_container_ref=ca_tls_container_ref,
            crl_container_ref=crl_container_ref).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertFalse(api_pool['tls_enabled'])

        new_pool = {'tls_enabled': True}
        self.cert_manager_mock().get_cert.reset_mock()
        self.cert_manager_mock().get_secret.reset_mock()
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertTrue(response.get('tls_enabled'))
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    @mock.patch(
        'octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_with_tls_container_ref(self, mock_cert_data):
        tls_container_ref = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'tls_container_ref': tls_container_ref}
        pool_cert = data_models.TLSContainer(certificate='pool cert')
        mock_cert_data.return_value = {'tls_cert': pool_cert,
                                       'sni_certs': [],
                                       'client_ca_cert': None}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(tls_container_ref, response.get('tls_container_ref'))
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_bad_tls_ref(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')

        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

        tls_uuid = uuidutils.generate_uuid()
        self.pool_repo.update(db_api.get_session(),
                              api_pool.get('id'),
                              tls_certificate_id=tls_uuid)
        update_data = {'name': 'pool2'}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(update_data))
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual('pool2', response.get('name'))

    def test_bad_update(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_pool = {'enabled': 'one'}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=400)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_update_with_bad_provider(self, mock_provider):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'name': 'new_name'}
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        response = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                            self._build_body(new_pool), status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_bad_update_non_udp_pool_with_udp_fields(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "persistence_timeout": 3,
              "persistence_granularity": '255.255.255.0'}
        self.set_lb_status(self.lb_id)
        new_pool = {'session_persistence': sp}
        expect_error_msg = ("Validation failure: persistence_timeout and "
                            "persistence_granularity is only for %s "
                            "protocol pools.") % constants.PROTOCOL_UDP
        res = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                       self._build_body(new_pool), status=400,
                       expect_errors=True)
        self.assertEqual(expect_error_msg, res.json['faultstring'])
        self.assert_correct_status(
            lb_id=self.udp_lb_id, listener_id=self.udp_listener_id)

    def test_update_with_bad_tls_container_ref(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        tls_container_ref = uuidutils.generate_uuid()
        new_pool = {'tls_container_ref': tls_container_ref}

        self.cert_manager_mock().get_cert.side_effect = [Exception(
            "bad cert")]
        self.cert_manager_mock().get_secret.side_effect = [Exception(
            "bad secret")]
        resp = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        self._build_body(new_pool), status=400).json
        self.assertIn(tls_container_ref, resp['faultstring'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_with_ca_and_crl(self, mock_cert_data):
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]
        ca_tls_container_ref = uuidutils.generate_uuid()
        crl_container_ref = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'ca_tls_container_ref': ca_tls_container_ref,
                    'crl_container_ref': crl_container_ref}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(ca_tls_container_ref,
                         response.get('ca_tls_container_ref'))
        self.assertEqual(crl_container_ref,
                         response.get('crl_container_ref'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_bad_ca_tls_container_ref(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        ca_tls_container_ref = uuidutils.generate_uuid()
        new_pool = {'ca_tls_container_ref': ca_tls_container_ref}
        self.cert_manager_mock().get_cert.side_effect = [Exception(
            "bad cert")]
        self.cert_manager_mock().get_secret.side_effect = [Exception(
            "bad secret")]
        resp = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        self._build_body(new_pool), status=400).json
        self.assertIn(ca_tls_container_ref, resp['faultstring'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_with_crl(self, mock_cert_data):
        ca_tls_container_ref = uuidutils.generate_uuid()
        crl_container_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_container_ref,
            crl_container_ref=crl_container_ref).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_crl_container_ref = uuidutils.generate_uuid()
        new_pool = {'crl_container_ref': new_crl_container_ref}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(new_crl_container_ref,
                         response.get('crl_container_ref'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_crl_only_negative_case(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        crl_container_ref = uuidutils.generate_uuid()
        new_pool = {'crl_container_ref': crl_container_ref}
        resp = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        self._build_body(new_pool), status=400).json
        self.assertIn(
            'A CA reference is required to specify a certificate revocation '
            'list.', resp['faultstring'])

    def test_update_with_crl_only_none_ca(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        crl_container_ref = uuidutils.generate_uuid()
        new_pool = {'ca_tls_container_ref': None,
                    'crl_container_ref': crl_container_ref}
        resp = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        self._build_body(new_pool), status=400).json
        self.assertIn(
            'A CA reference is required to specify a certificate revocation '
            'list.', resp['faultstring'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_with_unreachable_crl(self, mock_cert_data):
        crl_container_ref = uuidutils.generate_uuid()
        new_crl_container_ref = uuidutils.generate_uuid()
        ca_tls_container_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]

        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_container_ref,
            crl_container_ref=crl_container_ref).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_crl_container_ref = uuidutils.generate_uuid()
        new_pool = {'crl_container_ref': new_crl_container_ref}
        self.cert_manager_mock().get_secret.side_effect = [
            exceptions.CertificateRetrievalException(
                ref=new_crl_container_ref)]
        resp = self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        self._build_body(new_pool), status=400).json
        self.assertIn(new_crl_container_ref, resp['faultstring'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_unset_ca_cert(self, mock_cert_data):
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)

        ca_tls_uuid = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_uuid).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_pool = {'ca_tls_container_ref': None}
        body = self._build_body(new_pool)
        listener_path = self.POOL_PATH.format(
            pool_id=api_pool['id'])
        api_pool = self.put(listener_path, body).json.get(self.root_tag)
        self.assertIsNone(api_pool.get('ca_tls_container_ref'))
        self.assertIsNone(api_pool.get('crl_container_ref'))

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_unset_ca_cert_with_crl(self, mock_cert_data):
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]

        ca_tls_uuid = uuidutils.generate_uuid()
        crl_uuid = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_uuid,
            crl_container_ref=crl_uuid).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_pool = {'ca_tls_container_ref': None}
        body = self._build_body(new_pool)
        listener_path = self.POOL_PATH.format(
            pool_id=api_pool['id'])
        response = self.put(listener_path, body, status=400).json
        self.assertIn('A CA reference cannot be removed when a certificate '
                      'revocation list is present.', response['faultstring'])

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_update_unset_crl(self, mock_cert_data):
        self.cert_manager_mock().get_secret.side_effect = [
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL,
            sample_certs.X509_CA_CERT, sample_certs.X509_CA_CRL]
        ca_tls_uuid = uuidutils.generate_uuid()
        crl_uuid = uuidutils.generate_uuid()
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            ca_tls_container_ref=ca_tls_uuid,
            crl_container_ref=crl_uuid).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_pool = {'crl_container_ref': None}
        body = self._build_body(new_pool)
        listener_path = self.POOL_PATH.format(
            pool_id=api_pool['id'])
        update_pool = self.put(listener_path, body).json.get(self.root_tag)
        self.assertEqual(api_pool.get('ca_tls_container_ref'),
                         update_pool.get('ca_tls_container_ref'))
        self.assertIsNone(update_pool.get('crl_container_ref'))

    def test_update_with_tls_versions(self):
        tls_versions = [lib_constants.TLS_VERSION_1_3,
                        lib_constants.TLS_VERSION_1_2]
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            tls_enabled=True,
            tls_versions=tls_versions,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertTrue(api_pool['tls_enabled'])
        self.assertCountEqual(tls_versions,
                              api_pool['tls_versions'])

        new_pool = {'tls_versions': [lib_constants.TLS_VERSION_1_3]}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertCountEqual([lib_constants.TLS_VERSION_1_3],
                              response['tls_versions'])
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_empty_tls_versions(self):
        default_pool_tls_versions = [lib_constants.TLS_VERSION_1_3,
                                     lib_constants.TLS_VERSION_1_2]
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='api_settings',
                         default_pool_tls_versions=default_pool_tls_versions)

        tls_versions = [lib_constants.TLS_VERSION_1_3]
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            tls_enabled=True,
            tls_versions=tls_versions,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertTrue(api_pool['tls_enabled'])
        self.assertCountEqual(tls_versions,
                              api_pool['tls_versions'])

        new_pool = {'tls_versions': None}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertCountEqual(default_pool_tls_versions,
                              response['tls_versions'])
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_tls_ciphers(self):
        default_ciphers = (
            'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='api_settings',
                         default_pool_ciphers=default_ciphers)

        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            tls_enabled=True,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertTrue(api_pool['tls_enabled'])
        self.assertEqual(default_ciphers, api_pool['tls_ciphers'])

        new_tls_ciphers = 'DHE-RSA-AES128-GCM-SHA256'
        new_pool = {'tls_ciphers': new_tls_ciphers}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(new_tls_ciphers, response['tls_ciphers'])
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_update_with_empty_tls_ciphers(self):
        default_ciphers = (
            'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='api_settings',
                         default_pool_ciphers=default_ciphers)

        tls_ciphers = 'DHE-RSA-AES128-GCM-SHA256'
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            tls_enabled=True,
            tls_ciphers=tls_ciphers,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.assertTrue(api_pool['tls_enabled'])
        self.assertEqual(tls_ciphers, api_pool['tls_ciphers'])

        new_pool = {'tls_ciphers': None}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(default_ciphers, response['tls_ciphers'])
        self.assertIsNotNone(response.get('created_at'))
        self.assertIsNotNone(response.get('updated_at'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=response.get('id'))

    def test_delete(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')

        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_DELETE)

    # Problems with TLS certs should not block a delete
    def test_delete_with_bad_tls_ref(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')

        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

        tls_uuid = uuidutils.generate_uuid()
        self.pool_repo.update(db_api.get_session(),
                              api_pool.get('id'),
                              tls_certificate_id=tls_uuid)

        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_DELETE)

    def test_delete_authorize(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')

        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

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
            self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')))
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_DELETE)

    def test_delete_not_authorize(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        api_pool.pop('updated_at')

        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_pool, response)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=uuidutils.generate_uuid())
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                        status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            pool_prov_status=constants.ACTIVE)

    def test_bad_delete(self):
        self.delete(self.POOL_PATH.format(
            pool_id=uuidutils.generate_uuid()), status=404)

    def test_delete_with_l7policy(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7policy(
            self.listener_id,
            constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            redirect_pool_id=api_pool.get('id'))
        self.set_lb_status(self.lb_id)
        self.delete(self.POOL_PATH.format(
            pool_id=api_pool.get('id')), status=409)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_weighted_targets', True, create=True)
    def test_delete_pool_with_zero_weight_target(self):
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=['noop_driver'])
        pool_id = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN)[self.root_tag]['id']
        self.set_lb_status(self.lb_id)
        policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            targets=[{'weight': 1, 'fixed_response': {'status_code': 500}},
                     {'weight': 0, 'pool_id': pool_id}])['l7policy']
        self.set_lb_status(self.lb_id)

        pool_path = self.POOL_PATH.format(pool_id=pool_id)
        result = self.delete(pool_path, status=409)
        self.assertIn(policy['id'], result.json['faultstring'])

        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        self.put(policy_path, {'l7policy': {'action': 'REJECT'}})
        self.set_lb_status(self.lb_id)
        self.delete(pool_path)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_delete_with_bad_provider(self, mock_provider):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_pool['provisioning_status'] = constants.ACTIVE
        api_pool['operating_status'] = constants.ONLINE
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)

        self.assertIsNone(api_pool.pop('updated_at'))
        self.assertIsNotNone(response.pop('updated_at'))
        self.assertEqual(api_pool, response)
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                    status=500)

    def test_create_with_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name"}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_CREATE,
            pool_op_status=constants.OFFLINE)
        self.set_lb_status(self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        self.assertIsNotNone(sess_p)
        self.assertEqual(constants.SESSION_PERSISTENCE_APP_COOKIE,
                         sess_p.get('type'))
        self.assertEqual('test_cookie_name', sess_p.get('cookie_name'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'))

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_http_cookie_name_enrollment(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        capability = constants.GATEWAY_CAPABILITY_HTTP_COOKIE_NAME
        caps_path = self.PROVIDERS_PATH + '/{}/gateway_capabilities'
        persistence = 'session_persistence'
        default = {'type': 'HTTP_COOKIE'}
        named = dict(default, cookie_name='gw_cookie.1-prod')
        args = (lb_id, 'HTTP', 'ROUND_ROBIN')

        self.assertNotIn(capability, self.get(
            caps_path.format('amphora')).json['gateway_capabilities'])
        self.create_pool(*args, session_persistence=named, status=501)
        stock = self.create_pool(*args, session_persistence=default)['pool']
        stock_path = self.POOL_PATH.format(pool_id=stock['id'])
        self.assertIsNone(stock[persistence]['cookie_name'])
        with db_api.session().begin() as session:
            # Old graph creates could store a name that HAProxy ignored.
            repositories.SessionPersistenceRepository().update(
                session, stock['id'], cookie_name=named['cookie_name'])

        self.conf.config(
            group='api_settings',
            enabled_http_cookie_name_providers=['amphora', 'noop_driver'])
        self.assertIn(capability, self.get(
            caps_path.format('amphora')).json['gateway_capabilities'])
        self.assertNotIn(capability, self.get(
            caps_path.format('noop_driver')).json['gateway_capabilities'])
        self.assertIsNone(
            self.get(stock_path).json['pool'][persistence]['cookie_name'])
        self.set_lb_status(lb_id)
        for protocol in ('TCP', 'HTTPS'):
            self.create_pool(lb_id, protocol, 'ROUND_ROBIN',
                             session_persistence=named, status=400)
        self.create_pool(*args, session_persistence=dict(
            named, cookie_name='cookie@name'), status=400)
        self.create_pool(*args, session_persistence=dict(
            named, cookie_name='__SeCuRe-cookie'), status=400)

        created = self.create_pool(*args, session_persistence=named)['pool']
        path = self.POOL_PATH.format(pool_id=created['id'])
        self.assertEqual(named['cookie_name'],
                         created[persistence]['cookie_name'])
        cast = rpc.return_value.cast
        self.assertEqual(created[persistence],
                         cast.call_args.kwargs['pool'][persistence])
        self.assertEqual(created[persistence],
                         self.get(path).json['pool'][persistence])
        pools = {p['id']: p for p in self.get(self.POOLS_PATH).json['pools']}
        self.assertEqual(created[persistence],
                         pools[created['id']][persistence])

        self.set_lb_status(lb_id)
        replacement = 'gw_cookie.2-prod'
        self.put(path, self._build_body({
            persistence: {'cookie_name': '__Host-cookie'}}), status=400)
        updated = self.put(path, self._build_body({
            persistence: {'cookie_name': replacement}})).json['pool']
        self.assertEqual(replacement, updated[persistence]['cookie_name'])
        self.assertEqual(updated[persistence],
                         cast.call_args.kwargs['pool_updates'][persistence])

        self.conf.config(group='api_settings',
                         enabled_http_cookie_name_providers=[])
        self.set_lb_status(lb_id)
        self.put(path, self._build_body({persistence: named}), status=501)
        preserved = self.put(path, self._build_body(
            {'name': 'renamed'})).json['pool']
        self.assertEqual(updated[persistence], preserved[persistence])
        self.set_lb_status(lb_id)
        reset = self.put(path, self._build_body({
            persistence: default})).json['pool']
        self.assertIsNone(reset[persistence]['cookie_name'])
        self.set_lb_status(lb_id)
        removed = self.put(path, self._build_body({
            persistence: None})).json['pool']
        self.assertIsNone(removed[persistence])

    def test_legacy_http_cookie_name_visibility(self):
        pool = self.create_pool(
            self.lb_id, 'HTTP', 'ROUND_ROBIN',
            session_persistence={'type': 'HTTP_COOKIE'})['pool']
        pool_id = pool['id']
        path = self.POOL_PATH.format(pool_id=pool_id)
        name = 'LEGACY'
        with db_api.session().begin() as session:
            repositories.SessionPersistenceRepository().update(
                session, pool_id, cookie_name=name)

        providers = ('amphora', 'amphorav2', 'octavia', None, 'noop_driver')
        for provider in providers:
            with self.subTest(provider=provider):
                with db_api.session().begin() as session:
                    repositories.LoadBalancerRepository().update(
                        session, self.lb_id, provider=provider)
                    db_pool = repositories.PoolRepository().get(
                        session, id=pool_id)
                    dto = driver_utils.db_pool_to_provider_pool(db_pool)
                    self.assertEqual(
                        name, db_pool.session_persistence.cookie_name)

                expected = name if provider == 'noop_driver' else None
                detail = self.get(path).json['pool']
                persistence = detail['session_persistence']
                self.assertEqual(expected, persistence['cookie_name'])
                pools = self.get(
                    self.POOLS_PATH,
                    params={'fields': ['id', 'session_persistence']}
                ).json['pools']
                listed = next(pool for pool in pools if pool['id'] == pool_id)
                self.assertEqual(persistence, listed['session_persistence'])
                self.assertEqual(persistence, dto.session_persistence)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_http_cookie_absolute_timeout_lifecycle(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        args = (lb_id, 'HTTP', 'ROUND_ROBIN')
        name = {'type': 'HTTP_COOKIE', 'cookie_name': 'gw.session'}
        scope = 'a' * 64
        policy = dict(name, cookie_absolute_timeout_ms=0, cookie_scope=scope)
        capability = constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT
        provider_path = self.PROVIDERS_PATH + '/amphora/gateway_capabilities'
        self.conf.config(
            group='api_settings',
            enabled_http_cookie_name_providers=['amphora'])
        self.assertNotIn(capability,
                         self.get(provider_path).json['gateway_capabilities'])
        self.create_pool(*args, session_persistence=policy, status=501)

        self.conf.config(group='api_settings',
                         enabled_http_cookie_absolute_timeout_providers=[
                             'amphora'])
        self.assertIn(capability,
                      self.get(provider_path).json['gateway_capabilities'])
        self.create_pool(*args, session_persistence=dict(
            name, cookie_absolute_timeout_ms=0), status=400)
        self.create_pool(*args, session_persistence=dict(
            policy, cookie_name=None), status=400)
        self.create_pool(*args, session_persistence=dict(
            policy, cookie_scope='A' * 64), status=400)
        for invalid in (True, 1.5, '1', -1, 1439985600001):
            with self.subTest(invalid=invalid):
                self.create_pool(*args, session_persistence=dict(
                    policy, cookie_absolute_timeout_ms=invalid), status=400)

        persistence = 'session_persistence'
        anchor_id = self.create_pool(*args)['pool']['id']
        self.set_lb_status(lb_id)
        created = self.create_pool(*args, session_persistence=policy)['pool']
        path = self.POOL_PATH.format(pool_id=created['id'])
        cast = rpc.return_value.cast
        self.assertEqual(created[persistence],
                         cast.call_args.kwargs['pool'][persistence])
        self.assertEqual(0, self.get(path).json['pool'][persistence]
                         ['cookie_absolute_timeout_ms'])

        self.set_lb_status(lb_id)
        max_timeout = 1439985600000
        update = {'cookie_absolute_timeout_ms': max_timeout,
                  'cookie_scope': scope}
        updated = self.put(path, self._build_body({
            persistence: update})).json['pool'][persistence]
        self.assertEqual(max_timeout, updated['cookie_absolute_timeout_ms'])
        self.assertEqual(updated,
                         cast.call_args.kwargs['pool_updates'][persistence])

        # A fallback render may keep traffic available but must leave the
        # affinity profile in ERROR until its Amphorae can enforce it again.
        pool_id = created['id']
        repo = repositories.PoolRepository()
        persisted_policy = {pool_id: (name['cookie_name'], max_timeout, scope)}
        with db_api.session().begin() as session:
            repo.set_http_cookie_pool_statuses(
                session, persisted_policy, failed={pool_id}, recovered=set())
            repo.mark_active(session, pool_id)
        self.assertEqual(constants.ERROR,
                         self.get(path).json['pool']['provisioning_status'])
        page = {'id': pool_id, 'marker': anchor_id, 'limit': 1,
                'sort': 'id:asc' if anchor_id < pool_id else 'id:desc',
                'fields': ['id', 'provisioning_status']}
        projected = self.get(self.POOLS_PATH, params=page).json['pools']
        self.assertEqual([{'id': pool_id, 'provisioning_status':
                           constants.ERROR}], projected)

        # An ordinary PUT may replay the same policy. Publishing the pool's
        # lifecycle completion does not make its still-degraded cookies ready.
        self.set_lb_status(lb_id)
        self.put(path, self._build_body({
            persistence: update}))
        self.assertEqual(max_timeout, cast.call_args.kwargs['pool_updates']
                         [persistence]['cookie_absolute_timeout_ms'])
        with db_api.session().begin() as session:
            repo.mark_active(session, pool_id)
        self.assertEqual(constants.ERROR,
                         self.get(path).json['pool']['provisioning_status'])
        with db_api.session().begin() as session:
            repo.set_http_cookie_pool_statuses(
                session, persisted_policy, failed=set(), recovered={pool_id})
        self.assertEqual(constants.ACTIVE,
                         self.get(path).json['pool']['provisioning_status'])
        projected = self.get(self.POOLS_PATH, params=page).json['pools']
        self.assertEqual([{'id': pool_id, 'provisioning_status':
                           constants.ACTIVE}], projected)

        # Failures in each profile remain visible when the other recovers.
        with db_api.session().begin() as session:
            repo.update(session, pool_id, backend_tls_hostname='origin.test')
            repo.set_backend_tls_pool_statuses(
                session, closed={pool_id}, recovered=set())
            repo.set_http_cookie_pool_statuses(
                session, persisted_policy, failed=set(), recovered={pool_id})
        self.assertEqual(constants.ERROR,
                         self.get(path).json['pool']['provisioning_status'])
        with db_api.session().begin() as session:
            repo.set_http_cookie_pool_statuses(
                session, persisted_policy, failed={pool_id}, recovered=set())
            repo.set_backend_tls_pool_statuses(
                session, closed=set(), recovered={pool_id})
            repo.update(session, pool_id, backend_tls_hostname=None)
        self.assertEqual(constants.ERROR,
                         self.get(path).json['pool']['provisioning_status'])

        self.conf.config(group='api_settings',
                         enabled_http_cookie_absolute_timeout_providers=[],
                         enabled_http_cookie_name_providers=[])
        self.set_lb_status(lb_id)
        self.put(path, self._build_body({persistence: policy}), status=501)
        self.put(path, self._build_body({
            persistence: dict(name, cookie_name=None)}), status=400)
        preserved = self.put(path, self._build_body({
            persistence: name})).json['pool'][persistence]
        self.assertEqual(updated, preserved)

        self.set_lb_status(lb_id)
        self.put(path, self._build_body({
            persistence: {'cookie_absolute_timeout_ms': None,
                          'cookie_scope': None}}))
        stored = self.get(path).json['pool'][persistence]
        self.assertNotIn('cookie_absolute_timeout_ms', stored)
        self.assertNotIn('cookie_scope', stored)
        self.assertEqual(name['cookie_name'], stored['cookie_name'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.'
                'AmphoraProviderDriver.loadbalancer_create')
    def test_http_cookie_name_in_load_balancer_graph(self, create, _rpc):
        named = {'type': 'HTTP_COOKIE', 'cookie_name': 'nested_cookie'}
        pool = {'name': 'pool', 'protocol': 'HTTP',
                'lb_algorithm': 'ROUND_ROBIN', 'session_persistence': named}
        fields = {'provider': 'amphora',
                  'listeners': [{'protocol': 'HTTP', 'protocol_port': 80,
                                 'default_pool': pool}]}
        fields['vip_subnet_id'] = uuidutils.generate_uuid()
        fields['project_id'] = self.project_id
        self.post(self.LBS_PATH, {'loadbalancer': fields}, status=501)
        self.conf.config(group='api_settings',
                         enabled_http_cookie_name_providers=['amphora'],
                         enabled_http_cookie_absolute_timeout_providers=[
                             'amphora'])
        for option in ({'persistence_timeout': 0},
                       {'persistence_granularity': '255.255.255.0'}):
            pool['session_persistence'] = dict(named, **option)
            self.post(self.LBS_PATH, {'loadbalancer': fields}, status=400)
        pool['session_persistence'] = dict(
            named, cookie_absolute_timeout_ms=1500, cookie_scope='a' * 64)
        lb = self.post(self.LBS_PATH, {'loadbalancer': fields})
        pool_id = lb.json['loadbalancer']['pools'][0]['id']
        path = self.POOL_PATH.format(pool_id=pool_id)
        persistence = self.get(path).json['pool']['session_persistence']
        self.assertEqual(named['cookie_name'], persistence['cookie_name'])
        self.assertEqual(1500, persistence['cookie_absolute_timeout_ms'])
        self.assertEqual('a' * 64, persistence['cookie_scope'])
        create.assert_called_once()
        created = create.call_args.args[0]
        self.assertEqual(persistence, created.pools[0].session_persistence)

    def test_create_with_bad_session_persistence(self):
        sp = {"type": "persistence_type",
              "cookie_name": "test_cookie_name"}
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    def test_create_with_bad_SP_type_HTTP_cookie(self):
        sp = {"type": constants.SESSION_PERSISTENCE_HTTP_COOKIE,
              "cookie_name": "test_cookie_name"}
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=501)

    def test_create_with_bad_SP_type_IP_cookie(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP,
              "cookie_name": "test_cookie_name"}
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    def test_create_with_bad_SP_cookie_name(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "b@d_cookie_name"}
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    def test_create_with_missing_cookie_name(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE}
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'session_persistence': sp}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=400)

    def test_add_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name",
              'persistence_granularity': None,
              'persistence_timeout': None}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'session_persistence': sp}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(sp, response.get('session_persistence'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

    def test_update_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name"}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['cookie_name'] = None
        sess_p['type'] = constants.SESSION_PERSISTENCE_SOURCE_IP
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(sess_p, response.get('session_persistence'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

    def test_update_preserve_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name",
              'persistence_granularity': None,
              'persistence_timeout': None}
        optionals = {"listener_id": self.listener_id,
                     "name": "name", "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_pool = {'name': 'update_name'}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool))
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        self.assertEqual(sp, response.get('session_persistence'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

    def test_update_bad_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name"}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['type'] = 'fake_type'
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=400)

    def test_update_with_bad_SP_type_HTTP_cookie(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['type'] = constants.SESSION_PERSISTENCE_HTTP_COOKIE
        sess_p['cookie_name'] = 'test_cookie_name'
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=501)

    def test_update_with_bad_SP_type_IP_cookie(self):
        sp = {"type": constants.SESSION_PERSISTENCE_HTTP_COOKIE}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['type'] = constants.SESSION_PERSISTENCE_SOURCE_IP
        sess_p['cookie_name'] = 'test_cookie_name'
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=400)

    def test_update_with_bad_SP_cookie_name(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['type'] = constants.SESSION_PERSISTENCE_APP_COOKIE
        sess_p['cookie_name'] = 'b@d_cookie_name'
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=400)

    def test_update_with_missing_SP_cookie_name(self):
        sp = {"type": constants.SESSION_PERSISTENCE_SOURCE_IP}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        response = self.get(self.POOL_PATH.format(
            pool_id=api_pool.get('id'))).json.get(self.root_tag)
        sess_p = response.get('session_persistence')
        sess_p['type'] = constants.SESSION_PERSISTENCE_APP_COOKIE
        new_pool = {'session_persistence': sess_p}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=400)

    def test_delete_with_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name"}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_DELETE)

    def test_delete_session_persistence(self):
        sp = {"type": constants.SESSION_PERSISTENCE_APP_COOKIE,
              "cookie_name": "test_cookie_name"}
        optionals = {"listener_id": self.listener_id,
                     "session_persistence": sp}
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            **optionals).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)
        new_sp = {"pool": {"session_persistence": None}}
        response = self.put(self.POOL_PATH.format(
            pool_id=api_pool.get('id')), new_sp).json.get(self.root_tag)
        self.assertIsNone(response.get('session_persistence'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            pool_id=api_pool.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            pool_prov_status=constants.PENDING_UPDATE)

    def test_create_when_lb_pending_update(self):
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 {'loadbalancer': {'name': 'test_name_change'}})
        lb_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        self.post(self.POOLS_PATH, self._build_body(lb_pool), status=409)

    def test_update_when_lb_pending_update(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 {'loadbalancer': {'name': 'test_name_change'}})
        new_pool = {'admin_state_up': False}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=409)

    def test_delete_when_lb_pending_update(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 {"loadbalancer": {'name': 'test_name_change'}})
        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                    status=409)

    def test_create_when_lb_pending_delete(self):
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_pool = {
            'loadbalancer_id': self.lb_id,
            'listener_id': self.listener_id,
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        self.post(self.POOLS_PATH, self._build_body(new_pool), status=409)

    def test_update_when_lb_pending_delete(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_pool = {'admin_state_up': False}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=409)

    def test_delete_when_lb_pending_delete(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                    status=409)

    def test_update_already_deleted(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        new_pool = {'admin_state_up': False}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=404)

    def test_delete_already_deleted(self):
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        self.delete(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                    status=404)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_valid_listener_pool_protocol(self, mock_cert_data):
        cert = data_models.TLSContainer(certificate='cert')
        lb_pool = {
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        mock_cert_data.return_value = {'sni_certs': [cert]}
        valid_map = constants.VALID_LISTENER_POOL_PROTOCOL_MAP
        port = 1
        for listener_proto in valid_map:
            for pool_proto in valid_map[listener_proto]:
                port = port + 1
                opts = {}
                if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                    opts['sni_container_refs'] = [uuidutils.generate_uuid()]
                listener = self.create_listener(
                    listener_proto, port, self.lb_id, **opts).get('listener')
                self.set_object_status(self.lb_repo, self.lb_id)
                if listener['default_pool_id'] is None:
                    lb_pool['protocol'] = pool_proto
                    lb_pool['listener_id'] = listener.get('id')
                    self.post(self.POOLS_PATH, self._build_body(lb_pool),
                              status=201)
                    self.set_object_status(self.lb_repo, self.lb_id)

    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_invalid_listener_pool_protocol_map(self, mock_cert_data):
        cert = data_models.TLSContainer(certificate='cert')
        lb_pool = {
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'project_id': self.project_id}
        mock_cert_data.return_value = {'sni_certs': [cert]}
        invalid_map = c_const.INVALID_LISTENER_POOL_PROTOCOL_MAP
        port = 1
        for listener_proto in invalid_map:
            opts = {}
            if listener_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                opts['sni_container_refs'] = [uuidutils.generate_uuid()]
            listener = self.create_listener(
                listener_proto, port, self.lb_id, **opts).get('listener')
            self.set_object_status(self.lb_repo, self.lb_id)
            port = port + 1
            for pool_proto in invalid_map[listener_proto]:
                expect_error_msg = ("Validation failure: The pool protocol "
                                    "'%s' is invalid while the listener "
                                    "protocol is '%s'.") % (pool_proto,
                                                            listener_proto)
                if listener['default_pool_id'] is None:
                    lb_pool['protocol'] = pool_proto
                    lb_pool['listener_id'] = listener.get('id')
                    res = self.post(self.POOLS_PATH, self._build_body(lb_pool),
                                    status=400, expect_errors=True)
                    if pool_proto == constants.PROTOCOL_TERMINATED_HTTPS:
                        self.assertIn('Invalid input',
                                      res.json['faultstring'])
                    else:
                        self.assertEqual(expect_error_msg,
                                         res.json['faultstring'])
                    self.assert_correct_status(lb_id=self.lb_id)

    @mock.patch.object(noop_driver.NoopProviderDriver, 'supports_backend_h2c',
                       True, create=True)
    def test_backend_h2c_enrollment_and_clear(self):
        args = (self.lb_id, constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN)
        self.create_pool(*args, backend_h2c=True, status=501)
        self.conf.config(group='api_settings',
                         enabled_backend_h2c_providers=['noop_driver'])
        pool = self.create_pool(*args, backend_h2c=True)['pool']
        self.assertIs(True, pool['backend_h2c'])
        self.set_lb_status(self.lb_id)
        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.put(path, {'pool': {'tls_enabled': True}}, status=400)
        self.put(path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.conf.config(group='api_settings',
                         enabled_backend_h2c_providers=[])
        self.assertIs(True, self.get(path).json['pool']['backend_h2c'])
        self.put(path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(path, {'pool': {'backend_h2c': False}})
        self.assertIs(False, self.get(path).json['pool']['backend_h2c'])
        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {'backend_h2c': True}}, status=501)

    @mock.patch.object(noop_driver.NoopProviderDriver, 'supports_backend_h2c',
                       True, create=True)
    def test_backend_h2c_requires_plain_http(self):
        self.conf.config(group='api_settings',
                         enabled_backend_h2c_providers=['noop_driver'])
        for protocol, options in ((constants.PROTOCOL_TCP, {}),
                                  (constants.PROTOCOL_HTTP,
                                   {'tls_enabled': True})):
            self.create_pool(self.lb_id, protocol,
                             constants.LB_ALGORITHM_ROUND_ROBIN,
                             backend_h2c=True, status=400, **options)

    @mock.patch.object(noop_driver.NoopProviderDriver, 'supports_backend_h2c',
                       True, create=True)
    def test_backend_h2c_nested_pool(self):
        pool = {'name': 'grpc', 'protocol': constants.PROTOCOL_HTTP,
                'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
                'backend_h2c': True}
        body = {'loadbalancer': {
            'vip_subnet_id': uuidutils.generate_uuid(),
            'project_id': self.project_id,
            'listeners': [{'name': 'http', 'protocol': constants.PROTOCOL_HTTP,
                           'protocol_port': 80, 'default_pool': pool}]}}
        self.post(self.LBS_PATH, body, status=501)
        self.conf.config(group='api_settings',
                         enabled_backend_h2c_providers=['noop_driver'])
        result = self.post(self.LBS_PATH, body).json['loadbalancer']
        selected, = result['pools']
        self.assertIs(True, selected['backend_h2c'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_h2_alpn', True, create=True)
    def test_backend_tls_require_h2_enrollment_and_drain(self):
        args = (self.lb_id, constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN)
        options = {
            'backend_tls_hostname': 'backend.example.test',
            'tls_enabled': True,
            'ca_tls_container_ref': uuidutils.generate_uuid(),
            'backend_tls_require_h2': True,
        }
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'])
        self.create_pool(*args, **options, status=501)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_h2_alpn_providers=['noop_driver'])
        self.create_pool(*args, backend_tls_require_h2=True, status=400)

        pool = self.create_pool(*args, **options)['pool']
        self.assertIs(True, pool['backend_tls_require_h2'])
        self.set_lb_status(self.lb_id)
        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.put(path, {'pool': {'backend_tls_require_h2': False}}, status=400)
        self.put(path, {'pool': {'backend_tls_hostname': None}}, status=400)
        self.conf.config(group='api_settings',
                         enabled_backend_tls_h2_alpn_providers=[])
        update = self.put(path, {'pool': {'admin_state_up': False}}).json
        self.assertIs(True, update['pool']['backend_tls_require_h2'])
        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {'admin_state_up': True}}, status=501)
        update = self.put(
            path, {'pool': {'backend_tls_require_h2': False}}).json['pool']
        self.assertIs(False, update['backend_tls_require_h2'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_h2_alpn', True, create=True)
    def test_backend_tls_require_h2_upgrade_revalidates_hostname_and_ca(self):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'],
            enabled_backend_tls_h2_alpn_providers=['noop_driver'])
        secret = self.cert_manager_mock().get_secret
        secret.return_value = sample_certs.X509_CA_CERT
        ca_ref = uuidutils.generate_uuid()
        pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            backend_tls_hostname='backend.example.test', tls_enabled=True,
            ca_tls_container_ref=ca_ref)['pool']
        self.set_lb_status(self.lb_id)
        path = self.POOL_PATH.format(pool_id=pool['id'])
        update = {'pool': {'backend_tls_require_h2': True}}

        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=[])
        self.put(path, update, status=501)

        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'])
        secret.side_effect = KeyError('missing CA')
        self.put(path, update, status=400)
        self.assertFalse(self.get(path).json['pool']['backend_tls_require_h2'])
        self.assertEqual(ca_ref, secret.call_args.args[1])

        secret.side_effect = None
        updated = self.put(path, update).json['pool']
        self.assertIs(True, updated['backend_tls_require_h2'])
        self.assertEqual(ca_ref, updated['ca_tls_container_ref'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_h2_alpn', True, create=True)
    @mock.patch.object(driver_utils, 'BACKEND_TLS_H2_ALPN_PAYLOAD_AVAILABLE',
                       False)
    @mock.patch.object(noop_driver.NoopProviderDriver, 'pool_update',
                       autospec=True)
    @mock.patch.object(noop_driver.NoopProviderDriver, 'pool_delete',
                       autospec=True)
    def test_legacy_provider_dto_can_drain_and_delete_h2_pool(
            self, provider_delete, provider_update):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'],
            enabled_backend_tls_h2_alpn_providers=['noop_driver'])
        secret = self.cert_manager_mock().get_secret
        secret.return_value = sample_certs.X509_CA_CERT
        pool = self.create_pool(
            self.lb_id, constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            backend_tls_hostname='backend.example.test', tls_enabled=True,
            ca_tls_container_ref=uuidutils.generate_uuid())['pool']
        # Simulate a pool enrolled before the provider DTO was downgraded.
        with db_api.session().begin() as session:
            self.pool_repo.update(session, pool['id'],
                                  backend_tls_require_h2=True)
        self.set_lb_status(self.lb_id)
        path = self.POOL_PATH.format(pool_id=pool['id'])

        secret.side_effect = KeyError('missing CA')
        drained = self.put(path, {'pool': {'admin_state_up': False}}).json
        self.assertIs(False, drained['pool']['admin_state_up'])
        self.assertIs(True, drained['pool']['backend_tls_require_h2'])
        self.assertNotIn('backend_tls_require_h2',
                         provider_update.call_args.args[1].to_dict())

        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {'admin_state_up': True}}, status=501)
        self.delete(path)
        self.assertNotIn('backend_tls_require_h2',
                         provider_delete.call_args.args[1].to_dict())

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    def test_backend_tls_hostname_enrollment_and_drain(self):
        hostname = 'backend.example.test'
        ca_ref = uuidutils.generate_uuid()
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        args = (self.lb_id, constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN)
        options = {'backend_tls_hostname': hostname, 'tls_enabled': True,
                   'ca_tls_container_ref': ca_ref}
        self.create_pool(*args, **options, status=501)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'])
        self.create_pool(*args, backend_tls_hostname=hostname, status=400)
        self.create_pool(*args, **dict(options, backend_h2c=True), status=400)
        self.create_pool(*args, **dict(options, backend_tls_hostname='str(x)'),
                         status=400)
        pool = self.create_pool(*args, **options)['pool']
        self.assertEqual(hostname, pool['backend_tls_hostname'])
        self.assertNotIn('ca_tls_container_data', pool)

        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {'tls_enabled': False}}, status=400)
        self.put(path, {'pool': {'ca_tls_container_ref': None}}, status=400)
        self.put(path, {'pool': {'backend_tls_hostname': None}}, status=400)
        update = self.put(path, {'pool': {
            'ca_tls_container_ref': uuidutils.generate_uuid()}}).json['pool']
        self.assertEqual(hostname, update['backend_tls_hostname'])
        self.assertNotEqual(ca_ref, update['ca_tls_container_ref'])
        self.set_lb_status(self.lb_id)

        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=[])
        self.assertEqual(hostname,
                         self.get(path).json['pool']['backend_tls_hostname'])
        self.put(path, {'pool': {'admin_state_up': False}})
        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {'admin_state_up': True}}, status=501)
        self.put(path, {'pool': {'backend_tls_hostname': None,
                                 'admin_state_up': True}}, status=400)
        update = self.put(path, {'pool': {
            'backend_tls_hostname': None, 'tls_enabled': False,
            'ca_tls_container_ref': None}}).json['pool']
        self.assertIsNone(update['backend_tls_hostname'])
        self.assertFalse(update['admin_state_up'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    def test_backend_tls_hostname_nested_pool(self):
        hostname = 'backend.example.test'
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        pool = {'name': 'https-backend', 'protocol': constants.PROTOCOL_HTTP,
                'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
                'tls_enabled': True,
                'ca_tls_container_ref': uuidutils.generate_uuid(),
                'backend_tls_hostname': hostname}
        body = {'loadbalancer': {
            'vip_subnet_id': uuidutils.generate_uuid(),
            'project_id': self.project_id,
            'listeners': [{'name': 'http', 'protocol': constants.PROTOCOL_HTTP,
                           'protocol_port': 80, 'default_pool': pool}]}}
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'])
        result = self.post(self.LBS_PATH, body).json['loadbalancer']
        selected, = result['pools']
        self.assertEqual(hostname, selected['backend_tls_hostname'])

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_subject_alt_names',
                       True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver, 'pool_update',
                       autospec=True)
    def test_backend_tls_sans_partial_update_and_clear(self, provider_update):
        field = 'backend_tls_subject_alt_names'
        identities = [
            {'type': 'Hostname', 'hostname': '*.Backend.Example.test'},
            {'type': 'URI',
             'uri': 'spiffe://id.example.test/workload%2fa?key=value#ID'},
            {'type': 'URI', 'uri': 'https://id.example.test:000443/workload'},
            {'type': 'URI', 'uri': 'https://@id.example.test/workload'},
        ]
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'])
        args = (self.lb_id, constants.PROTOCOL_HTTP,
                constants.LB_ALGORITHM_ROUND_ROBIN)
        options = {
            'backend_tls_hostname': 'sni.example.test', 'tls_enabled': True,
            'ca_tls_container_ref': uuidutils.generate_uuid(),
        }
        self.create_pool(*args, **options, **{field: identities}, status=501)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_subject_alt_names_providers=['noop_driver'])
        self.create_pool(*args, **{field: identities}, status=400)
        self.create_pool(*args, **options, **{field: None}, status=400)

        created = self.create_pool(*args, **options, **{field: identities})
        pool = created['pool']
        self.assertEqual(identities, pool[field])
        path = self.POOL_PATH.format(pool_id=pool['id'])
        self.set_lb_status(self.lb_id)
        for invalid in (
                None, 'sni.example.test', [None], identities * 3,
                [{'type': 'hostname', 'hostname': 'example.test'}],
                [{'type': 'Hostname', 'hostname': '192.0.2.2'}],
                [{'type': 'Hostname', 'hostname': 123}],
                [{'type': 'Hostname', 'hostname': 'example.test', 'uri': ''}],
                [{'type': 'URI', 'uri': '/relative'}],
                [{'type': 'URI', 'uri': 'spiffe://example.test/bad%xx'}],
                [{'type': 'URI', 'uri': 'spiffe://exa_mple.test/path'}]):
            with self.subTest(invalid=invalid):
                self.put(path, {'pool': {field: invalid}}, status=400)
        self.put(path, {'pool': {'ca_tls_container_ref': None}}, status=400)
        self.put(path, {'pool': {'backend_tls_hostname': None}}, status=400)
        self.put(path, {'pool': {'tls_enabled': False}}, status=400)

        replacement = identities[1:]
        updated = self.put(path, {'pool': {field: replacement}}).json['pool']
        self.assertEqual(replacement, updated[field])
        self.assertEqual(replacement,
                         provider_update.call_args.args[2].to_dict()[field])
        self.set_lb_status(self.lb_id)

        self.conf.config(
            group='api_settings',
            enabled_backend_tls_subject_alt_names_providers=[])
        preserved = self.put(path, {'pool': {'name': 'updated'}}).json['pool']
        self.assertEqual(replacement, preserved[field])
        self.assertEqual(replacement,
                         provider_update.call_args.args[1].to_dict()[field])
        self.assertNotIn(field, provider_update.call_args.args[2].to_dict())

        self.set_lb_status(self.lb_id)
        self.put(path, {'pool': {field: identities}}, status=501)
        cleared = self.put(path, {'pool': {field: []}}).json['pool']
        self.assertEqual([], cleared[field])
        delta = provider_update.call_args.args[2].to_dict()
        self.assertEqual([], delta[field])
        self.assertEqual([], self.get(path).json['pool'][field])
        self.assertEqual('sni.example.test', cleared['backend_tls_hostname'])
        with db_api.session().begin() as session:
            self.assertEqual([], self.pool_repo.get(session, id=pool['id'])
                             .backend_tls_subject_alt_names)

    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_hostname', True, create=True)
    @mock.patch.object(noop_driver.NoopProviderDriver,
                       'supports_backend_tls_subject_alt_names',
                       True, create=True)
    def test_backend_tls_sans_nested_pool(self):
        identities = [{'type': 'Hostname', 'hostname': 'id.example.test'}]
        self.cert_manager_mock().get_secret.return_value = (
            sample_certs.X509_CA_CERT)
        pool = {
            'name': 'san-backend',
            'protocol': constants.PROTOCOL_HTTP,
            'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
            'tls_enabled': True,
            'ca_tls_container_ref': uuidutils.generate_uuid(),
            'backend_tls_hostname': 'sni.example.test',
            'backend_tls_subject_alt_names': identities,
        }
        body = {'loadbalancer': {
            'vip_subnet_id': uuidutils.generate_uuid(),
            'project_id': self.project_id,
            'listeners': [{'name': 'http', 'protocol': constants.PROTOCOL_HTTP,
                           'protocol_port': 80, 'default_pool': pool}]}}
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['noop_driver'],
            enabled_backend_tls_subject_alt_names_providers=['noop_driver'])
        result = self.post(self.LBS_PATH, body).json['loadbalancer']
        selected, = result['pools']
        self.assertEqual(identities, selected['backend_tls_subject_alt_names'])

    def test_create_with_alpn(self):
        alpn_protocols = [lib_constants.ALPN_PROTOCOL_HTTP_2,
                          lib_constants.ALPN_PROTOCOL_HTTP_1_1]
        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_enabled=True,
            alpn_protocols=alpn_protocols).get(self.root_tag)
        self.assertEqual(alpn_protocols, api_pool['alpn_protocols'])

    def test_create_with_alpn_negative(self):
        req_dict = {'protocol': constants.PROTOCOL_HTTP,
                    'lb_algorithm': constants.LB_ALGORITHM_ROUND_ROBIN,
                    'listener_id': self.listener_id,
                    'tls_enabled': True,
                    'alpn_protocols': [lib_constants.ALPN_PROTOCOL_HTTP_1_1,
                                       'invalid-proto']}
        res = self.post(self.POOLS_PATH, self._build_body(req_dict),
                        status=400)
        fault = res.json['faultstring']
        self.assertIn(
            'Invalid input for field/attribute alpn_protocols', fault)
        self.assertIn('Value should be a valid ALPN protocol ID', fault)
        self.assert_correct_status(lb_id=self.lb_id)

    def test_update_with_alpn(self):
        alpn_protocols_orig = [lib_constants.ALPN_PROTOCOL_HTTP_1_0]
        alpn_protocols = [lib_constants.ALPN_PROTOCOL_HTTP_2,
                          lib_constants.ALPN_PROTOCOL_HTTP_1_1]
        pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_enabled=True,
            alpn_protocols=alpn_protocols_orig)
        self.set_lb_status(self.lb_id)
        pool_path = self.POOL_PATH.format(pool_id=pool['pool']['id'])
        get_pool = self.get(pool_path).json['pool']
        self.assertEqual(alpn_protocols_orig, get_pool.get('alpn_protocols'))
        self.put(pool_path,
                 self._build_body({'alpn_protocols': alpn_protocols}))
        get_pool = self.get(pool_path).json['pool']
        self.assertEqual(alpn_protocols, get_pool.get('alpn_protocols'))

    def test_update_with_alpn_negative(self):
        alpn_protocols_orig = [lib_constants.ALPN_PROTOCOL_HTTP_1_0]
        pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id,
            tls_enabled=True,
            alpn_protocols=alpn_protocols_orig)
        self.set_lb_status(self.lb_id)
        pool_path = self.POOL_PATH.format(pool_id=pool['pool']['id'])
        get_pool = self.get(pool_path).json['pool']
        self.assertEqual(alpn_protocols_orig, get_pool.get('alpn_protocols'))

        req_dict = {'alpn_protocols': [
            lib_constants.ALPN_PROTOCOL_HTTP_1_1, 'invalid-proto']}
        res = self.put(self.POOLS_PATH, self._build_body(req_dict), status=400)
        fault = res.json['faultstring']
        self.assertIn(
            'Invalid input for field/attribute alpn_protocols', fault)
        self.assertIn('Value should be a valid ALPN protocol ID', fault)
        self.assert_correct_status(lb_id=self.lb_id)

    @mock.patch("octavia.api.drivers.noop_driver.driver.NoopManager."
                "pool_update")
    def test_update_with_exception_in_provider_driver(self, pool_update_mock):
        pool_update_mock.side_effect = Exception("Provider error")

        api_pool = self.create_pool(
            self.lb_id,
            constants.PROTOCOL_HTTP,
            constants.LB_ALGORITHM_ROUND_ROBIN,
            listener_id=self.listener_id).get(self.root_tag)
        self.set_lb_status(lb_id=self.lb_id)

        new_pool = {'name': 'foo'}
        self.put(self.POOL_PATH.format(pool_id=api_pool.get('id')),
                 self._build_body(new_pool), status=500)

        lb = self.get(self.LB_PATH.format(lb_id=self.lb_id)).json.get(
            "loadbalancer")
        self.assertEqual(lb[constants.PROVISIONING_STATUS],
                         constants.ACTIVE)
