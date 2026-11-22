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

from unittest import mock

from octavia_lib.api.drivers import exceptions as lib_exceptions
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.api.drivers.noop_driver import driver as noop_driver
from octavia.common import constants
import octavia.common.context
from octavia.common import data_models
from octavia.common import exceptions
from octavia.tests.common import constants as c_const
from octavia.tests.functional.api.v2 import base


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
        self.assertEqual('a.example.test', policy['rules'][0]['value'])
        self.assertEqual(lb['pools'][0]['id'], policy['redirect_pool_id'])
        listener_path = self.LISTENER_PATH.format(listener_id=saved['id'])
        self.assertTrue(self.get(listener_path).json['listener'][
            'tcp_tls_termination'])

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
