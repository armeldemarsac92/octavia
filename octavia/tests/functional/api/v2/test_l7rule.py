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

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.common import constants
import octavia.common.context
from octavia.common import data_models
from octavia.common import exceptions
from octavia.db import repositories
from octavia.tests.functional.api.v2 import base


class TestL7Rule(base.BaseAPITest):

    root_tag = 'rule'
    root_tag_list = 'rules'
    root_tag_links = 'rules_links'

    def setUp(self):
        super().setUp()
        self.lb = self.create_load_balancer(uuidutils.generate_uuid())
        self.lb_id = self.lb.get('loadbalancer').get('id')
        self.project_id = self.lb.get('loadbalancer').get('project_id')
        self.set_lb_status(self.lb_id)
        self.listener = self.create_listener(
            constants.PROTOCOL_HTTP, 80, lb_id=self.lb_id)
        self.listener_id = self.listener.get('listener').get('id')
        self.set_lb_status(self.lb_id)
        self.l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT)
        self.l7policy_id = self.l7policy.get('l7policy').get('id')
        self.set_lb_status(self.lb_id)
        self.l7rules_path = self.L7RULES_PATH.format(
            l7policy_id=self.l7policy_id)
        self.l7rule_path = self.l7rules_path + '/{l7rule_id}'
        self.l7policy_repo = repositories.L7PolicyRepository()

    def test_get(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', tags=['test_tag']).get(self.root_tag)
        response = self.get(self.l7rule_path.format(
            l7rule_id=l7rule.get('id'))).json.get(self.root_tag)
        self.assertEqual(l7rule, response)

    def test_get_authorized(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
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
            response = self.get(self.l7rule_path.format(
                l7rule_id=l7rule.get('id'))).json.get(self.root_tag)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(l7rule, response)

    def test_get_not_authorized(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            response = self.get(self.l7rule_path.format(
                l7rule_id=l7rule.get('id')), status=403).json
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, response)

    def test_get_with_wrong_l7policy(self):
        """Regression test for bug 2171382.

        GET must verify that the rule named in the URL actually belongs to
        the l7policy named in the URL. Without that check, a rule can be
        fetched through a different, real l7policy's URL within the same
        project ("answers under the wrong path") instead of the request
        being rejected with 404.

        Note: unlike PUT/DELETE, GET already authorizes against the
        rule's own project, so this does not leak data across tenants by
        itself -- but the policy/rule relationship in the URL should
        still be validated for consistency.
        """
        victim_rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/admin').get(self.root_tag)
        victim_rule_id = victim_rule.get('id')
        self.set_lb_status(self.lb_id)

        # A second, real l7policy in the SAME project/listener that does
        # NOT own the rule created above.
        other_l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT).get(
            'l7policy')
        other_l7policy_id = other_l7policy.get('id')
        self.set_lb_status(self.lb_id)

        wrong_path = self.L7RULE_PATH.format(
            l7policy_id=other_l7policy_id, l7rule_id=victim_rule_id)
        self.get(wrong_path, status=404)

    def test_get_deleted_gives_404(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)

        self.set_object_status(self.l7rule_repo, api_l7rule.get('id'),
                               provisioning_status=constants.DELETED)
        self.get(self.l7rule_path.format(l7rule_id=api_l7rule.get('id')),
                 status=404)

    def test_get_bad_parent_policy(self):
        bad_path = (self.L7RULES_PATH.format(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=uuidutils.generate_uuid()) + '/' +
            uuidutils.generate_uuid())
        self.get(bad_path, status=404)

    def test_bad_get(self):
        self.get(self.l7rule_path.format(
            l7rule_id=uuidutils.generate_uuid()), status=404)

    def test_get_all(self):
        api_l7r_a = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', tags=['test_tag1']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        api_l7r_b = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie', tags=['test_tag2']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        rules = self.get(self.l7rules_path).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(2, len(rules))
        rule_id_types = [(r.get('id'), r.get('type'),
                          r['tags']) for r in rules]
        self.assertIn((api_l7r_a.get('id'), api_l7r_a.get('type'),
                       api_l7r_a['tags']),
                      rule_id_types)
        self.assertIn((api_l7r_b.get('id'), api_l7r_b.get('type'),
                       api_l7r_b['tags']),
                      rule_id_types)

    def test_get_all_authorized(self):
        api_l7r_a = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        api_l7r_b = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
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
            rules = self.get(
                self.l7rules_path).json.get(self.root_tag_list)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertIsInstance(rules, list)
        self.assertEqual(2, len(rules))
        rule_id_types = [(r.get('id'), r.get('type')) for r in rules]
        self.assertIn((api_l7r_a.get('id'), api_l7r_a.get('type')),
                      rule_id_types)
        self.assertIn((api_l7r_b.get('id'), api_l7r_b.get('type')),
                      rule_id_types)

    def test_get_all_unscoped_token(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
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
            result = self.get(self.l7rules_path, status=403).json
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, result)

    def test_get_all_not_authorized(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            rules = self.get(self.l7rules_path, status=403)

        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, rules.json)

    def test_get_all_sorted(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        response = self.get(self.l7rules_path,
                            params={'sort': 'type:desc'})
        rules_desc = response.json.get(self.root_tag_list)
        response = self.get(self.l7rules_path,
                            params={'sort': 'type:asc'})
        rules_asc = response.json.get(self.root_tag_list)

        self.assertEqual(3, len(rules_desc))
        self.assertEqual(3, len(rules_asc))

        rule_id_types_desc = [(rule.get('id'), rule.get('type'))
                              for rule in rules_desc]
        rule_id_types_asc = [(rule.get('id'), rule.get('type'))
                             for rule in rules_asc]
        self.assertEqual(rule_id_types_asc,
                         list(reversed(rule_id_types_desc)))

    def test_get_all_limited(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        # First two -- should have 'next' link
        first_two = self.get(self.l7rules_path, params={'limit': 2}).json
        objs = first_two[self.root_tag_list]
        links = first_two[self.root_tag_links]
        self.assertEqual(2, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('next', links[0]['rel'])

        # Third + off the end -- should have previous link
        third = self.get(self.l7rules_path, params={
            'limit': 2,
            'marker': first_two[self.root_tag_list][1]['id']}).json
        objs = third[self.root_tag_list]
        links = third[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(1, len(links))
        self.assertEqual('previous', links[0]['rel'])

        # Middle -- should have both links
        middle = self.get(self.l7rules_path, params={
            'limit': 1,
            'marker': first_two[self.root_tag_list][0]['id']}).json
        objs = middle[self.root_tag_list]
        links = middle[self.root_tag_links]
        self.assertEqual(1, len(objs))
        self.assertEqual(2, len(links))
        self.assertCountEqual(['previous', 'next'],
                              [link['rel'] for link in links])

    def test_get_all_fields_filter(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7rus = self.get(self.l7rules_path, params={
            'fields': ['id', 'compare_type']}).json
        for l7ru in l7rus['rules']:
            self.assertIn('id', l7ru)
            self.assertIn('compare_type', l7ru)
            self.assertNotIn('project_id', l7ru)

    def test_get_one_fields_filter(self):
        l7r1 = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7ru = self.get(
            self.l7rule_path.format(l7rule_id=l7r1.get('id')),
            params={'fields': ['id', 'compare_type']}).json.get(self.root_tag)
        self.assertIn('id', l7ru)
        self.assertIn('compare_type', l7ru)
        self.assertNotIn('project_id', l7ru)

    def test_get_all_filter(self):
        ru1 = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com').get(self.root_tag)
        self.set_lb_status(self.lb_id)

        l7rus = self.get(self.l7rules_path, params={
            'id': ru1['id']}).json

        self.assertEqual(1, len(l7rus['rules']))
        self.assertEqual(ru1['id'],
                         l7rus['rules'][0]['id'])

    def test_get_all_tags_filter(self):
        rule1 = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', tags=['test_tag1', 'test_tag2']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        rule2 = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie',
            tags=['test_tag2', 'test_tag3']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        rule3 = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com',
            tags=['test_tag4', 'test_tag5']).get(self.root_tag)
        self.set_lb_status(self.lb_id)

        rules = self.get(
            self.l7rules_path,
            params={'tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(2, len(rules))
        self.assertEqual(
            [rule1.get('id'), rule2.get('id')],
            [rule.get('id') for rule in rules]
        )

        rules = self.get(
            self.l7rules_path,
            params={'tags': ['test_tag2', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(1, len(rules))
        self.assertEqual(
            [rule2.get('id')],
            [rule.get('id') for rule in rules]
        )

        rules = self.get(
            self.l7rules_path,
            params={'tags-any': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(2, len(rules))
        self.assertEqual(
            [rule1.get('id'), rule2.get('id')],
            [rule.get('id') for rule in rules]
        )

        rules = self.get(
            self.l7rules_path,
            params={'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(1, len(rules))
        self.assertEqual(
            [rule3.get('id')],
            [rule.get('id') for rule in rules]
        )

        rules = self.get(
            self.l7rules_path,
            params={'not-tags-any': ['test_tag2', 'test_tag4']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(0, len(rules))

        rules = self.get(
            self.l7rules_path,
            params={'tags': 'test_tag2',
                    'tags-any': ['test_tag1', 'test_tag3']}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(2, len(rules))
        self.assertEqual(
            [rule1.get('id'), rule2.get('id')],
            [rule.get('id') for rule in rules]
        )

        rules = self.get(
            self.l7rules_path,
            params={'tags': 'test_tag2', 'not-tags': 'test_tag2'}
        ).json.get(self.root_tag_list)
        self.assertIsInstance(rules, list)
        self.assertEqual(0, len(rules))

    def test_empty_get_all(self):
        response = self.get(self.l7rules_path).json.get(self.root_tag_list)
        self.assertIsInstance(response, list)
        self.assertEqual(0, len(response))

    def test_get_all_hides_deleted(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)

        response = self.get(self.l7rules_path)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 1)
        self.set_object_status(self.l7rule_repo, api_l7rule.get('id'),
                               provisioning_status=constants.DELETED)
        response = self.get(self.l7rules_path)
        objects = response.json.get(self.root_tag_list)
        self.assertEqual(len(objects), 0)

    def test_create_host_name_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com').get(self.root_tag)
        self.assertEqual(constants.L7RULE_TYPE_HOST_NAME,
                         api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                         api_l7rule.get('compare_type'))
        self.assertEqual('www.example.com', api_l7rule.get('value'))
        self.assertIsNone(api_l7rule.get('key'))
        self.assertFalse(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    def test_disable_legacy_path_regex_with_final_linefeed(self):
        value = '/legacy\n'
        rule = self.create_l7rule(
            self.l7policy_id, 'PATH', 'REGEX', value)['rule']
        self.set_lb_status(self.lb_id)
        path = self.L7RULE_PATH.format(
            l7policy_id=self.l7policy_id, l7rule_id=rule['id'])
        self.put(path, {'rule': {'value': '/legacy\nsuffix'}}, status=400)
        self.put(path, {'rule': {'admin_state_up': False}})
        saved = self.get(path).json['rule']
        self.assertEqual(value, saved['value'])
        self.assertFalse(saved['admin_state_up'])

    def test_create_rule_authorized(self):
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
            api_l7rule = self.create_l7rule(
                self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                'www.example.com').get(self.root_tag)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(constants.L7RULE_TYPE_HOST_NAME,
                         api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                         api_l7rule.get('compare_type'))
        self.assertEqual('www.example.com', api_l7rule.get('value'))
        self.assertIsNone(api_l7rule.get('key'))
        self.assertFalse(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    def test_create_rule_not_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)

        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            api_l7rule = self.create_l7rule(
                self.l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                'www.example.com', status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, api_l7rule)

    def test_create_l7policy_in_error(self):
        l7policy = self.create_l7policy(
            self.listener_id, constants.L7POLICY_ACTION_REJECT)
        l7policy_id = l7policy.get('l7policy').get('id')
        self.set_lb_status(self.lb_id)
        self.set_object_status(self.l7policy_repo, l7policy_id,
                               provisioning_status=constants.ERROR)
        api_l7rule = self.create_l7rule(
            l7policy_id, constants.L7RULE_TYPE_HOST_NAME,
            constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
            'www.example.com', status=409)
        ref_msg = f'L7Policy {l7policy_id} is immutable and cannot be updated.'
        self.assertEqual(ref_msg, api_l7rule.get('faultstring'))

    def test_create_path_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH, '/api',
            invert=True).get(self.root_tag)
        self.assertEqual(constants.L7RULE_TYPE_PATH, api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                         api_l7rule.get('compare_type'))
        self.assertEqual('/api', api_l7rule.get('value'))
        self.assertIsNone(api_l7rule.get('key'))
        self.assertTrue(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    def test_create_file_type_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_FILE_TYPE,
            constants.L7RULE_COMPARE_TYPE_REGEX, 'jpg|png').get(self.root_tag)
        self.assertEqual(constants.L7RULE_TYPE_FILE_TYPE,
                         api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_REGEX,
                         api_l7rule.get('compare_type'))
        self.assertEqual('jpg|png', api_l7rule.get('value'))
        self.assertIsNone(api_l7rule.get('key'))
        self.assertFalse(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    def test_create_header_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_HEADER,
            constants.L7RULE_COMPARE_TYPE_ENDS_WITH, '"some string"',
            key='Some-header').get(self.root_tag)
        self.assertEqual(constants.L7RULE_TYPE_HEADER, api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                         api_l7rule.get('compare_type'))
        self.assertEqual('"some string"', api_l7rule.get('value'))
        self.assertEqual('Some-header', api_l7rule.get('key'))
        self.assertFalse(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_full_header_rule_create_and_update(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)

        key = 'X-' + 'a' * 253
        oversized_key = key + 'a'
        value = 'one, ' + 'x' * 4091
        rpc.return_value.cast.reset_mock()
        self.create_l7rule(policy['id'], 'HTTP_HEADER_EXACT', 'EQUAL_TO',
                           value, key=key, status=501)
        self.conf.config(group='api_settings',
                         enabled_http_header_exact_providers=['amphora'])
        self.create_l7rule(policy['id'], 'HTTP_HEADER_EXACT', 'EQUAL_TO',
                           value, key=oversized_key, status=400)
        self.create_l7rule(policy['id'], 'HEADER', 'EQUAL_TO',
                           'one', key=oversized_key, status=400)
        self.create_l7rule(policy['id'], 'HEADER', 'EQUAL_TO',
                           'x' * 256, key='X-Version', status=400)
        self.create_l7rule(policy['id'], 'HTTP_HEADER_EXACT', 'REGEX',
                           value, key=key, status=400)
        self.create_l7rule(policy['id'], 'HTTP_HEADER_EXACT', 'EQUAL_TO',
                           ' one', key=key, status=400)
        rpc.return_value.cast.assert_not_called()
        rules_path = self.L7RULES_PATH.format(l7policy_id=policy['id'])
        self.assertEqual([], self.get(rules_path).json['rules'])
        rule = self.create_l7rule(policy['id'], 'HTTP_HEADER_EXACT',
                                  'EQUAL_TO', value, key=key)['rule']
        self.assertEqual(key, rule['key'])
        self.assertEqual(value, rule['value'])
        path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                       l7rule_id=rule['id'])
        self.set_lb_status(lb_id)
        rpc.return_value.cast.reset_mock()
        self.put(path, {'rule': {'key': oversized_key}}, status=400)
        self.put(path, {'rule': {'type': 'HEADER'}}, status=400)
        rpc.return_value.cast.assert_not_called()
        self.assertEqual(key, self.get(path).json['rule']['key'])
        new_value = 'two,\t café'
        self.put(path, {'rule': {'value': new_value}})
        self.set_lb_status(lb_id)
        self.assertEqual(new_value, self.get(path).json['rule']['value'])
        self.conf.config(group='api_settings',
                         enabled_http_header_exact_providers=[])
        self.put(path, {'rule': {'value': 'one, other'}}, status=501)
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy['id'])
        listener_path = self.LISTENER_PATH.format(listener_id=listener['id'])
        lb_path = self.LB_PATH.format(lb_id=lb_id)
        parents = (
            (policy_path, 'l7policy'),
            (listener_path, 'listener'),
            (lb_path, 'loadbalancer'),
        )
        for parent_path, tag in parents:
            with self.subTest(parent=tag):
                self.put(parent_path, {tag: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                rpc.return_value.cast.reset_mock()
                self.put(parent_path, {tag: {'admin_state_up': True}},
                         status=501)
                rpc.return_value.cast.assert_not_called()
                self.assertFalse(
                    self.get(parent_path).json[tag]['admin_state_up'])
                self.conf.config(
                    group='api_settings',
                    enabled_http_header_exact_providers=['amphora'])
                reopened = self.put(parent_path,
                                    {tag: {'admin_state_up': True}}).json[tag]
                self.assertTrue(reopened['admin_state_up'])
                self.set_lb_status(lb_id)
                self.conf.config(
                    group='api_settings',
                    enabled_http_header_exact_providers=[])
        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        self.create_l7rule(policy['id'], 'HEADER', 'EQUAL_TO',
                           'one', key='X-Version')
        self.set_lb_status(lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        reopened = self.put(policy_path, {
            'l7policy': {'admin_state_up': True}}).json['l7policy']
        self.assertTrue(reopened['admin_state_up'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_long_http_hostname_rule_admission_and_lifecycle(self, rpc):
        option = 'enabled_http_long_hostname_providers'
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        policy_id = policy['id']
        # 127 one-character labels make a legal 253-character DNS name.
        value = '^' + r'\.'.join(['a'] * 127) + '(:[0-9]+)?$'

        legacy = self.create_l7rule(policy_id, 'HOST_NAME', 'REGEX',
                                    'a' * 255)['rule']
        self.set_lb_status(lb_id)
        legacy_path = self.L7RULE_PATH.format(l7policy_id=policy_id,
                                              l7rule_id=legacy['id'])
        rpc.return_value.cast.reset_mock()
        rejected = self.create_l7rule(
            policy_id, 'HOST_NAME', 'REGEX', value, status=400)
        self.assertIn('255 characters', rejected['faultstring'])
        self.put(legacy_path, {'rule': {'value': value}}, status=400)
        self.conf.config(group='api_settings', **{option: ['noop_driver']})
        self.create_l7rule(self.l7policy_id, 'HOST_NAME', 'REGEX', value,
                           status=400)
        rpc.return_value.cast.assert_not_called()

        self.conf.config(group='api_settings', **{option: ['amphora']})
        for rule_type, compare_type, invalid in (
                ('HOST_NAME', 'EQUAL_TO', 'a' * 256),
                ('PATH', 'REGEX', '/' + 'a' * 255),
                ('HOST_NAME', 'REGEX', 'a' * 513)):
            self.create_l7rule(policy_id, rule_type, compare_type, invalid,
                               status=400)
        rule = self.create_l7rule(policy_id, 'HOST_NAME', 'REGEX', value,
                                  invert=True)['rule']
        self.set_lb_status(lb_id)
        path = self.L7RULE_PATH.format(l7policy_id=policy_id,
                                       l7rule_id=rule['id'])
        saved = self.get(path).json['rule']
        self.assertEqual(value, saved['value'])
        self.assertTrue(saved['invert'])
        self.put(legacy_path, {'rule': {'value': 'a' * 512}})
        self.set_lb_status(lb_id)
        self.assertEqual('a' * 512,
                         self.get(legacy_path).json['rule']['value'])
        self.put(legacy_path, {'rule': {'value': 'a' * 513}}, status=400)
        self.delete(legacy_path)
        self.set_lb_status(lb_id)

        self.conf.config(group='api_settings', **{option: []})
        self.put(path, {'rule': {'invert': False}}, status=400)
        for parent_path, tag in (
                (self.L7POLICY_PATH.format(l7policy_id=policy_id), 'l7policy'),
                (self.LISTENER_PATH.format(listener_id=listener['id']),
                 'listener'),
                (self.LB_PATH.format(lb_id=lb_id), 'loadbalancer')):
            with self.subTest(parent=tag):
                self.put(parent_path, {tag: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                rpc.return_value.cast.reset_mock()
                self.put(parent_path, {tag: {'admin_state_up': True}},
                         status=501)
                rpc.return_value.cast.assert_not_called()
                self.conf.config(group='api_settings',
                                 **{option: ['amphora']})
                self.put(parent_path, {tag: {'admin_state_up': True}})
                self.set_lb_status(lb_id)
                self.conf.config(group='api_settings', **{option: []})

        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        retained = self.get(path).json['rule']
        self.assertEqual(value, retained['value'])
        self.assertFalse(retained['admin_state_up'])
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    @mock.patch('octavia.common.tls_utils.cert_parser.load_certificates_data')
    def test_long_http_hostname_rule_listener_protocol(self, cert_data, rpc):
        cert_data.return_value = {
            'tls_cert': data_models.TLSContainer(certificate='cert')}
        self.conf.config(group='api_settings',
                         enabled_http_long_hostname_providers=['amphora'],
                         enabled_tls_sni_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('TCP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        pool = self.create_pool(lb_id, 'TCP', 'ROUND_ROBIN')['pool']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REDIRECT_TO_POOL',
                                      redirect_pool_id=pool['id'])['l7policy']
        self.set_lb_status(lb_id)
        value = 'a' * 256
        response = self.create_l7rule(
            policy['id'], 'HOST_NAME', 'REGEX', value, status=400)
        self.assertIn('requires an HTTP', response['faultstring'])

        rule = {'type': 'HOST_NAME', 'compare_type': 'REGEX', 'value': value}
        response = self.create_listener(
            'HTTP', 81, lb_id, status=400,
            l7policies=[{'action': 'REJECT', 'rules': [rule]}])
        self.assertIn('L7 policy endpoint', response['faultstring'])
        listener = self.create_listener(
            'TERMINATED_HTTPS', 443, lb_id,
            default_tls_container_ref=uuidutils.generate_uuid())['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        self.create_l7rule(policy['id'], 'HOST_NAME', 'REGEX', value)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_query_param_rule_admission_and_lifecycle(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        policy_id = policy['id']
        rule_type = constants.L7RULE_TYPE_HTTP_QUERY_PARAM_EXACT
        key = 'X&' + 'a' * 254
        value = '\U0001f4da' * 1024
        rpc.return_value.cast.reset_mock()
        self.create_l7rule(policy_id, rule_type, 'EQUAL_TO', value, key=key,
                           status=501)
        self.conf.config(group='api_settings',
                         enabled_http_query_param_exact_providers=['amphora'])
        for comparison, name, literal in (
                ('REGEX', key, value),
                ('EQUAL_TO', None, value),
                ('EQUAL_TO', key + 'x', value),
                ('EQUAL_TO', 'x y', value),
                ('EQUAL_TO', key, ''),
                ('EQUAL_TO', key, value + 'x')):
            self.create_l7rule(policy_id, rule_type, comparison, literal,
                               key=name, status=400)
        self.create_l7rule(policy_id, 'PATH', 'REGEX', '/foo\r\nbar',
                           status=400)
        rpc.return_value.cast.assert_not_called()

        rule = self.create_l7rule(policy_id, rule_type, 'EQUAL_TO', value,
                                  key=key)['rule']
        path = self.L7RULE_PATH.format(l7policy_id=policy_id,
                                       l7rule_id=rule['id'])
        self.assertEqual(value, self.get(path).json['rule']['value'])
        self.assertEqual(key, rule['key'])
        self.set_lb_status(lb_id)
        rpc.return_value.cast.reset_mock()
        self.put(path, {'rule': {'type': 'HTTP_HEADER_EXACT',
                                 'value': 'one'}}, status=400)
        self.put(path, {'rule': {'type': 'PATH', 'key': None,
                                 'value': '/foo\r\nbar'}}, status=400)
        rpc.return_value.cast.assert_not_called()
        self.put(path, {'rule': {'value': 'one\r\ntwo', 'invert': True}})
        self.set_lb_status(lb_id)
        saved = self.get(path).json['rule']
        self.assertEqual('one\r\ntwo', saved['value'])
        self.assertTrue(saved['invert'])
        self.put(path, {'rule': {'type': 'PATH', 'compare_type': 'REGEX',
                                 'key': None}}, status=400)

        self.conf.config(group='api_settings',
                         enabled_http_query_param_exact_providers=[])
        self.put(path, {'rule': {'value': 'other'}}, status=501)
        self.assertEqual(saved, self.get(path).json['rule'])
        for parent_path, tag in (
                (self.L7POLICY_PATH.format(l7policy_id=policy_id), 'l7policy'),
                (self.LISTENER_PATH.format(listener_id=listener['id']),
                 'listener'),
                (self.LB_PATH.format(lb_id=lb_id), 'loadbalancer')):
            with self.subTest(parent=tag):
                self.put(parent_path, {tag: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                rpc.return_value.cast.reset_mock()
                self.put(parent_path, {tag: {'admin_state_up': True}},
                         status=501)
                rpc.return_value.cast.assert_not_called()
                self.assertFalse(
                    self.get(parent_path).json[tag]['admin_state_up'])
                self.conf.config(
                    group='api_settings',
                    enabled_http_query_param_exact_providers=['amphora'])
                self.put(parent_path, {tag: {'admin_state_up': True}})
                self.set_lb_status(lb_id)
                self.conf.config(
                    group='api_settings',
                    enabled_http_query_param_exact_providers=[])

        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_grpc_content_type_rule_admission_and_removal(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        policy_id = policy['id']
        rule_type = 'GRPC_CONTENT_TYPE'
        value = 'application/grpc'
        self.create_l7rule(policy_id, rule_type, 'EQUAL_TO', value, status=501)
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=['amphora'])
        rpc.return_value.cast.reset_mock()
        self.create_l7rule(policy_id, rule_type, 'REGEX', value, status=400)
        self.create_l7rule(policy_id, rule_type, 'EQUAL_TO',
                           'Application/GRPC', status=400)
        self.create_l7rule(policy_id, rule_type, 'EQUAL_TO', value,
                           key='Content-Type', status=400)
        self.create_l7rule(policy_id, rule_type, 'EQUAL_TO', value,
                           invert=True, status=400)
        rpc.return_value.cast.assert_not_called()

        legacy = self.create_l7rule(policy_id, 'HEADER', 'REGEX', '^grpc',
                                    key='Content-Type')['rule']
        self.set_lb_status(lb_id)
        path = self.L7RULE_PATH.format(l7policy_id=policy_id,
                                       l7rule_id=legacy['id'])
        self.put(path, {'rule': {'type': rule_type, 'compare_type': 'EQUAL_TO',
                                 'value': value}})
        self.set_lb_status(lb_id)
        rule = self.get(path).json['rule']
        self.assertEqual((rule_type, 'EQUAL_TO', None, value),
                         (rule['type'], rule['compare_type'], rule['key'],
                          rule['value']))
        sent = rpc.return_value.cast.call_args.kwargs
        self.assertIsNone(sent[constants.L7RULE_UPDATES]['key'])

        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=[])
        policy_path = self.L7POLICY_PATH.format(l7policy_id=policy_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}},
                 status=501)
        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        self.put(policy_path, {'l7policy': {'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.delete(path)

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_rule_type_conversion_requires_opt_in(self, rpc):
        lb_id = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)
        path_match = {'type': 'PATH', 'key': None, 'value': '/catalogue'}
        cases = (
            ('enabled_grpc_content_type_providers', 'GRPC_CONTENT_TYPE',
             None, 'application/grpc'),
            ('enabled_http_query_param_exact_providers',
             'HTTP_QUERY_PARAM_EXACT', 'view', 'full'),
        )
        for opt_in, rule_type, key, value in cases:
            with self.subTest(rule_type=rule_type):
                opted_in_match = {'type': rule_type, 'key': key, 'value': value}
                self.conf.config(group='api_settings', **{opt_in: ['amphora']})
                rule = self.create_l7rule(policy['id'], rule_type, 'EQUAL_TO',
                                          value, key=key)['rule']
                path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                               l7rule_id=rule['id'])
                self.set_lb_status(lb_id)
                stored = self.get(path).json['rule']

                self.conf.config(group='api_settings', **{opt_in: []})
                rpc.return_value.cast.reset_mock()
                self.put(path, {'rule': path_match}, status=501)
                self.assertEqual(stored, self.get(path).json['rule'])
                rpc.return_value.cast.assert_not_called()

                self.conf.config(group='api_settings', **{opt_in: ['amphora']})
                self.put(path, {'rule': path_match})
                rpc.return_value.cast.assert_called_once()
                self.set_lb_status(lb_id)
                stored = self.get(path).json['rule']
                for field, expected in path_match.items():
                    self.assertEqual(expected, stored[field])

                self.conf.config(group='api_settings', **{opt_in: []})
                rpc.return_value.cast.reset_mock()
                self.put(path, {'rule': opted_in_match}, status=501)
                self.assertEqual(stored, self.get(path).json['rule'])
                rpc.return_value.cast.assert_not_called()

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_convert_header_to_http_method(self, rpc):
        self.conf.config(group='api_settings',
                         enabled_http_method_match_providers=['amphora'])
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        update = {'type': 'HTTP_METHOD', 'value': 'POST'}

        for key_field in ({}, {'key': None}):
            with self.subTest(key_field=key_field):
                self.set_lb_status(lb_id)
                rule = self.create_l7rule(policy['id'], 'HEADER', 'EQUAL_TO',
                                          'one', key='Version')['rule']
                path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                               l7rule_id=rule['id'])
                self.set_lb_status(lb_id)
                rpc.return_value.cast.reset_mock()
                self.put(path, {'rule': dict(update, key='Version')},
                         status=400)
                rpc.return_value.cast.assert_not_called()
                self.assertEqual('HEADER', self.get(path).json['rule']['type'])

                self.put(path, {'rule': dict(update, **key_field)})
                current = self.get(path).json['rule']
                self.assertEqual(('HTTP_METHOD', 'POST', None),
                                 (current['type'], current['value'],
                                  current['key']))
                rpc.return_value.cast.assert_called_once()
                sent = rpc.return_value.cast.call_args.kwargs
                self.assertEqual('Version',
                                 sent[constants.ORIGINAL_L7RULE]['key'])
                self.assertIsNone(sent[constants.L7RULE_UPDATES]['key'])

    @mock.patch('octavia.api.drivers.amphora_driver.v2.driver.rpc.get_client')
    def test_http_method_rule_updates_and_parent_reactivation(self, rpc):
        lb = self.create_load_balancer(
            uuidutils.generate_uuid(), provider='amphora')['loadbalancer']
        lb_id = lb['id']
        self.set_lb_status(lb_id)
        listener = self.create_listener('HTTP', 80, lb_id)['listener']
        self.set_lb_status(lb_id)
        policy = self.create_l7policy(listener['id'], 'REJECT')['l7policy']
        self.set_lb_status(lb_id)

        rpc.return_value.cast.reset_mock()
        self.create_l7rule(policy['id'], 'HTTP_METHOD', 'EQUAL_TO', 'GET',
                           status=501)
        self.conf.config(group='api_settings',
                         enabled_http_method_match_providers=['amphora'])
        self.create_l7rule(policy['id'], 'HTTP_METHOD', 'REGEX', 'GET',
                           status=400)
        for invalid_value in ('get', 'GET POST', 'PROPFIND'):
            self.create_l7rule(policy['id'], 'HTTP_METHOD', 'EQUAL_TO',
                               invalid_value, status=400)
        self.create_l7rule(policy['id'], 'HTTP_METHOD', 'EQUAL_TO', 'GET',
                           key='Method', status=400)
        self.create_l7rule(policy['id'], 'HTTP_METHOD', 'EQUAL_TO', 'GET',
                           invert=True, status=400)
        rpc.return_value.cast.assert_not_called()
        rules_path = self.L7RULES_PATH.format(l7policy_id=policy['id'])
        self.assertEqual([], self.get(rules_path).json['rules'])

        rule = self.create_l7rule(policy['id'], 'HTTP_METHOD', 'EQUAL_TO',
                                  'GET')['rule']
        self.assertIsNone(rule['key'])
        self.assertFalse(rule['invert'])
        path = self.L7RULE_PATH.format(l7policy_id=policy['id'],
                                       l7rule_id=rule['id'])
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'value': 'POST'}})
        self.set_lb_status(lb_id)
        self.assertEqual('POST', self.get(path).json['rule']['value'])
        self.conf.config(group='api_settings',
                         enabled_http_method_match_providers=[])
        self.put(path, {'rule': {'value': 'PATCH'}}, status=501)

        parents = (
            (self.L7POLICY_PATH.format(l7policy_id=policy['id']), 'l7policy'),
            (self.LISTENER_PATH.format(listener_id=listener['id']),
             'listener'),
            (self.LB_PATH.format(lb_id=lb_id), 'loadbalancer'),
        )
        for parent_path, tag in parents:
            with self.subTest(parent=tag):
                self.put(parent_path, {tag: {'admin_state_up': False}})
                self.set_lb_status(lb_id)
                rpc.return_value.cast.reset_mock()
                self.put(parent_path, {tag: {'admin_state_up': True}},
                         status=501)
                rpc.return_value.cast.assert_not_called()
                self.assertFalse(
                    self.get(parent_path).json[tag]['admin_state_up'])
                self.conf.config(
                    group='api_settings',
                    enabled_http_method_match_providers=['amphora'])
                self.put(parent_path, {tag: {'admin_state_up': True}})
                self.set_lb_status(lb_id)
                self.conf.config(
                    group='api_settings',
                    enabled_http_method_match_providers=[])

        self.put(path, {'rule': {'admin_state_up': False}})
        self.set_lb_status(lb_id)
        self.put(path, {'rule': {'admin_state_up': True}}, status=501)
        self.put(path, {'rule': {'type': 'PATH', 'value': '/catalog',
                                 'admin_state_up': True}})
        self.set_lb_status(lb_id)
        self.assertEqual('PATH', self.get(path).json['rule']['type'])

    def test_create_cookie_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_COOKIE,
            constants.L7RULE_COMPARE_TYPE_CONTAINS, 'some-value',
            key='some-cookie').get(self.root_tag)
        self.assertEqual(constants.L7RULE_TYPE_COOKIE, api_l7rule.get('type'))
        self.assertEqual(constants.L7RULE_COMPARE_TYPE_CONTAINS,
                         api_l7rule.get('compare_type'))
        self.assertEqual('some-value', api_l7rule.get('value'))
        self.assertEqual('some-cookie', api_l7rule.get('key'))
        self.assertFalse(api_l7rule.get('invert'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_CREATE,
            l7rule_op_status=constants.OFFLINE)

    @mock.patch('octavia.common.constants.MAX_L7RULES_PER_L7POLICY', new=2)
    def test_create_too_many_rules(self):
        for i in range(0, constants.MAX_L7RULES_PER_L7POLICY):
            self.create_l7rule(
                self.l7policy_id, constants.L7RULE_TYPE_PATH,
                constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                '/api').get(self.root_tag)
            self.set_lb_status(self.lb_id)
        body = {'type': constants.L7RULE_TYPE_PATH,
                'compare_type': constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                'value': '/api'}
        self.post(self.l7rules_path, self._build_body(body), status=409)

    def test_bad_create(self):
        l7rule = {'name': 'test1'}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    def test_bad_create_host_name_rule(self):
        l7rule = {'type': constants.L7RULE_TYPE_HOST_NAME,
                  'compare_type': constants.L7RULE_COMPARE_TYPE_STARTS_WITH}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    def test_bad_create_path_rule(self):
        l7rule = {'type': constants.L7RULE_TYPE_PATH,
                  'compare_type': constants.L7RULE_COMPARE_TYPE_REGEX,
                  'value': 'bad string\\'}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    def test_bad_create_file_type_rule(self):
        l7rule = {'type': constants.L7RULE_TYPE_FILE_TYPE,
                  'compare_type': constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                  'value': 'png'}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    def test_bad_create_header_rule(self):
        l7rule = {'type': constants.L7RULE_TYPE_HEADER,
                  'compare_type': constants.L7RULE_COMPARE_TYPE_CONTAINS,
                  'value': 'some-string'}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    def test_bad_create_cookie_rule(self):
        l7rule = {'type': constants.L7RULE_TYPE_COOKIE,
                  'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                  'key': 'bad cookie name',
                  'value': 'some-string'}
        self.post(self.l7rules_path, self._build_body(l7rule), status=400)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_create_with_bad_provider(self, mock_provider):
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        l7rule = {'compare_type': 'REGEX',
                  'invert': False,
                  'type': 'PATH',
                  'value': '/images*',
                  'admin_state_up': True}
        response = self.post(self.l7rules_path, self._build_body(l7rule),
                             status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_create_with_ssl_rule_types(self):
        test_mapping = {
            constants.L7RULE_TYPE_SSL_CONN_HAS_CERT: {
                'value': 'tRuE',
                'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO},
            constants.L7RULE_TYPE_SSL_VERIFY_RESULT: {
                'value': '0',
                'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO},
            constants.L7RULE_TYPE_SSL_DN_FIELD: {
                'key': 'st-1', 'value': 'ST-FIELD1-PREFIX',
                'compare_type': constants.L7RULE_COMPARE_TYPE_STARTS_WITH}
        }
        for l7rule_type, test_body in test_mapping.items():
            self.set_lb_status(self.lb_id)
            test_body.update({'type': l7rule_type})
            api_l7rule = self.create_l7rule(
                self.l7policy_id, l7rule_type,
                test_body['compare_type'], test_body['value'],
                key=test_body.get('key')).get(self.root_tag)
            self.assertEqual(l7rule_type, api_l7rule.get('type'))
            self.assertEqual(test_body['compare_type'],
                             api_l7rule.get('compare_type'))
            self.assertEqual(test_body['value'], api_l7rule.get('value'))
            if test_body.get('key'):
                self.assertEqual(test_body['key'], api_l7rule.get('key'))
            self.assertFalse(api_l7rule.get('invert'))
            self.assert_correct_status(
                lb_id=self.lb_id, listener_id=self.listener_id,
                l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
                lb_prov_status=constants.PENDING_UPDATE,
                listener_prov_status=constants.PENDING_UPDATE,
                l7policy_prov_status=constants.PENDING_UPDATE,
                l7rule_prov_status=constants.PENDING_CREATE,
                l7rule_op_status=constants.OFFLINE)

    def _test_bad_cases_with_ssl_rule_types(self, is_create=True,
                                            rule_id=None):
        if is_create:
            req_func = self.post
            first_req_arg = self.l7rules_path
        else:
            req_func = self.put
            first_req_arg = self.l7rule_path.format(l7rule_id=rule_id)

        # test bad cases of L7RULE_TYPE_SSL_CONN_HAS_CERT
        l7rule = {'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                  'invert': False,
                  'type': constants.L7RULE_TYPE_SSL_CONN_HAS_CERT,
                  'value': 'true',
                  'admin_state_up': True,
                  'key': 'no-need-key'}
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn('L7rule type {} does not use the "key" field.'.format(
            constants.L7RULE_TYPE_SSL_CONN_HAS_CERT),
            response.get('faultstring'))

        l7rule.pop('key')
        l7rule['value'] = 'not-true-string'
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule value {} is not a boolean True string.'.format(
                l7rule['value']), response.get('faultstring'))

        l7rule['value'] = 'tRUe'
        l7rule['compare_type'] = constants.L7RULE_COMPARE_TYPE_STARTS_WITH
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule type {} only supports the {} compare type.'.format(
                constants.L7RULE_TYPE_SSL_CONN_HAS_CERT,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO),
            response.get('faultstring'))

        # test bad cases of L7RULE_TYPE_SSL_VERIFY_RES
        l7rule = {'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                  'invert': False,
                  'type': constants.L7RULE_TYPE_SSL_VERIFY_RESULT,
                  'value': 'true',
                  'admin_state_up': True,
                  'key': 'no-need-key'}
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule type {} does not use the "key" field.'.format(
                l7rule['type']), response.get('faultstring'))

        l7rule.pop('key')
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule type {} needs a int value, which is >= 0'.format(
                l7rule['type']), response.get('faultstring'))

        l7rule['value'] = '0'
        l7rule['compare_type'] = constants.L7RULE_COMPARE_TYPE_STARTS_WITH
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule type {} only supports the {} compare type.'.format(
                l7rule['type'], constants.L7RULE_COMPARE_TYPE_EQUAL_TO),
            response.get('faultstring'))

        # test bad cases of L7RULE_TYPE_SSL_DN_FIELD
        l7rule = {'compare_type': constants.L7RULE_COMPARE_TYPE_REGEX,
                  'invert': False,
                  'type': constants.L7RULE_TYPE_SSL_DN_FIELD,
                  'value': 'bad regex\\',
                  'admin_state_up': True}
        # This case just test that fail to parse the regex from the value
        req_func(first_req_arg, self._build_body(l7rule), status=400).json

        l7rule['value'] = '^.test*$'
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn(
            'L7rule type {} needs to specify a key and a value.'.format(
                l7rule['type']), response.get('faultstring'))

        l7rule['key'] = 'NOT_SUPPORTED_DN_FIELD'
        response = req_func(first_req_arg, self._build_body(l7rule),
                            status=400).json
        self.assertIn('Invalid L7rule distinguished name field.',
                      response.get('faultstring'))

    def test_create_bad_cases_with_ssl_rule_types(self):
        self._test_bad_cases_with_ssl_rule_types()

    def test_create_over_quota(self):
        self.start_quota_mock(data_models.L7Rule)
        l7rule = {'compare_type': 'REGEX',
                  'invert': False,
                  'type': 'PATH',
                  'value': '/images*',
                  'admin_state_up': True}
        self.post(self.l7rules_path, self._build_body(l7rule), status=403)

    def test_update(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', tags=['old_tag']).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'value': '/images', 'tags': ['new_tag']}
        response = self.put(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id')),
            self._build_body(new_l7rule)).json.get(self.root_tag)
        self.assertEqual('/images', response.get('value'))
        self.assertEqual(['new_tag'], response['tags'])
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_UPDATE)

    def test_update_authorized(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'value': '/images'}

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
            response = self.put(self.l7rule_path.format(
                l7rule_id=api_l7rule.get('id')),
                self._build_body(new_l7rule)).json.get(self.root_tag)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual('/images', response.get('value'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_UPDATE)

    def test_update_not_authorized(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'value': '/images'}

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            response = self.put(self.l7rule_path.format(
                l7rule_id=api_l7rule.get('id')),
                self._build_body(new_l7rule), status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(self.NOT_AUTHORIZED_BODY, response.json)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE,
            l7rule_prov_status=constants.ACTIVE)

    def test_update_with_wrong_l7policy(self):
        """Regression test for bug 2171382.

        PUT must verify that the rule named in the URL actually belongs to
        the l7policy named in the URL. Without that check, a tenant can
        name their own (properly authorized) l7policy in the URL together
        with another tenant's rule UUID, and the request is wrongly
        accepted instead of rejected with 404.
        """
        # Victim: the rule lives under self.l7policy_id / self.lb_id,
        # which belong to self.project_id.
        victim_rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/admin').get(self.root_tag)
        victim_rule_id = victim_rule.get('id')
        self.set_lb_status(self.lb_id)

        # Attacker: a different project with its own, fully separate
        # load balancer / listener / l7policy.
        attacker_project_id = uuidutils.generate_uuid()
        attacker_lb = self.create_load_balancer(
            uuidutils.generate_uuid(),
            project_id=attacker_project_id).get('loadbalancer')
        attacker_lb_id = attacker_lb.get('id')
        self.set_lb_status(attacker_lb_id)
        attacker_listener = self.create_listener(
            constants.PROTOCOL_HTTP, 80, lb_id=attacker_lb_id).get(
            'listener')
        attacker_listener_id = attacker_listener.get('id')
        self.set_lb_status(attacker_lb_id)
        attacker_l7policy = self.create_l7policy(
            attacker_listener_id, constants.L7POLICY_ACTION_REJECT).get(
            'l7policy')
        attacker_l7policy_id = attacker_l7policy.get('id')
        self.set_lb_status(attacker_lb_id)

        # The attacker sends PUT to their OWN l7policy's URL, but with the
        # VICTIM's rule_id. The attacker is a legitimate, fully-authorized
        # member of their own project/policy -- that is the whole point of
        # the bug: authorization succeeds against the URL's (attacker's)
        # policy, and the missing check is whether the loaded rule actually
        # belongs to that policy.
        attack_path = self.L7RULE_PATH.format(
            l7policy_id=attacker_l7policy_id, l7rule_id=victim_rule_id)
        new_l7rule = {'value': '/'}

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
            'project_id': attacker_project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            self.put(attack_path, self._build_body(new_l7rule), status=404)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        # The victim's rule must be completely unaffected.
        unaffected_rule = self.get(self.l7rule_path.format(
            l7rule_id=victim_rule_id)).json.get(self.root_tag)
        self.assertEqual('/admin', unaffected_rule.get('value'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=victim_rule_id,
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE,
            l7rule_prov_status=constants.ACTIVE)

        # The attacker's own (never legitimately touched) resources must
        # also remain ACTIVE, not locked into PENDING_UPDATE.
        self.assert_correct_status(
            lb_id=attacker_lb_id, listener_id=attacker_listener_id,
            l7policy_id=attacker_l7policy_id,
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE)

    def test_bad_update(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        new_l7rule = {'type': 'bad type'}
        self.put(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                 self._build_body(new_l7rule), status=400)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_update_with_bad_provider(self, mock_provider):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'value': '/images'}
        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        response = self.put(
            self.l7rule_path.format(l7rule_id=api_l7rule.get('id')),
            self._build_body(new_l7rule), status=500)
        self.assertIn('Provider \'bad_driver\' reports error: broken',
                      response.json.get('faultstring'))

    def test_update_with_invalid_rule(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'compare_type': constants.L7RULE_COMPARE_TYPE_REGEX,
                      'value': 'bad string\\'}
        self.put(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id')), self._build_body(new_l7rule),
            status=400)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            l7rule_prov_status=constants.ACTIVE)

    def test_update_with_ssl_rule_types(self):
        test_mapping = {
            constants.L7RULE_TYPE_SSL_CONN_HAS_CERT: {
                'value': 'tRuE',
                'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO},
            constants.L7RULE_TYPE_SSL_VERIFY_RESULT: {
                'value': '0',
                'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO},
            constants.L7RULE_TYPE_SSL_DN_FIELD: {
                'key': 'st-1', 'value': 'ST-FIELD1-PREFIX',
                'compare_type': constants.L7RULE_COMPARE_TYPE_STARTS_WITH}
        }

        for l7rule_type, test_body in test_mapping.items():
            self.set_lb_status(self.lb_id)
            api_l7rule = self.create_l7rule(
                self.l7policy_id, constants.L7RULE_TYPE_PATH,
                constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                '/api').get(self.root_tag)
            self.set_lb_status(self.lb_id)
            test_body.update({'type': l7rule_type})
            response = self.put(self.l7rule_path.format(
                l7rule_id=api_l7rule.get('id')),
                self._build_body(test_body)).json.get(self.root_tag)
            self.assertEqual(l7rule_type, response.get('type'))
            self.assertEqual(test_body['compare_type'],
                             response.get('compare_type'))
            self.assertEqual(test_body['value'], response.get('value'))
            if test_body.get('key'):
                self.assertEqual(test_body['key'], response.get('key'))
            self.assertFalse(response.get('invert'))
            self.assert_correct_status(
                lb_id=self.lb_id, listener_id=self.listener_id,
                l7policy_id=self.l7policy_id, l7rule_id=response.get('id'),
                lb_prov_status=constants.PENDING_UPDATE,
                listener_prov_status=constants.PENDING_UPDATE,
                l7policy_prov_status=constants.PENDING_UPDATE,
                l7rule_prov_status=constants.PENDING_UPDATE)

    def test_update_bad_cases_with_ssl_rule_types(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self._test_bad_cases_with_ssl_rule_types(
            is_create=False, rule_id=api_l7rule.get('id'))

    def test_update_invert_none(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', tags=['old_tag'], invert=True).get(self.root_tag)
        self.set_lb_status(self.lb_id)
        new_l7rule = {'invert': None}
        response = self.put(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id')),
            self._build_body(new_l7rule)).json.get(self.root_tag)
        self.assertFalse(response.get('invert'))

    def test_delete(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7rule['provisioning_status'] = constants.ACTIVE
        api_l7rule['operating_status'] = constants.ONLINE
        api_l7rule.pop('updated_at')

        response = self.get(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7rule, response)

        self.delete(self.l7rule_path.format(l7rule_id=api_l7rule.get('id')))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_DELETE)
        self.set_lb_status(self.lb_id)

    def test_delete_authorized(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7rule['provisioning_status'] = constants.ACTIVE
        api_l7rule['operating_status'] = constants.ONLINE
        api_l7rule.pop('updated_at')

        response = self.get(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7rule, response)

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

            self.delete(
                self.l7rule_path.format(l7rule_id=api_l7rule.get('id')))
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.PENDING_UPDATE,
            listener_prov_status=constants.PENDING_UPDATE,
            l7policy_prov_status=constants.PENDING_UPDATE,
            l7rule_prov_status=constants.PENDING_DELETE)
        self.set_lb_status(self.lb_id)

    def test_delete_not_authorized(self):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7rule['provisioning_status'] = constants.ACTIVE
        api_l7rule['operating_status'] = constants.ONLINE
        api_l7rule.pop('updated_at')

        response = self.get(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id'))).json.get(self.root_tag)
        response.pop('updated_at')
        self.assertEqual(api_l7rule, response)

        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        test_context = octavia.common.context.RequestContext(
            project_id=self.project_id)
        with mock.patch('oslo_context.context.RequestContext.from_environ',
                        return_value=test_context):
            self.delete(
                self.l7rule_path.format(l7rule_id=api_l7rule.get('id')),
                status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=api_l7rule.get('id'),
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE,
            l7rule_prov_status=constants.ACTIVE)

    def test_delete_with_wrong_l7policy(self):
        """Regression test for bug 2171382.

        DELETE must verify that the rule named in the URL actually belongs
        to the l7policy named in the URL. Without that check, a tenant can
        name their own (properly authorized) l7policy in the URL together
        with another tenant's rule UUID, and the rule is wrongly deleted
        instead of the request being rejected with 404.
        """
        # Victim: the rule lives under self.l7policy_id / self.lb_id,
        # which belong to self.project_id.
        victim_rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/admin').get(self.root_tag)
        victim_rule_id = victim_rule.get('id')
        self.set_lb_status(self.lb_id)

        # Attacker: a different project with its own, fully separate
        # load balancer / listener / l7policy.
        attacker_project_id = uuidutils.generate_uuid()
        attacker_lb = self.create_load_balancer(
            uuidutils.generate_uuid(),
            project_id=attacker_project_id).get('loadbalancer')
        attacker_lb_id = attacker_lb.get('id')
        self.set_lb_status(attacker_lb_id)
        attacker_listener = self.create_listener(
            constants.PROTOCOL_HTTP, 80, lb_id=attacker_lb_id).get(
            'listener')
        attacker_listener_id = attacker_listener.get('id')
        self.set_lb_status(attacker_lb_id)
        attacker_l7policy = self.create_l7policy(
            attacker_listener_id, constants.L7POLICY_ACTION_REJECT).get(
            'l7policy')
        attacker_l7policy_id = attacker_l7policy.get('id')
        self.set_lb_status(attacker_lb_id)

        # The attacker sends DELETE to their OWN l7policy's URL, but with
        # the VICTIM's rule_id. The attacker is a legitimate, fully-
        # authorized member of their own project/policy -- that is the
        # whole point of the bug: authorization succeeds against the URL's
        # (attacker's) policy, and the missing check is whether the loaded
        # rule actually belongs to that policy.
        attack_path = self.L7RULE_PATH.format(
            l7policy_id=attacker_l7policy_id, l7rule_id=victim_rule_id)

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
            'project_id': attacker_project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            self.delete(attack_path, status=404)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

        # The victim's rule must still exist, completely unaffected.
        unaffected_rule = self.get(self.l7rule_path.format(
            l7rule_id=victim_rule_id)).json.get(self.root_tag)
        self.assertEqual('/admin', unaffected_rule.get('value'))
        self.assert_correct_status(
            lb_id=self.lb_id, listener_id=self.listener_id,
            l7policy_id=self.l7policy_id, l7rule_id=victim_rule_id,
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE,
            l7rule_prov_status=constants.ACTIVE)

        # The attacker's own (never legitimately touched) resources must
        # also remain ACTIVE, not locked into PENDING_UPDATE.
        self.assert_correct_status(
            lb_id=attacker_lb_id, listener_id=attacker_listener_id,
            l7policy_id=attacker_l7policy_id,
            lb_prov_status=constants.ACTIVE,
            listener_prov_status=constants.ACTIVE,
            l7policy_prov_status=constants.ACTIVE)

    def test_bad_delete(self):
        self.delete(self.l7rule_path.format(
            l7rule_id=uuidutils.generate_uuid()), status=404)

    @mock.patch('octavia.api.drivers.utils.call_provider')
    def test_delete_with_bad_provider(self, mock_provider):
        api_l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        # Set status to ACTIVE/ONLINE because set_lb_status did it in the db
        api_l7rule['provisioning_status'] = constants.ACTIVE
        api_l7rule['operating_status'] = constants.ONLINE
        response = self.get(self.l7rule_path.format(
            l7rule_id=api_l7rule.get('id'))).json.get(self.root_tag)

        self.assertIsNone(api_l7rule.pop('updated_at'))
        self.assertIsNotNone(response.pop('updated_at'))
        self.assertEqual(api_l7rule, response)

        mock_provider.side_effect = exceptions.ProviderDriverError(
            prov='bad_driver', user_msg='broken')
        self.delete(self.l7rule_path.format(l7rule_id=api_l7rule.get('id')),
                    status=500)

    def test_create_when_lb_pending_update(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        new_l7rule = {'type': constants.L7RULE_TYPE_PATH,
                      'compare_type': constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                      'value': '/api'}
        self.post(self.l7rules_path, body=self._build_body(new_l7rule),
                  status=409)

    def test_update_when_lb_pending_update(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        new_l7rule = {'type': constants.L7RULE_TYPE_HOST_NAME,
                      'compare_type': constants.L7RULE_COMPARE_TYPE_REGEX,
                      'value': '.*.example.com'}
        self.put(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                 body=self._build_body(new_l7rule), status=409)

    def test_delete_when_lb_pending_update(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.put(self.LB_PATH.format(lb_id=self.lb_id),
                 body={'loadbalancer': {'name': 'test_name_change'}})
        self.delete(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                    status=409)

    def test_create_when_lb_pending_delete(self):
        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_l7rule = {'type': constants.L7RULE_TYPE_HEADER,
                      'compare_type':
                          constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                      'value': 'some-string',
                      'key': 'Some-header'}
        self.post(self.l7rules_path, body=self._build_body(new_l7rule),
                  status=409)

    def test_update_when_lb_pending_delete(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        new_l7rule = {'type': constants.L7RULE_TYPE_COOKIE,
                      'compare_type':
                          constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                      'value': 'some-string',
                      'key': 'some-cookie'}
        self.put(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                 body=self._build_body(new_l7rule), status=409)

    def test_delete_when_lb_pending_delete(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        self.set_lb_status(self.lb_id)
        self.delete(self.LB_PATH.format(lb_id=self.lb_id),
                    params={'cascade': "true"})
        self.delete(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                    status=409)

    def test_update_already_deleted(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        new_l7rule = {'type': constants.L7RULE_TYPE_COOKIE,
                      'compare_type':
                          constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                      'value': 'some-string',
                      'key': 'some-cookie'}
        self.put(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                 body=self._build_body(new_l7rule), status=404)

    def test_delete_already_deleted(self):
        l7rule = self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api').get(self.root_tag)
        # This updates the child objects
        self.set_lb_status(self.lb_id, status=constants.DELETED)
        self.delete(self.l7rule_path.format(l7rule_id=l7rule.get('id')),
                    status=404)

    @mock.patch("octavia.api.drivers.noop_driver.driver.NoopManager."
                "l7rule_create")
    def test_create_with_exception_in_provider_driver(self,
                                                      l7rule_create_mock):
        l7rule_create_mock.side_effect = Exception("Provider error")

        self.create_l7rule(
            self.l7policy_id, constants.L7RULE_TYPE_PATH,
            constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
            '/api', status=500)

        lb = self.get(self.LB_PATH.format(lb_id=self.lb_id)).json.get(
            "loadbalancer")
        self.assertEqual(lb[constants.PROVISIONING_STATUS],
                         constants.ACTIVE)
