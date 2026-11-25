#    Copyright 2018 Rackspace, US Inc.
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
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.api.drivers.amphora_driver.v2 import driver as amphora_driver
from octavia.api.drivers import utils as driver_utils
from octavia.common import constants
from octavia.tests.functional.api.v2 import base


class TestProvider(base.BaseAPITest):

    root_tag_list = 'providers'

    def setUp(self):
        super().setUp()

    def test_get_all_providers(self):
        octavia_dict = {'description': 'Octavia driver.',
                        'name': 'octavia'}
        amphora_dict = {'description': 'Amp driver.', 'name': 'amphora'}
        noop_dict = {'description': 'NoOp driver.', 'name': 'noop_driver'}
        providers = self.get(self.PROVIDERS_PATH).json.get(self.root_tag_list)
        self.assertEqual(4, len(providers))
        self.assertIn(octavia_dict, providers)
        self.assertIn(amphora_dict, providers)
        self.assertIn(noop_dict, providers)

    def test_get_all_providers_fields(self):
        octavia_dict = {'name': 'octavia'}
        amphora_dict = {'name': 'amphora'}
        noop_dict = {'name': 'noop_driver'}
        providers = self.get(self.PROVIDERS_PATH, params={'fields': ['name']})
        providers_list = providers.json.get(self.root_tag_list)
        self.assertEqual(4, len(providers_list))
        self.assertIn(octavia_dict, providers_list)
        self.assertIn(amphora_dict, providers_list)
        self.assertIn(noop_dict, providers_list)


class TestGatewayCapabilities(base.BaseAPITest):

    def capabilities_path(self, provider='amphora'):
        return f'{self.PROVIDERS_PATH}/{provider}/gateway_capabilities'

    def test_long_http_hostname_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_http_long_hostname_providers=['amphora', 'noop_driver'])
        self.assertEqual({'gateway_capabilities': ['http_long_hostname_v1']},
                         self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_full_header_exact_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_http_header_exact_providers=['amphora', 'noop_driver'])
        self.assertEqual({'gateway_capabilities': ['http_header_exact_v1']},
                         self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_http_method_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_http_method_match_providers=['amphora', 'noop_driver'])
        self.assertEqual({'gateway_capabilities': ['http_method_match_v1']},
                         self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_query_param_exact_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_http_query_param_exact_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['http_query_param_exact_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_grpc_content_type_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_grpc_content_type_providers=['amphora', 'noop_driver'])
        self.assertEqual({'gateway_capabilities': ['grpc_content_type_v1']},
                         self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_grpc_request_mirror_requires_matching_and_mirroring(self):
        providers = ['amphora', 'noop_driver']
        path = self.capabilities_path()
        self.conf.config(group='api_settings',
                         enabled_http_request_mirror_providers=providers)
        self.assertEqual(['http_request_mirror_v1'],
                         self.get(path).json['gateway_capabilities'])
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=providers)
        features = ['http_request_mirror_v1', 'grpc_content_type_v1']
        self.assertCountEqual(features,
                              self.get(path).json['gateway_capabilities'])
        self.conf.config(group='api_settings',
                         enabled_grpc_request_mirror_providers=providers)
        with mock.patch.object(amphora_driver.AmphoraProviderDriver,
                               'supports_grpc_request_mirror', False):
            self.assertCountEqual(features,
                                  self.get(path).json['gateway_capabilities'])
        self.assertCountEqual(features + ['grpc_request_mirror_v1'],
                              self.get(path).json['gateway_capabilities'])
        self.assertEqual([], self.get(self.capabilities_path('noop_driver'))
                         .json['gateway_capabilities'])

    def test_grpc_binary_metadata_capability_requires_both_features(self):
        providers = ['amphora', 'noop_driver']
        path = self.capabilities_path()
        self.conf.config(
            group='api_settings',
            enabled_response_header_operation_providers=providers)
        self.assertEqual(['response_header_operations_v1'],
                         self.get(path).json['gateway_capabilities'])
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=providers)
        ordinary = ['response_header_operations_v1', 'grpc_content_type_v1']
        with mock.patch.object(amphora_driver.AmphoraProviderDriver,
                               'supports_grpc_binary_response_metadata',
                               False):
            self.assertCountEqual(ordinary,
                                  self.get(path).json['gateway_capabilities'])
        self.assertCountEqual(ordinary + ['grpc_binary_response_metadata_v1'],
                              self.get(path).json['gateway_capabilities'])
        self.assertEqual([], self.get(self.capabilities_path('noop_driver'))
                         .json['gateway_capabilities'])

    def test_grpc_binary_request_metadata_capability(self):
        path = self.capabilities_path()
        name = 'grpc_binary_request_metadata_v1'
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=['amphora'])
        self.assertNotIn(name, self.get(path).json['gateway_capabilities'])
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=['amphora'])
        self.assertIn(name, self.get(path).json['gateway_capabilities'])
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=[],
            enabled_gateway_action_providers=['amphora'],
            enabled_weighted_target_request_filter_providers=['amphora'])
        self.assertIn(name, self.get(path).json['gateway_capabilities'])
        self.conf.config(group='api_settings',
                         enabled_grpc_content_type_providers=[])
        self.assertNotIn(name, self.get(path).json['gateway_capabilities'])

    def test_http_request_redirect_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_http_request_redirect_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['http_request_redirect_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_request_url_rewrite_capability_requires_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_request_url_rewrite_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['request_url_rewrite_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_request_cors_capability_requires_opt_in_driver_and_dto(self):
        empty = {'gateway_capabilities': []}
        path = self.capabilities_path()
        self.assertEqual(empty, self.get(path).json)
        self.conf.config(
            group='api_settings',
            enabled_request_cors_providers=['amphora', 'noop_driver'])
        with mock.patch.object(driver_utils, 'REQUEST_CORS_PAYLOAD_AVAILABLE',
                               False):
            self.assertEqual(empty, self.get(path).json)
        self.assertEqual({'gateway_capabilities': ['request_cors_v1']},
                         self.get(path).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_weighted_target_filters_require_weighted_provider_opt_in(self):
        field = 'gateway_capabilities'
        self.conf.config(
            group='api_settings',
            enabled_weighted_target_request_filter_providers=[
                'amphora', 'noop_driver'])
        self.assertEqual([], self.get(self.capabilities_path()).json[field])
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[
                             'amphora', 'noop_driver'])
        self.assertEqual(
            ['fixed_http_responses_v1', 'weighted_http_targets_v1',
             'weighted_http_target_request_filters_v1'],
            self.get(self.capabilities_path()).json[field])
        self.assertEqual(
            [], self.get(self.capabilities_path('noop_driver')).json[field])

    def test_initial_rules_require_compatible_opt_in(self):
        empty = {'gateway_capabilities': []}
        path = self.capabilities_path()
        self.assertEqual(empty, self.get(path).json)
        self.conf.config(
            group='api_settings',
            enabled_l7policy_initial_rules_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['l7policy_initial_rules_v1']},
            self.get(path).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)
        self.conf.config(group='api_settings',
                         enabled_l7policy_initial_rules_providers=[])
        self.assertEqual(empty, self.get(path).json)

    def test_https_listener_isolation_is_independently_enrolled(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_https_listener_isolation_providers=['amphora',
                                                        'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['https_listener_isolation_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_frontend_client_auth_fallback_capability(self):
        field = 'gateway_capabilities'
        path = self.capabilities_path()
        self.assertEqual([], self.get(path).json[field])
        self.conf.config(
            group='api_settings',
            enabled_frontend_client_auth_insecure_fallback_providers=[
                'amphora', 'noop_driver'])
        self.assertEqual(['frontend_client_auth_insecure_fallback_v1'],
                         self.get(path).json[field])
        with mock.patch('octavia.api.drivers.utils.'
                        'FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK_'
                        'PAYLOAD_AVAILABLE', False):
            self.assertEqual([], self.get(path).json[field])
        self.assertEqual([], self.get(self.capabilities_path(
            'noop_driver')).json[field])

    def test_tls_sni_capability_is_independent_and_provider_specific(self):
        self.conf.config(group='api_settings',
                         enabled_tls_sni_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['tls_sni_passthrough_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path('noop_driver')).json)
        self.conf.config(
            group='api_settings',
            enabled_tls_sni_suffix_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['tls_sni_passthrough_v1',
                                      'tls_sni_suffix_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path('noop_driver')).json)
        self.conf.config(group='api_settings', enabled_tls_sni_providers=[])
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path()).json)

    def test_requires_opt_in_for_the_requested_compatible_provider(self):
        empty = {'gateway_capabilities': []}
        self.assertEqual(empty, self.get(self.capabilities_path()).json)
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[
                             'amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['fixed_http_responses_v1',
                                      'weighted_http_targets_v1']},
            self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_request_header_operation_providers=[
                'amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['fixed_http_responses_v1',
                                      'weighted_http_targets_v1',
                                      'request_header_operations_v1']},
            self.get(self.capabilities_path()).json)
        self.conf.config(group='api_settings',
                         enabled_gateway_action_providers=[])
        self.assertEqual(
            {'gateway_capabilities': ['request_header_operations_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('octavia')).json)
        self.assertEqual(empty,
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_backend_tls_hostname_is_independently_enrolled(self):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['backend_tls_hostname_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path('noop_driver')).json)

    def test_backend_tls_system_ca_requires_regional_profile(self):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_system_ca_providers=['amphora'])
        self.conf.config(group='haproxy_amphora',
                         backend_tls_system_ca_sha256='a' * 64)
        self.assertEqual([], self.get(self.capabilities_path()).json[
            'gateway_capabilities'])
        self.conf.config(group='api_settings',
                         enabled_backend_tls_hostname_providers=['amphora'])
        self.conf.config(group='haproxy_amphora',
                         backend_tls_system_ca_path='relative/path')
        self.assertEqual(['backend_tls_hostname_v1'],
                         self.get(self.capabilities_path()).json[
                             'gateway_capabilities'])
        self.conf.config(group='haproxy_amphora',
                         backend_tls_system_ca_path='/etc/image-ca.pem')
        self.assertEqual(['backend_tls_hostname_v1',
                          'backend_tls_system_ca_v1'],
                         self.get(self.capabilities_path()).json[
                             'gateway_capabilities'])

    def test_backend_tls_h2_alpn_requires_its_own_enrollment(self):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora'],
            enabled_backend_tls_h2_alpn_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['backend_tls_hostname_v1',
                                      'backend_tls_h2_alpn_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path('noop_driver')).json)

    def test_backend_tls_sans_require_enrolled_hostname_and_provider(self):
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_subject_alt_names_providers=[
                'amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path()).json)
        self.conf.config(
            group='api_settings',
            enabled_backend_tls_hostname_providers=['amphora', 'noop_driver'])
        self.assertEqual(
            {'gateway_capabilities': ['backend_tls_hostname_v1',
                                      'backend_tls_subject_alt_names_v1']},
            self.get(self.capabilities_path()).json)
        self.assertEqual(
            {'gateway_capabilities': []},
            self.get(self.capabilities_path('noop_driver')).json)

    def test_backend_h2c_is_independently_enrolled(self):
        self.conf.config(group='api_settings',
                         enabled_backend_h2c_providers=['amphora',
                                                        'noop_driver'])
        self.assertEqual({'gateway_capabilities': ['backend_h2c_v1']},
                         self.get(self.capabilities_path()).json)
        self.assertEqual({'gateway_capabilities': []},
                         self.get(self.capabilities_path('noop_driver')).json)

    def test_unknown_provider(self):
        self.get(self.capabilities_path('bogus'), status=400)

    def test_requires_provider_read_role(self):
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        headers = {'X-Project-Id': self.project_id}
        self.get(self.capabilities_path(), headers=headers, status=403)
        headers['X-Roles'] = 'load-balancer_member,member'
        self.get(self.capabilities_path(), headers=headers)


class TestFlavorCapabilities(base.BaseAPITest):

    root_tag = 'flavor_capabilities'

    def setUp(self):
        super().setUp()

    def test_nonexistent_provider(self):
        self.get(self.FLAVOR_CAPABILITIES_PATH.format(provider='bogus'),
                 status=400)

    def test_noop_provider(self):
        ref_capabilities = [{'description': 'The glance image tag to use for '
                             'this load balancer.', 'name': 'amp_image_tag'}]

        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider='noop_driver'))
        self.assertEqual(ref_capabilities, result.json.get(self.root_tag))

    def test_amphora_driver(self):
        ref_description = ("The load balancer topology. One of: SINGLE - One "
                           "amphora per load balancer. ACTIVE_STANDBY - Two "
                           "amphora per load balancer.")
        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider='amphora'))
        capabilities = result.json.get(self.root_tag)
        capability_dict = [i for i in capabilities if
                           i['name'] == 'loadbalancer_topology'][0]
        self.assertEqual(ref_description,
                         capability_dict['description'])

    # Some drivers might not have implemented this yet, test that case
    @mock.patch('octavia.api.drivers.noop_driver.driver.NoopProviderDriver.'
                'get_supported_flavor_metadata')
    def test_not_implemented(self, mock_get_metadata):
        mock_get_metadata.side_effect = lib_exceptions.NotImplementedError()
        self.get(self.FLAVOR_CAPABILITIES_PATH.format(provider='noop_driver'),
                 status=501)

    def test_authorized(self):
        ref_capabilities = [{'description': 'The glance image tag to use '
                             'for this load balancer.',
                             'name': 'amp_image_tag'}]
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        project_id = uuidutils.generate_uuid()
        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member'],
            'user_id': None,
            'is_admin': True,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            result = self.get(self.FLAVOR_CAPABILITIES_PATH.format(
                provider='noop_driver'))
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(ref_capabilities, result.json.get(self.root_tag))

    def test_not_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        self.get(self.FLAVOR_CAPABILITIES_PATH.format(provider='noop_driver'),
                 status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

    def test_amphora_driver_one_filter(self):
        ref_description = ("The compute driver flavor ID.")
        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider=constants.AMPHORA),
            params={constants.NAME: 'compute_flavor'})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(2, len(capabilities[0]))
        self.assertEqual(ref_description,
                         capabilities[0][constants.DESCRIPTION])

    def test_amphora_driver_two_filters(self):
        ref_description = ("The compute driver flavor ID.")
        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider=constants.AMPHORA),
            params={constants.NAME: 'compute_flavor',
                    constants.DESCRIPTION: ref_description})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(ref_description,
                         capabilities[0][constants.DESCRIPTION])

    def test_amphora_driver_filter_no_match(self):
        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider=constants.AMPHORA),
            params={constants.NAME: 'bogus'})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual([], capabilities)

    def test_amphora_driver_one_filter_one_field(self):
        result = self.get(
            self.FLAVOR_CAPABILITIES_PATH.format(provider=constants.AMPHORA),
            params={constants.NAME: 'compute_flavor',
                    constants.FIELDS: constants.NAME})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(1, len(capabilities[0]))
        self.assertEqual('compute_flavor', capabilities[0][constants.NAME])


class TestAvailabilityZoneCapabilities(base.BaseAPITest):

    root_tag = 'availability_zone_capabilities'

    def setUp(self):
        super().setUp()

    def test_nonexistent_provider(self):
        self.get(self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
            provider='bogus'), status=400)

    def test_noop_provider(self):
        ref_capabilities = [
            {'description': 'The compute availability zone to '
                            'use for this loadbalancer.',
             'name': constants.COMPUTE_ZONE},
            {'description': 'The volume availability zone to '
                            'use for this loadbalancer.',
             'name': constants.VOLUME_ZONE},
        ]

        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider='noop_driver'))
        self.assertEqual(ref_capabilities, result.json.get(self.root_tag))

    def test_amphora_driver(self):
        ref_description1 = 'The compute availability zone.'
        ref_description2 = 'The management network ID for the amphora.'
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider='amphora'))
        capabilities = result.json.get(self.root_tag)
        capability_dict = [i for i in capabilities if
                           i['name'] == constants.COMPUTE_ZONE][0]
        self.assertEqual(ref_description1,
                         capability_dict['description'])
        capability_dict = [i for i in capabilities if
                           i['name'] == constants.MANAGEMENT_NETWORK][0]
        self.assertEqual(ref_description2,
                         capability_dict['description'])

    # Some drivers might not have implemented this yet, test that case
    @mock.patch('octavia.api.drivers.noop_driver.driver.NoopProviderDriver.'
                'get_supported_availability_zone_metadata')
    def test_not_implemented(self, mock_get_metadata):
        mock_get_metadata.side_effect = lib_exceptions.NotImplementedError()
        self.get(self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
            provider='noop_driver'), status=501)

    def test_authorized(self):
        ref_capabilities = [
            {'description': 'The compute availability zone to '
                            'use for this loadbalancer.',
             'name': constants.COMPUTE_ZONE},
            {'description': 'The volume availability zone to '
                            'use for this loadbalancer.',
             'name': constants.VOLUME_ZONE},
        ]
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        project_id = uuidutils.generate_uuid()
        override_credentials = {
            'service_user_id': None,
            'user_domain_id': None,
            'is_admin_project': True,
            'service_project_domain_id': None,
            'service_project_id': None,
            'roles': ['load-balancer_member'],
            'user_id': None,
            'is_admin': True,
            'service_user_domain_id': None,
            'project_domain_id': None,
            'service_roles': [],
            'project_id': project_id}
        with mock.patch(
                "oslo_context.context.RequestContext.to_policy_values",
                return_value=override_credentials):
            result = self.get(
                self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                    provider='noop_driver'))
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)
        self.assertEqual(ref_capabilities, result.json.get(self.root_tag))

    def test_not_authorized(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        auth_strategy = self.conf.conf.api_settings.get('auth_strategy')
        self.conf.config(group='api_settings', auth_strategy=constants.TESTING)
        self.get(self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
            provider='noop_driver'), status=403)
        self.conf.config(group='api_settings', auth_strategy=auth_strategy)

    def test_amphora_driver_one_filter(self):
        ref_description = 'The compute availability zone.'
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider=constants.AMPHORA),
            params={constants.NAME: constants.COMPUTE_ZONE})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(2, len(capabilities[0]))
        self.assertEqual(ref_description,
                         capabilities[0][constants.DESCRIPTION])

        ref_description = 'The management network ID for the amphora.'
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider=constants.AMPHORA),
            params={constants.NAME: constants.MANAGEMENT_NETWORK})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(2, len(capabilities[0]))
        self.assertEqual(ref_description,
                         capabilities[0][constants.DESCRIPTION])

    def test_amphora_driver_two_filters(self):
        ref_description = 'The compute availability zone.'
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider=constants.AMPHORA),
            params={constants.NAME: constants.COMPUTE_ZONE,
                    constants.DESCRIPTION: ref_description})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(ref_description,
                         capabilities[0][constants.DESCRIPTION])

    def test_amphora_driver_filter_no_match(self):
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider=constants.AMPHORA),
            params={constants.NAME: 'bogus'})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual([], capabilities)

    def test_amphora_driver_one_filter_one_field(self):
        result = self.get(
            self.AVAILABILITY_ZONE_CAPABILITIES_PATH.format(
                provider=constants.AMPHORA),
            params={constants.NAME: constants.COMPUTE_ZONE,
                    constants.FIELDS: constants.NAME})
        capabilities = result.json.get(self.root_tag)
        self.assertEqual(1, len(capabilities))
        self.assertEqual(1, len(capabilities[0]))
        self.assertEqual(constants.COMPUTE_ZONE,
                         capabilities[0][constants.NAME])
