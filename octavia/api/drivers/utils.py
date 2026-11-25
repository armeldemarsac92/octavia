# Copyright 2018 Rackspace, US Inc.
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

import copy

from octavia_lib.api.drivers import data_models as driver_dm
from octavia_lib.api.drivers import exceptions as lib_exceptions
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_context import context as oslo_context
from oslo_log import log as logging
from oslo_utils import excutils
from stevedore import driver as stevedore_driver

from octavia.api.drivers import driver_factory
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common.tls_utils import cert_parser
from octavia.common import validate
from octavia.db import api as db_api
from octavia.db import repositories
from octavia.i18n import _

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
HTTP_REQUEST_REDIRECT_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.L7Policy(), 'redirect_request')
REQUEST_URL_REWRITE_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.L7Policy(), 'request_url_rewrite')
REQUEST_CORS_PAYLOAD_AVAILABLE = hasattr(driver_dm.L7Policy(), 'request_cors')
BACKEND_RETRY_BUDGET_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Pool(), 'backend_retry_budget')
HTTP_REQUEST_POLICY_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.L7Policy(), 'http_request_policy')
HTTP_REQUEST_MIRROR_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.L7Policy(), 'request_mirrors')
LISTENER_OTLP_TRACING_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Listener(), 'otlp_tracing')
LISTENER_REQUEST_FILTERS_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Listener(), 'request_filter_sections')
WEIGHTED_TARGET_PAYLOAD_AVAILABLE = hasattr(driver_dm.L7Policy(), 'targets')
BACKEND_TLS_H2_ALPN_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Pool(), 'backend_tls_require_h2')
BACKEND_TLS_SUBJECT_ALT_NAMES_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Pool(), 'backend_tls_subject_alt_names')
FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Listener(), 'client_authentication_insecure_fallback')
TCP_TLS_MIXED_MODE_PAYLOAD_AVAILABLE = (
    hasattr(driver_dm.Listener(), 'tcp_tls_mixed_mode') and
    hasattr(driver_dm.L7Policy(), 'tcp_tls_passthrough'))

HTTP_L7RULE_CAPABILITIES = {
    constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
        constants.GATEWAY_CAPABILITY_HTTP_HEADER_EXACT,
    constants.L7RULE_TYPE_HTTP_METHOD:
        constants.GATEWAY_CAPABILITY_HTTP_METHOD_MATCH,
    constants.L7RULE_TYPE_HTTP_QUERY_PARAM_EXACT:
        constants.GATEWAY_CAPABILITY_HTTP_QUERY_PARAM_EXACT,
    constants.L7RULE_TYPE_GRPC_CONTENT_TYPE:
        constants.GATEWAY_CAPABILITY_GRPC_CONTENT_TYPE,
}


def require_listener_render_lock(locks, lb_id):
    # Renderers holding this same lock acquire the LB row next. Take the
    # render lock without waiting when admission already holds the row.
    if not locks.enter_context(db_api.listener_render_lock(lb_id)):
        raise exceptions.ImmutableObject(resource='Load Balancer', id=lb_id)


def gateway_capabilities(driver):
    api_settings = CONF.api_settings
    capabilities = []
    if driver.name in api_settings.enabled_gateway_action_providers:
        if getattr(driver, 'supports_fixed_http_responses', False) is True:
            capabilities.append(
                constants.GATEWAY_CAPABILITY_FIXED_HTTP_RESPONSES)
        if getattr(driver, 'supports_weighted_targets', False) is True:
            capabilities.append(
                constants.GATEWAY_CAPABILITY_WEIGHTED_HTTP_TARGETS)
            target_filter_providers = (
                api_settings.enabled_weighted_target_request_filter_providers)
            if (WEIGHTED_TARGET_PAYLOAD_AVAILABLE and
                    driver.name in target_filter_providers and
                    getattr(driver, 'supports_weighted_target_request_filters',
                            False) is True):
                capabilities.append(
                    constants.GATEWAY_CAPABILITY_WEIGHTED_TARGET_FILTERS)
    header_providers = api_settings.enabled_request_header_operation_providers
    if (driver.name in header_providers and
            getattr(driver, 'supports_request_header_operations',
                    False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_REQUEST_HEADER_OPERATIONS)
    response_providers = (
        api_settings.enabled_response_header_operation_providers)
    if (driver.name in response_providers and
            getattr(driver, 'supports_response_header_operations',
                    False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_RESPONSE_HEADER_OPERATIONS)
    redirect_providers = api_settings.enabled_http_request_redirect_providers
    if (HTTP_REQUEST_REDIRECT_PAYLOAD_AVAILABLE and
            driver.name in redirect_providers and
            getattr(driver, 'supports_http_request_redirect', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_REQUEST_REDIRECT)
    if (REQUEST_URL_REWRITE_PAYLOAD_AVAILABLE and
            driver.name in api_settings.enabled_request_url_rewrite_providers
            and getattr(driver, 'supports_request_url_rewrite', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_REQUEST_URL_REWRITE)
    if (REQUEST_CORS_PAYLOAD_AVAILABLE and
            driver.name in api_settings.enabled_request_cors_providers and
            getattr(driver, 'supports_request_cors', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_REQUEST_CORS)
    if (driver.name in api_settings.enabled_http_cookie_path_providers and
            getattr(driver, 'supports_http_cookie_path', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH)
    if (driver.name in api_settings.enabled_http_cookie_name_providers and
            getattr(driver, 'supports_http_cookie_name', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_COOKIE_NAME)
        absolute_cookie_providers = (
            api_settings.enabled_http_cookie_absolute_timeout_providers)
        if (driver.name in absolute_cookie_providers and
                getattr(driver, 'supports_http_cookie_absolute_timeout',
                        False) is True):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT)
            if (driver.name in
                    api_settings.enabled_http_cookie_permanent_providers and
                    getattr(driver, 'supports_http_cookie_permanent',
                            False) is True):
                capabilities.append(
                    constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT)
    budget_providers = api_settings.enabled_backend_retry_budget_providers
    if (BACKEND_RETRY_BUDGET_PAYLOAD_AVAILABLE and
            driver.name in budget_providers and
            getattr(driver, 'supports_backend_retry_budget', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET)
    policy_providers = api_settings.enabled_http_request_policy_providers
    if (HTTP_REQUEST_POLICY_PAYLOAD_AVAILABLE and
            driver.name in policy_providers and
            getattr(driver, 'supports_http_request_policy', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY)
        backoff_providers = api_settings.enabled_http_retry_backoff_providers
        if (driver.name in backoff_providers and
                getattr(driver, 'supports_http_retry_backoff', False) is True):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF)
    mirror_providers = api_settings.enabled_http_request_mirror_providers
    if (HTTP_REQUEST_MIRROR_PAYLOAD_AVAILABLE and
            driver.name in mirror_providers and
            getattr(driver, 'supports_http_request_mirror', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR)
    if (LISTENER_OTLP_TRACING_PAYLOAD_AVAILABLE and driver.name in
            api_settings.enabled_listener_otlp_tracing_providers and
            getattr(driver, 'supports_listener_otlp_tracing', False)
            is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING)
        if (driver.name in
                api_settings.enabled_listener_otlp_sampling_providers and
                getattr(driver, 'supports_listener_otlp_sampling', False)
                is True):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING)
    if (LISTENER_REQUEST_FILTERS_PAYLOAD_AVAILABLE and driver.name in
            api_settings.enabled_listener_request_filter_providers and
            getattr(driver, 'supports_listener_request_filters',
                    False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_LISTENER_REQUEST_FILTERS)
    initial_rules_providers = (
        api_settings.enabled_l7policy_initial_rules_providers)
    if (driver.name in initial_rules_providers and
            getattr(driver, 'supports_l7policy_initial_rules', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_L7POLICY_INITIAL_RULES)
    batch_activation_providers = (
        api_settings.enabled_l7policy_batch_activation_providers)
    if (driver.name in batch_activation_providers and
            getattr(driver, 'supports_l7policy_batch_activation', False)
            is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_L7POLICY_BATCH_ACTIVATION)
    tcp_rejection_providers = (
        api_settings.enabled_tcp_connection_rejection_providers)
    if (driver.name in tcp_rejection_providers and
            driver_factory.supports_tcp_connection_rejection(driver)):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_TCP_CONNECTION_REJECTION)
    if (driver.name in api_settings.enabled_udp_packet_drop_providers and
            driver_factory.supports_udp_packet_drop(driver)):
        capabilities.append(constants.GATEWAY_CAPABILITY_UDP_PACKET_DROP)
    if (driver.name in api_settings.enabled_http_header_exact_providers and
            getattr(driver, 'supports_http_header_exact', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_HEADER_EXACT)
    if (driver.name in api_settings.enabled_http_method_match_providers and
            getattr(driver, 'supports_http_method_match', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_METHOD_MATCH)
    query_param_providers = (
        api_settings.enabled_http_query_param_exact_providers)
    if (driver.name in query_param_providers and
            getattr(driver, 'supports_http_query_param_exact', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_QUERY_PARAM_EXACT)
    if (driver.name in api_settings.enabled_grpc_content_type_providers and
            getattr(driver, 'supports_grpc_content_type', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_GRPC_CONTENT_TYPE)
    if (driver.name in api_settings.enabled_backend_h2c_providers and
            getattr(driver, 'supports_backend_h2c', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_BACKEND_H2C)
    tls_hostname_providers = (
        api_settings.enabled_backend_tls_hostname_providers)
    if (driver.name in tls_hostname_providers and
            getattr(driver, 'supports_backend_tls_hostname', False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME)
    h2_alpn_providers = api_settings.enabled_backend_tls_h2_alpn_providers
    if (BACKEND_TLS_H2_ALPN_PAYLOAD_AVAILABLE and
            driver.name in h2_alpn_providers and
            getattr(driver, 'supports_backend_tls_h2_alpn', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN)
    san_providers = (
        api_settings.enabled_backend_tls_subject_alt_names_providers)
    if (BACKEND_TLS_SUBJECT_ALT_NAMES_PAYLOAD_AVAILABLE and
            (constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME
             in capabilities) and
            driver.name in san_providers and
            getattr(driver, 'supports_backend_tls_subject_alt_names', False)
            is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES)
    if (api_settings.allow_tls_terminated_listeners and driver.name in
            api_settings.enabled_tcp_tls_termination_providers and
            getattr(driver, 'supports_tcp_tls_termination', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_TCP_TLS_TERMINATION)
        if (WEIGHTED_TARGET_PAYLOAD_AVAILABLE and driver.name in
                api_settings.enabled_tls_sni_weighted_pool_providers and
                getattr(driver, 'supports_tls_sni_weighted_pools', False)
                is True):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_TLS_SNI_WEIGHTED_POOLS)
        tcp_auth_providers = (
            api_settings.enabled_tcp_tls_backend_auth_providers)
        if (driver.name in tcp_auth_providers and
                getattr(driver, 'supports_tcp_tls_backend_auth', False)
                is True and
                constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME in
                capabilities):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH)
    if (driver.name in api_settings.enabled_tls_sni_providers and
            getattr(driver, 'supports_tls_sni_passthrough', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_TLS_SNI)
        if (driver.name in api_settings.enabled_tls_sni_suffix_providers and
                getattr(driver, 'supports_tls_sni_suffix', False) is True):
            capabilities.append(constants.GATEWAY_CAPABILITY_TLS_SNI_SUFFIX)
        mixed_mode_providers = (
            api_settings.enabled_tcp_tls_mixed_mode_providers)
        if (TCP_TLS_MIXED_MODE_PAYLOAD_AVAILABLE and
                constants.GATEWAY_CAPABILITY_TCP_TLS_TERMINATION
                in capabilities and
                driver.name in mixed_mode_providers and
                getattr(driver, 'supports_tcp_tls_mixed_mode', False)
                is True):
            capabilities.append(
                constants.GATEWAY_CAPABILITY_TCP_TLS_MIXED_MODE)
    https_isolation_providers = (
        api_settings.enabled_https_listener_isolation_providers)
    if (driver.name in https_isolation_providers and
            getattr(driver, 'supports_https_listener_isolation', False)
            is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_HTTPS_LISTENER_ISOLATION)
    fallback_providers = (
        api_settings.enabled_frontend_client_auth_insecure_fallback_providers)
    if (FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK_PAYLOAD_AVAILABLE and
            driver.name in fallback_providers and
            getattr(driver, 'supports_frontend_client_auth_insecure_fallback',
                    False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
    return capabilities


def require_frontend_client_auth_fallback(driver):
    if (constants.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK
            not in gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Insecure fallback for frontend client certificate '
                'validation is unavailable for this provider.'))


def require_https_listener_isolation(driver):
    if (constants.GATEWAY_CAPABILITY_HTTPS_LISTENER_ISOLATION not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'HTTPS listener isolation is unavailable for this provider.'))


def require_listener_otlp_tracing(driver, *, sampling=False):
    capabilities = gateway_capabilities(driver)
    if constants.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING not in capabilities:
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Listener OTLP tracing is unavailable for this provider.'))
    if (sampling and
            constants.GATEWAY_CAPABILITY_LISTENER_OTLP_SAMPLING
            not in capabilities):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Listener OTLP sampling is unavailable for this provider.'))


def require_fixed_http_responses(driver):
    if (constants.GATEWAY_CAPABILITY_FIXED_HTTP_RESPONSES not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Local HTTP responses are unavailable for this provider.'))


def require_weighted_targets(driver):
    if (constants.GATEWAY_CAPABILITY_WEIGHTED_HTTP_TARGETS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Weighted L7 policy targets are unavailable for this '
                'provider.'))


def require_request_header_operations(driver):
    if (constants.GATEWAY_CAPABILITY_REQUEST_HEADER_OPERATIONS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'L7 policy request header operations are unavailable for '
                'this provider.'))


def require_http_request_redirect(driver):
    if (constants.GATEWAY_CAPABILITY_HTTP_REQUEST_REDIRECT not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'HTTP request redirects are unavailable for this provider.'))


def require_response_header_operations(driver):
    if (constants.GATEWAY_CAPABILITY_RESPONSE_HEADER_OPERATIONS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'L7 policy response header operations are unavailable for '
                'this provider.'))


def request_url_rewrite_available(driver):
    return (constants.GATEWAY_CAPABILITY_REQUEST_URL_REWRITE in
            gateway_capabilities(driver))


def require_request_url_rewrite(driver, protocol):
    validate.validate_http_request_url_rewrite_protocol(protocol)
    if not request_url_rewrite_available(driver):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'HTTP request URL rewrites are unavailable for this '
                'provider.'))


def require_request_cors(driver, protocol):
    validate.validate_http_request_cors_protocol(protocol)
    if (constants.GATEWAY_CAPABILITY_REQUEST_CORS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'L7 policy CORS is unavailable for this provider.'))


def require_backend_retry_budget(driver, protocol):
    if protocol != constants.PROTOCOL_HTTP:
        raise exceptions.ValidationException(detail=_(
            'backend_retry_budget requires an HTTP pool.'))
    if (constants.GATEWAY_CAPABILITY_BACKEND_RETRY_BUDGET not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Backend retry budgets are unavailable for this provider.'))


def require_http_cookie_name(driver, protocol):
    if protocol != constants.PROTOCOL_HTTP:
        raise exceptions.ValidationException(detail=_(
            'A custom HTTP_COOKIE name requires an HTTP pool.'))
    if (constants.GATEWAY_CAPABILITY_HTTP_COOKIE_NAME not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Custom HTTP_COOKIE names are unavailable for this provider.'))


def require_http_cookie_path(driver):
    if (constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Custom HTTP_COOKIE paths are unavailable for this provider.'))


def require_http_cookie_absolute_timeout(driver):
    if (constants.GATEWAY_CAPABILITY_HTTP_COOKIE_ABSOLUTE_TIMEOUT not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Absolute HTTP_COOKIE timeouts are unavailable for this '
                'provider.'))


def require_http_cookie_permanent(driver):
    if (constants.GATEWAY_CAPABILITY_HTTP_COOKIE_PERMANENT not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Permanent HTTP_COOKIE persistence is unavailable for this '
                'provider.'))


def require_http_request_policy(driver, protocol):
    validate.validate_http_request_policy_protocol(protocol)
    if (constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'L7 HTTP request policies are unavailable for this provider.'))


def require_http_retry_backoff(driver, protocol):
    validate.validate_http_request_policy_protocol(protocol)
    if (constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Explicit HTTP retry backoff is unavailable for this '
                'provider.'))


def require_listener_request_filters(driver):
    if (constants.GATEWAY_CAPABILITY_LISTENER_REQUEST_FILTERS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'HTTP listener request filters are unavailable for '
                'this provider.'))


def require_http_request_mirror(driver, protocol):
    validate.validate_request_mirror_protocol(protocol)
    if (constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'HTTP request mirroring is unavailable for this provider.'))


def require_weighted_target_request_filters(driver, protocol):
    validate.validate_weighted_l7policy_protocol(protocol)
    if (constants.GATEWAY_CAPABILITY_WEIGHTED_TARGET_FILTERS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Request filters on weighted pool targets are unavailable '
                'for this provider.'))


def _withdrawn_request_transforms(driver):
    capabilities = gateway_capabilities(driver)
    if constants.GATEWAY_CAPABILITY_REQUEST_URL_REWRITE not in capabilities:
        yield 'request_url_rewrite', require_request_url_rewrite
    if (constants.GATEWAY_CAPABILITY_WEIGHTED_TARGET_FILTERS not in
            capabilities):
        yield 'target_filters', require_weighted_target_request_filters
    if constants.GATEWAY_CAPABILITY_REQUEST_CORS not in capabilities:
        yield 'request_cors', require_request_cors
    if constants.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY not in capabilities:
        yield 'http_request_policy', require_http_request_policy
    elif constants.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF not in capabilities:
        yield 'http_retry_backoff', require_http_retry_backoff
    if constants.GATEWAY_CAPABILITY_HTTP_REQUEST_MIRROR not in capabilities:
        yield 'request_mirrors', require_http_request_mirror


def require_no_exposed_request_transforms(driver, policy_repo, session,
                                          **changes):
    for transform, require in _withdrawn_request_transforms(driver):
        protocol = policy_repo.get_transform_exposed_by_policy(
            session, transform=transform, **changes)
        if protocol:
            require(driver, protocol)


def require_no_transform_exposed_by_ordered_redirect(
        driver, policy_repo, session, listener_id, hostname, position,
        *, policy_id=None):
    for transform, require in _withdrawn_request_transforms(driver):
        protocol = policy_repo.get_transform_exposed_by_ordered_redirect(
            session, listener_id, hostname, position, policy_id=policy_id,
            transform=transform)
        if protocol:
            require(driver, protocol)


def require_no_active_request_transforms(
        driver, policy_repo, session, *, policy_id=None,
        removed_https_hosts=(), **scope):
    for transform, require in _withdrawn_request_transforms(driver):
        for row in policy_repo.get_active_request_transforms(
                session, transform=transform, **scope):
            if policy_id is not None and row.id != policy_id:
                continue
            section = row.https_listener_hostname
            if removed_https_hosts and not any(
                    host != '*' and
                    (section == '*' or
                     (section.startswith('*.') and
                      host.endswith(section[1:])))
                    for host in removed_https_hosts):
                continue
            require(driver, row.protocol)


def uses_tls_sni_policy_path(driver, protocol, tcp_tls_termination=False):
    return protocol == constants.PROTOCOL_TCP and (
        tcp_tls_termination is True or
        getattr(driver, 'supports_tls_sni_passthrough', False) is True)


def require_tcp_tls_termination(driver):
    if (constants.GATEWAY_CAPABILITY_TCP_TLS_TERMINATION not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'TCP listener TLS termination is unavailable for this '
                'provider.'))


def require_tls_sni_weighted_pools(driver):
    if (constants.GATEWAY_CAPABILITY_TLS_SNI_WEIGHTED_POOLS not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Weighted TLS SNI pools are unavailable for this provider.'))


def require_tcp_tls_backend_auth(driver):
    if (constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Backend TLS authentication on terminating TCP listeners is '
                'unavailable for this provider.'))


def require_tcp_tls_mixed_mode(driver):
    if (constants.GATEWAY_CAPABILITY_TCP_TLS_MIXED_MODE not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Mixed TCP listener TLS routing is unavailable for this '
                'provider.'))


def validate_tcp_tls_policy_mode(driver, mixed_mode, passthrough):
    if passthrough is not True and passthrough is not False:
        raise exceptions.ValidationException(detail=_(
            'tcp_tls_passthrough must be true or false.'))
    if passthrough and not mixed_mode:
        raise exceptions.ValidationException(detail=_(
            'tcp_tls_passthrough requires a TCP listener with '
            'tcp_tls_mixed_mode enabled.'))
    if mixed_mode:
        require_tcp_tls_mixed_mode(driver)


def validate_tcp_pool_attachment(driver, protocol, tls_enabled, *,
                                 tcp_tls_termination=False, hostname=None,
                                 ca_ref=None, tls_sni_policy=False):
    validate.validate_tcp_tls_backend_listener(
        tcp_tls_termination, protocol, hostname)
    if tcp_tls_termination or tls_sni_policy:
        validate.validate_tcp_redirect_pool_protocol(
            protocol, tls_enabled, tcp_tls_termination=tcp_tls_termination,
            hostname=hostname, ca_ref=ca_ref)
    if protocol == constants.PROTOCOL_TCP and hostname is not None:
        require_tcp_tls_backend_auth(driver)


def validate_existing_tcp_pool_attachment(
        driver, policy_repo, session, listener, pool_id, *,
        tls_sni_policy=False, skip_disabled_pool=False, passthrough=False):
    pool = policy_repo.get_redirect_pool_for_update(session, listener, pool_id)
    if skip_disabled_pool and not pool.enabled:
        return
    validate_tcp_pool_attachment(
        driver, pool.protocol, pool.tls_enabled,
        tcp_tls_termination=listener.tcp_tls_termination and not passthrough,
        hostname=pool.backend_tls_hostname,
        ca_ref=pool.ca_tls_certificate_id, tls_sni_policy=tls_sni_policy)


def validate_tcp_policy_targets(
        driver, policy_repo, session, listener, action, redirect_pool_id,
        targets, passthrough, *, active_targets_only=False):
    if action != constants.L7POLICY_ACTION_WEIGHTED_TARGETS:
        validate_existing_tcp_pool_attachment(
            driver, policy_repo, session, listener, redirect_pool_id,
            tls_sni_policy=True, passthrough=passthrough)
        return
    pools = policy_repo.get_weighted_target_pools(
        session, listener, targets, tcp_tls_passthrough=passthrough)
    # All declared pools must be valid. When an existing weighted route
    # reopens, only enabled, positive-weight pools can carry traffic.
    checked_pools = pools.values()
    if active_targets_only:
        checked_pools = (
            pools[target['pool_id']]
            for target in validate.tls_sni_weighted_targets(targets)
            if target['weight'] > 0 and pools[target['pool_id']].enabled)
    if any(pool.backend_tls_hostname for pool in checked_pools):
        require_tcp_tls_backend_auth(driver)


def require_tls_sni_passthrough(driver):
    if (constants.GATEWAY_CAPABILITY_TLS_SNI not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'TLS SNI passthrough is unavailable for this provider.'))


def require_tls_sni_suffix(driver):
    if (constants.GATEWAY_CAPABILITY_TLS_SNI_SUFFIX not in
            gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'TLS SNI suffix routing is unavailable for this provider.'))


def require_tls_sni_rule_comparison(driver, compare_type,
                                    tcp_tls_termination=False):
    if (not tcp_tls_termination and
            compare_type == constants.L7RULE_COMPARE_TYPE_ENDS_WITH):
        require_tls_sni_suffix(driver)


def _unsupported_http_l7rule(driver, rule_type):
    if rule_type == constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
        message = _('Full-value exact HTTP header matching is unavailable '
                    'for this provider.')
    elif rule_type == constants.L7RULE_TYPE_HTTP_QUERY_PARAM_EXACT:
        message = _('Exact HTTP query parameter matching is unavailable '
                    'for this provider.')
    elif rule_type == constants.L7RULE_TYPE_GRPC_CONTENT_TYPE:
        message = _('Native gRPC Content-Type matching is unavailable '
                    'for this provider.')
    else:
        message = _('Exact HTTP method matching is unavailable for this '
                    'provider.')
    return exceptions.ProviderUnsupportedOptionError(prov=driver.name,
                                                     user_msg=message)


def require_active_http_l7rule_capabilities(driver, policy_repo, session,
                                            **parent_filters):
    capabilities = gateway_capabilities(driver)
    for rule_type, capability in HTTP_L7RULE_CAPABILITIES.items():
        if (capability not in capabilities and policy_repo.has_enabled_l7rule(
                session, rule_type, **parent_filters)):
            raise _unsupported_http_l7rule(driver, rule_type)


def require_http_l7rule_capability(driver, rule_type):
    capability = HTTP_L7RULE_CAPABILITIES.get(rule_type)
    if capability and capability not in gateway_capabilities(driver):
        raise _unsupported_http_l7rule(driver, rule_type)


def validate_l7rule_context(driver, rule_type, protocol, *,
                            admit_http_l7rule=True, tcp_tls_termination=False):
    if rule_type in HTTP_L7RULE_CAPABILITIES:
        if protocol not in (constants.PROTOCOL_HTTP,
                            constants.PROTOCOL_TERMINATED_HTTPS):
            raise exceptions.L7RuleValidation(error=_(
                '%(rule_type)s requires an HTTP or TERMINATED_HTTPS '
                'listener.') % {'rule_type': rule_type})
        if admit_http_l7rule:
            require_http_l7rule_capability(driver, rule_type)
    elif rule_type == constants.L7RULE_TYPE_TLS_SNI:
        if protocol != constants.PROTOCOL_TCP:
            raise exceptions.L7RuleValidation(error=_(
                'TLS_SNI requires a TCP listener.'))
        if not uses_tls_sni_policy_path(driver, protocol, tcp_tls_termination):
            require_tls_sni_passthrough(driver)
    elif uses_tls_sni_policy_path(driver, protocol, tcp_tls_termination):
        raise exceptions.L7RuleValidation(error=_(
            'TCP listener policies require TLS_SNI rules.'))


def require_gateway_policy_action(driver, action, protocol, *,
                                  request_header_operations=None,
                                  tcp_tls_termination=False,
                                  tcp_tls_passthrough=False,
                                  response_header_operations=None,
                                  request_url_rewrite=None, targets=None,
                                  request_cors=None,
                                  http_request_policy=None,
                                  request_mirrors=None):
    if validate.request_mirror_pool_ids(request_mirrors, targets):
        require_http_request_mirror(driver, protocol)
    if http_request_policy is not None:
        require_http_request_policy(driver, protocol)
        if 'backoff_ms' in http_request_policy.get('retry', {}):
            require_http_retry_backoff(driver, protocol)
    if request_cors is not None:
        require_request_cors(driver, protocol)
    if request_url_rewrite:
        require_request_url_rewrite(driver, protocol)
    if action == constants.L7POLICY_ACTION_FIXED_RESPONSE:
        validate.validate_fixed_http_protocol(protocol)
        require_fixed_http_responses(driver)
    elif action == constants.L7POLICY_ACTION_WEIGHTED_TARGETS:
        if protocol == constants.PROTOCOL_TCP:
            validate.validate_tls_sni_weighted_policy(
                tcp_tls_termination, tcp_tls_passthrough)
            if targets is not None:
                validate.tls_sni_weighted_targets(targets)
            require_tls_sni_weighted_pools(driver)
        else:
            validate.validate_weighted_l7policy_protocol(protocol)
            require_weighted_targets(driver)
            if any(validate.target_request_filters(target)
                   for target in targets or []):
                require_weighted_target_request_filters(driver, protocol)
    elif action == constants.L7POLICY_ACTION_REDIRECT_REQUEST:
        validate.validate_http_request_redirect_protocol(protocol)
        require_http_request_redirect(driver)
    elif uses_tls_sni_policy_path(driver, protocol, tcp_tls_termination):
        if tcp_tls_termination:
            require_tcp_tls_termination(driver)
        else:
            require_tls_sni_passthrough(driver)
        if action != constants.L7POLICY_ACTION_REDIRECT_TO_POOL:
            raise exceptions.ValidationException(detail=_(
                'TCP listener policies require the REDIRECT_TO_POOL action.'))
    require_policy_header_operations(
        driver, protocol, request_header_operations, response_header_operations)


def require_policy_header_operations(driver, protocol, request_ops,
                                     response_ops):
    if request_ops:
        require_request_header_operations(driver)
    if response_ops:
        require_response_header_operations(driver)
    if request_ops or response_ops:
        validate.validate_header_protocol(protocol)


def call_provider(provider, driver_method, *args, **kwargs):
    """Wrap calls to the provider driver to handle driver errors.

    This allows Octavia to return user friendly errors when a provider driver
    has an issue.

    :param driver_method: Method in the driver to call.
    :raises ProviderDriverError: Catch all driver error.
    :raises ProviderNotImplementedError: The driver doesn't support this
                                         action.
    :raises ProviderUnsupportedOptionError: The driver doesn't support a
                                            provided option.
    """

    try:
        return driver_method(*args, **kwargs)
    except lib_exceptions.Conflict as e:
        LOG.info("Provider '%s' raised a conflict error: %s",
                 provider, e.operator_fault_string)
        raise exceptions.VIPAddressConflict(msg=e.user_fault_string)
    except lib_exceptions.DriverError as e:
        LOG.exception("Provider '%s' raised a driver error: %s",
                      provider, e.operator_fault_string)
        raise exceptions.ProviderDriverError(prov=provider,
                                             user_msg=e.user_fault_string)
    except (lib_exceptions.NotImplementedError, NotImplementedError) as e:
        op_fault_string = (
            e.operator_fault_string
            if hasattr(e, "operator_fault_string")
            else _("This feature is not implemented by this provider."))
        usr_fault_string = (
            e.user_fault_string
            if hasattr(e, "user_fault_string")
            else _("This feature is not implemented by the provider."))
        LOG.info("Provider '%s' raised a not implemented error: %s",
                 provider, op_fault_string)
        raise exceptions.ProviderNotImplementedError(
            prov=provider, user_msg=usr_fault_string)
    except lib_exceptions.UnsupportedOptionError as e:
        LOG.info("Provider '%s' raised an unsupported option error: "
                 "%s", provider, e.operator_fault_string)
        raise exceptions.ProviderUnsupportedOptionError(
            prov=provider, user_msg=e.user_fault_string)
    except Exception as e:
        LOG.exception("Provider '%s' raised an unknown error: %s",
                      provider, str(e))
        raise exceptions.ProviderDriverError(prov=provider, user_msg=e)


def _base_to_provider_dict(current_dict, include_project_id=False):
    new_dict = copy.deepcopy(current_dict)
    if 'provisioning_status' in new_dict:
        del new_dict['provisioning_status']
    if 'operating_status' in new_dict:
        del new_dict['operating_status']
    if 'provider' in new_dict:
        del new_dict['provider']
    if 'created_at' in new_dict:
        del new_dict['created_at']
    if 'updated_at' in new_dict:
        del new_dict['updated_at']
    if 'enabled' in new_dict:
        new_dict['admin_state_up'] = new_dict.pop('enabled')
    if 'project_id' in new_dict and not include_project_id:
        del new_dict['project_id']
    if 'tenant_id' in new_dict:
        del new_dict['tenant_id']
    if 'tags' in new_dict:
        del new_dict['tags']
    if 'flavor_id' in new_dict:
        del new_dict['flavor_id']
    if 'topology' in new_dict:
        del new_dict['topology']
    if 'vrrp_group' in new_dict:
        del new_dict['vrrp_group']
    if 'amphorae' in new_dict:
        del new_dict['amphorae']
    if 'vip' in new_dict:
        del new_dict['vip']
    if 'listeners' in new_dict:
        del new_dict['listeners']
    if 'pools' in new_dict:
        del new_dict['pools']
    if 'server_group_id' in new_dict:
        del new_dict['server_group_id']
    return new_dict


# Note: The provider dict returned from this method will have provider
#       data model objects in it.
def lb_dict_to_provider_dict(lb_dict, vip=None, add_vips=None, db_pools=None,
                             db_listeners=None, for_delete=False):
    new_lb_dict = _base_to_provider_dict(lb_dict, include_project_id=True)
    for field in ('l7policy_graph_generation', 'l7policy_activation'):
        new_lb_dict.pop(field, None)
        new_lb_dict.pop('_' + field, None)
    new_lb_dict['loadbalancer_id'] = new_lb_dict.pop('id')
    if vip:
        new_lb_dict['vip_address'] = vip.ip_address
        new_lb_dict['vip_network_id'] = vip.network_id
        new_lb_dict['vip_port_id'] = vip.port_id
        new_lb_dict['vip_subnet_id'] = vip.subnet_id
        new_lb_dict['vip_qos_policy_id'] = vip.qos_policy_id
        new_lb_dict[lib_consts.VIP_SG_IDS] = vip.sg_ids
    if 'flavor_id' in lb_dict and lb_dict['flavor_id']:
        flavor_repo = repositories.FlavorRepository()
        session = db_api.get_session()
        with session.begin():
            new_lb_dict['flavor'] = flavor_repo.get_flavor_metadata_dict(
                session, lb_dict['flavor_id'])
    if add_vips:
        new_lb_dict['additional_vips'] = db_additional_vips_to_provider_vips(
            add_vips)
    if db_pools:
        new_lb_dict['pools'] = db_pools_to_provider_pools(
            db_pools, for_delete=for_delete)
    if db_listeners:
        new_lb_dict['listeners'] = db_listeners_to_provider_listeners(
            db_listeners, for_delete=for_delete)
    return new_lb_dict


def db_loadbalancer_to_provider_loadbalancer(db_loadbalancer,
                                             for_delete=False):
    new_loadbalancer_dict = lb_dict_to_provider_dict(
        db_loadbalancer.to_dict(recurse=True),
        vip=db_loadbalancer.vip,
        db_pools=db_loadbalancer.pools,
        db_listeners=db_loadbalancer.listeners, for_delete=for_delete)
    for unsupported_field in ['server_group_id', 'amphorae',
                              'vrrp_group', 'topology', 'vip']:
        if unsupported_field in new_loadbalancer_dict:
            del new_loadbalancer_dict[unsupported_field]
    provider_loadbalancer = driver_dm.LoadBalancer.from_dict(
        new_loadbalancer_dict)
    return provider_loadbalancer


def db_listeners_to_provider_listeners(db_listeners, for_delete=False):
    provider_listeners = []
    for listener in db_listeners:
        provider_listener = db_listener_to_provider_listener(
            listener, for_delete=for_delete)
        provider_listeners.append(provider_listener)
    return provider_listeners


def db_listeners_to_provider_dicts_list_of_dicts(db_listeners,
                                                 for_delete=False):
    listeners = db_listeners_to_provider_listeners(
        db_listeners, for_delete=for_delete)
    return [listener.to_dict() for listener in listeners]


def db_listener_to_provider_listener(db_listener, for_delete=False):
    new_listener_dict = listener_dict_to_provider_dict(
        db_listener.to_dict(recurse=True), for_delete=for_delete)
    for attribute in ('default_http_response', 'https_virtual_hosts',
                      'request_filter_sections', 'otlp_tracing'):
        if new_listener_dict.get(attribute) is None:
            new_listener_dict.pop(attribute, None)
    if ('default_pool' in new_listener_dict and
            new_listener_dict['default_pool']):
        provider_pool = db_pool_to_provider_pool(db_listener.default_pool,
                                                 for_delete=for_delete)
        new_listener_dict['default_pool_id'] = provider_pool.pool_id
        new_listener_dict['default_pool'] = provider_pool
    if new_listener_dict.get('l7policies', None):
        new_listener_dict['l7policies'] = (
            db_l7policies_to_provider_l7policies(db_listener.l7policies))
    provider_listener = driver_dm.Listener.from_dict(new_listener_dict)
    return provider_listener


def _get_secret_data(cert_manager, project_id, secret_ref, for_delete=False):
    """Get the secret from the certificate manager and upload it to the amp.

    :returns: The secret data.
    """
    context = oslo_context.RequestContext(project_id=project_id)
    try:
        secret_data = cert_manager.get_secret(context, secret_ref)
    except Exception as e:
        LOG.warning('Unable to retrieve certificate: %s due to %s.',
                    secret_ref, str(e))
        if for_delete:
            secret_data = None
        else:
            raise exceptions.CertificateRetrievalException(ref=secret_ref)
    # We need to have json convertible data for storing it in
    # persistence jobboard backend.
    if isinstance(secret_data, bytes):
        return secret_data.decode()
    return secret_data


def listener_dict_to_provider_dict(listener_dict, for_delete=False,
                                   clear_client_auth_fallback=False):
    new_listener_dict = _base_to_provider_dict(listener_dict,
                                               include_project_id=True)
    new_listener_dict['listener_id'] = new_listener_dict.pop('id')
    if 'load_balancer_id' in new_listener_dict:
        new_listener_dict['loadbalancer_id'] = new_listener_dict.pop(
            'load_balancer_id')

    # Preserve the existing driver payload for ordinary listeners.
    new_listener_dict.pop('frontend_fallback_owns_error', None)
    new_listener_dict.pop('otlp_tracing_status', None)
    new_listener_dict.pop('otlp_tracing_revision', None)
    if not LISTENER_OTLP_TRACING_PAYLOAD_AVAILABLE:
        new_listener_dict.pop('otlp_tracing', None)
    if not LISTENER_REQUEST_FILTERS_PAYLOAD_AVAILABLE:
        new_listener_dict.pop('request_filter_sections', None)
    if not new_listener_dict.get('tcp_tls_termination'):
        new_listener_dict.pop('tcp_tls_termination', None)
    if (not TCP_TLS_MIXED_MODE_PAYLOAD_AVAILABLE or
            not new_listener_dict.get('tcp_tls_mixed_mode')):
        new_listener_dict.pop('tcp_tls_mixed_mode', None)
    if (not FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK_PAYLOAD_AVAILABLE or
            (new_listener_dict.get('client_authentication_insecure_fallback')
             is not True and not clear_client_auth_fallback)):
        new_listener_dict.pop('client_authentication_insecure_fallback', None)

    # Pull the certs out of the certificate manager to pass to the provider
    if 'tls_certificate_id' in new_listener_dict:
        new_listener_dict['default_tls_container_ref'] = new_listener_dict.pop(
            'tls_certificate_id')
    if 'client_ca_tls_certificate_id' in new_listener_dict:
        new_listener_dict['client_ca_tls_container_ref'] = (
            new_listener_dict.pop('client_ca_tls_certificate_id'))
    if 'client_crl_container_id' in new_listener_dict:
        new_listener_dict['client_crl_container_ref'] = (
            new_listener_dict.pop('client_crl_container_id'))
    listener_obj = data_models.Listener(**listener_dict)
    if (listener_obj.tls_certificate_id or listener_obj.sni_containers or
            listener_obj.client_ca_tls_certificate_id):
        SNI_objs = []
        for sni in listener_obj.sni_containers:
            if isinstance(sni, dict):
                sni_obj = data_models.SNI(**sni)
                SNI_objs.append(sni_obj)
            elif isinstance(sni, str):
                sni_obj = data_models.SNI(tls_container_id=sni)
                SNI_objs.append(sni_obj)
            else:
                raise exceptions.ValidationException(
                    detail=_('Invalid SNI container on listener'))
        listener_obj.sni_containers = SNI_objs
        cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=CONF.certificates.cert_manager,
            invoke_on_load=True,
        ).driver
        try:
            cert_dict = cert_parser.load_certificates_data(cert_manager,
                                                           listener_obj)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning('Unable to retrieve certificate(s) due to %s.',
                            str(e))
                if for_delete:
                    ctxt.reraise = False
                    cert_dict = {}
        if 'tls_cert' in cert_dict and cert_dict['tls_cert']:
            new_listener_dict['default_tls_container_data'] = (
                cert_dict['tls_cert'].to_dict(recurse=True))
        if 'sni_certs' in cert_dict and cert_dict['sni_certs']:
            sni_data_list = []
            for sni in cert_dict['sni_certs']:
                sni_data_list.append(sni.to_dict(recurse=True))
            new_listener_dict['sni_container_data'] = sni_data_list

        if listener_obj.client_ca_tls_certificate_id:
            cert = _get_secret_data(cert_manager, listener_obj.project_id,
                                    listener_obj.client_ca_tls_certificate_id,
                                    for_delete=for_delete)
            new_listener_dict['client_ca_tls_container_data'] = cert
        if listener_obj.client_crl_container_id:
            crl_file = _get_secret_data(cert_manager, listener_obj.project_id,
                                        listener_obj.client_crl_container_id,
                                        for_delete=for_delete)
            new_listener_dict['client_crl_container_data'] = crl_file

    # Format the allowed_cidrs
    if ('allowed_cidrs' in new_listener_dict and
            new_listener_dict['allowed_cidrs'] and
            'cidr' in new_listener_dict['allowed_cidrs'][0]):
        cidrs_dict_list = new_listener_dict.pop('allowed_cidrs')
        new_listener_dict['allowed_cidrs'] = [cidr_dict['cidr'] for
                                              cidr_dict in cidrs_dict_list]

    # Format the sni_containers -> sni_container_refs
    sni_containers = new_listener_dict.pop('sni_containers', None)
    if sni_containers:
        new_listener_dict['sni_container_refs'] = []
        for sni in sni_containers:
            if isinstance(sni, dict):
                new_listener_dict['sni_container_refs'].append(
                    sni['tls_container_id'])
            elif isinstance(sni, str):
                new_listener_dict['sni_container_refs'].append(sni)
            else:
                raise exceptions.ValidationException(
                    detail=_('Invalid SNI container on listener'))

    # Remove the DB back references
    if 'load_balancer' in new_listener_dict:
        del new_listener_dict['load_balancer']
    if 'peer_port' in new_listener_dict:
        del new_listener_dict['peer_port']
    if 'pools' in new_listener_dict:
        del new_listener_dict['pools']
    if 'stats' in new_listener_dict:
        del new_listener_dict['stats']

    if ('default_pool' in new_listener_dict and
            new_listener_dict['default_pool']):
        pool = new_listener_dict.pop('default_pool')
        if pool.get('backend_tls_hostname') is None:
            pool.pop('backend_tls_hostname', None)
        new_listener_dict['default_pool'] = pool_dict_to_provider_dict(
            pool, for_delete=for_delete)
    provider_l7policies = []
    if 'l7policies' in new_listener_dict:
        l7policies = new_listener_dict.pop('l7policies') or []
        for l7policy in l7policies:
            provider_l7policy = l7policy_dict_to_provider_dict(l7policy)
            provider_l7policies.append(provider_l7policy)
        new_listener_dict['l7policies'] = provider_l7policies
    return new_listener_dict


def db_additional_vips_to_provider_vips(db_add_vips):
    provider_add_vips = []
    for add_vip in db_add_vips:
        provider_add_vips.append(
            additional_vip_dict_to_provider_dict(add_vip.to_dict()))
    return provider_add_vips


def db_pools_to_provider_pools(db_pools, for_delete=False):
    provider_pools = []
    for pool in db_pools:
        provider_pools.append(db_pool_to_provider_pool(pool,
                                                       for_delete=for_delete))
    return provider_pools


def db_pool_to_provider_pool(db_pool, for_delete=False):
    pool_dict = db_pool.to_dict(recurse=True)
    persistence = pool_dict.get('session_persistence')
    if persistence and data_models.is_unenrolled_amphora_http_cookie(
            persistence.get('type'),
            persistence.get('http_cookie_name_enabled'),
            (pool_dict.get('load_balancer') or {}).get('provider')):
        pool_dict['session_persistence'] = dict(persistence, cookie_name=None)
    if pool_dict.get('backend_tls_hostname') is None:
        pool_dict.pop('backend_tls_hostname', None)
    new_pool_dict = pool_dict_to_provider_dict(pool_dict,
                                               for_delete=for_delete)
    if not new_pool_dict.get('backend_h2c'):
        new_pool_dict.pop('backend_h2c', None)
    # Replace the sub-dicts with objects
    if 'health_monitor' in new_pool_dict:
        del new_pool_dict['health_monitor']
    if db_pool.health_monitor:
        provider_healthmonitor = db_HM_to_provider_HM(db_pool.health_monitor)
        new_pool_dict['healthmonitor'] = provider_healthmonitor
    # Don't leave a 'members' None here, we want it to pass through to Unset
    if new_pool_dict.get('members', None):
        del new_pool_dict['members']
    if db_pool.members:
        provider_members = db_members_to_provider_members(db_pool.members)
        new_pool_dict['members'] = provider_members
    db_listeners = db_pool.listeners
    if db_listeners:
        new_pool_dict['listener_id'] = db_listeners[0].id
    return driver_dm.Pool.from_dict(new_pool_dict)


def pool_dict_to_provider_dict(pool_dict, for_delete=False, for_update=False):
    new_pool_dict = _base_to_provider_dict(pool_dict, include_project_id=True)
    new_pool_dict['pool_id'] = new_pool_dict.pop('id')
    # Only the Amphora member batch extension consumes these DB fields.
    new_pool_dict.pop('tcp_connection_rejection', None)
    new_pool_dict.pop('tcp_member_batch_id', None)
    new_pool_dict.pop('udp_packet_drop', None)
    # A legacy DTO can carry the old pool for updates and deletes. The
    # persisted requirement still controls rendering and reactivation.
    supports_h2 = BACKEND_TLS_H2_ALPN_PAYLOAD_AVAILABLE
    require_h2 = new_pool_dict.get('backend_tls_require_h2')
    if ((for_delete and not supports_h2) or
            (require_h2 is False and (not for_update or not supports_h2))):
        new_pool_dict.pop('backend_tls_require_h2', None)
    # An older DTO can still carry the pool during withdrawal. Admission
    # rejects new SANs without DTO support and Amphora uses persisted SANs.
    sans = new_pool_dict.get('backend_tls_subject_alt_names')
    if (not BACKEND_TLS_SUBJECT_ALT_NAMES_PAYLOAD_AVAILABLE or
            sans is None or (sans == [] and not for_update)):
        new_pool_dict.pop('backend_tls_subject_alt_names', None)

    if (not BACKEND_RETRY_BUDGET_PAYLOAD_AVAILABLE or
            (new_pool_dict.get('backend_retry_budget') is None and
             not for_update)):
        new_pool_dict.pop('backend_retry_budget', None)

    # Pull the certs out of the certificate manager to pass to the provider
    if 'tls_certificate_id' in new_pool_dict:
        new_pool_dict['tls_container_ref'] = new_pool_dict.pop(
            'tls_certificate_id')
    if 'ca_tls_certificate_id' in new_pool_dict:
        new_pool_dict['ca_tls_container_ref'] = new_pool_dict.pop(
            'ca_tls_certificate_id')
    if 'crl_container_id' in new_pool_dict:
        new_pool_dict['crl_container_ref'] = new_pool_dict.pop(
            'crl_container_id')

    pool_obj = data_models.Pool(**pool_dict)
    if pool_obj.backend_tls_hostname and pool_obj.enabled is False:
        # A disabled protected pool can drain even if a secret was removed.
        for_delete = True
    if (pool_obj.tls_certificate_id or pool_obj.ca_tls_certificate_id or
            pool_obj.crl_container_id):
        cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=CONF.certificates.cert_manager,
            invoke_on_load=True,
        ).driver
        try:
            cert_dict = cert_parser.load_certificates_data(cert_manager,
                                                           pool_obj)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                LOG.warning('Unable to retrieve certificate(s) due to %s.',
                            str(e))
                if for_delete:
                    ctxt.reraise = False
                    cert_dict = {}
        if 'tls_cert' in cert_dict and cert_dict['tls_cert']:
            new_pool_dict['tls_container_data'] = (
                cert_dict['tls_cert'].to_dict(recurse=True))

        if pool_obj.ca_tls_certificate_id:
            cert = _get_secret_data(cert_manager, pool_obj.project_id,
                                    pool_obj.ca_tls_certificate_id,
                                    for_delete=for_delete)
            new_pool_dict['ca_tls_container_data'] = cert

        if pool_obj.crl_container_id:
            crl_file = _get_secret_data(cert_manager, pool_obj.project_id,
                                        pool_obj.crl_container_id,
                                        for_delete=for_delete)
            new_pool_dict['crl_container_data'] = crl_file

    # Remove the DB back references
    if ('session_persistence' in new_pool_dict and
            new_pool_dict['session_persistence']):
        if 'pool_id' in new_pool_dict['session_persistence']:
            del new_pool_dict['session_persistence']['pool_id']
        if 'pool' in new_pool_dict['session_persistence']:
            del new_pool_dict['session_persistence']['pool']
        new_pool_dict['session_persistence'].pop(
            'http_cookie_name_enabled', None)
        new_pool_dict['session_persistence'].pop(
            'cookie_absolute_timeout_error', None)
        # Explicit nulls in an update can clear the path, timeout and scope.
        if not for_update:
            persistence = new_pool_dict['session_persistence']
            if persistence.get('cookie_path') in (
                    None, constants.HTTP_COOKIE_DEFAULT_PATH):
                persistence.pop('cookie_path', None)
            if persistence.get('cookie_permanent') is not True:
                persistence.pop('cookie_permanent', None)
            if persistence.get('cookie_absolute_timeout_ms') is None:
                persistence.pop('cookie_absolute_timeout_ms', None)
                persistence.pop('cookie_scope', None)
    if 'l7policies' in new_pool_dict:
        del new_pool_dict['l7policies']
    if 'listeners' in new_pool_dict:
        del new_pool_dict['listeners']
    if 'load_balancer' in new_pool_dict:
        del new_pool_dict['load_balancer']
    if 'load_balancer_id' in new_pool_dict:
        new_pool_dict['loadbalancer_id'] = new_pool_dict.pop(
            'load_balancer_id')
    if 'health_monitor' in new_pool_dict:
        hm = new_pool_dict.pop('health_monitor')
        if hm:
            new_pool_dict['healthmonitor'] = hm_dict_to_provider_dict(hm)
        else:
            new_pool_dict['healthmonitor'] = None
    if 'members' in new_pool_dict and new_pool_dict['members']:
        members = new_pool_dict.pop('members')
        provider_members = []
        for member in members:
            provider_member = member_dict_to_provider_dict(member)
            provider_members.append(provider_member)
        new_pool_dict['members'] = provider_members
    return new_pool_dict


def db_members_to_provider_members(db_members):
    provider_members = []
    for member in db_members:
        provider_members.append(db_member_to_provider_member(member))
    return provider_members


def db_member_to_provider_member(db_member):
    new_member_dict = member_dict_to_provider_dict(db_member.to_dict())
    if constants.REQUEST_SRIOV in new_member_dict:
        request_sriov = new_member_dict.pop(constants.REQUEST_SRIOV)
        if request_sriov:
            new_member_dict[constants.VNIC_TYPE] = constants.VNIC_TYPE_DIRECT
        else:
            new_member_dict[constants.VNIC_TYPE] = constants.VNIC_TYPE_NORMAL
    return driver_dm.Member.from_dict(new_member_dict)


def member_dict_to_provider_dict(member_dict):
    new_member_dict = _base_to_provider_dict(member_dict,
                                             include_project_id=True)
    new_member_dict['member_id'] = new_member_dict.pop('id')
    new_member_dict.pop('tcp_batch_quota_released', None)
    if 'ip_address' in new_member_dict:
        new_member_dict['address'] = new_member_dict.pop('ip_address')
    # Remove the DB back references
    if 'pool' in new_member_dict:
        del new_member_dict['pool']
    return new_member_dict


def db_HM_to_provider_HM(db_hm):
    new_HM_dict = hm_dict_to_provider_dict(db_hm.to_dict())
    return driver_dm.HealthMonitor.from_dict(new_HM_dict)


def hm_dict_to_provider_dict(hm_dict):
    new_hm_dict = _base_to_provider_dict(hm_dict, include_project_id=True)
    new_hm_dict['healthmonitor_id'] = new_hm_dict.pop('id')
    if 'fall_threshold' in new_hm_dict:
        new_hm_dict['max_retries_down'] = new_hm_dict.pop('fall_threshold')
    if 'rise_threshold' in new_hm_dict:
        new_hm_dict['max_retries'] = new_hm_dict.pop('rise_threshold')
    # Remove the DB back references
    if 'pool' in new_hm_dict:
        del new_hm_dict['pool']
    return new_hm_dict


def db_l7policies_to_provider_l7policies(db_l7policies):
    provider_l7policies = []
    for l7policy in db_l7policies:
        provider_l7policy = db_l7policy_to_provider_l7policy(l7policy)
        provider_l7policies.append(provider_l7policy)
    return provider_l7policies


def db_l7policy_to_provider_l7policy(db_l7policy):
    l7policy_dict = db_l7policy.to_dict(recurse=True)
    # ORM snapshots expose serialized targets through a property.
    targets = db_l7policy.targets
    if targets:
        l7policy_dict['targets'] = targets
    else:
        l7policy_dict.pop('targets', None)
    request_mirrors = getattr(db_l7policy, 'request_mirrors', None)
    if request_mirrors:
        l7policy_dict['request_mirrors'] = request_mirrors
    else:
        l7policy_dict.pop('request_mirrors', None)
    new_l7policy_dict = l7policy_dict_to_provider_dict(l7policy_dict)
    if 'l7rules' in new_l7policy_dict:
        del new_l7policy_dict['l7rules']
        new_l7rules = db_l7rules_to_provider_l7rules(db_l7policy.l7rules)
        new_l7policy_dict['rules'] = new_l7rules
    for field in ('request_header_operations', 'response_header_operations'):
        if not new_l7policy_dict.get(field):
            new_l7policy_dict.pop(field, None)
    for field in ('fixed_response', 'redirect_request', 'request_url_rewrite',
                  'request_cors', 'http_request_policy'):
        if new_l7policy_dict.get(field) is None:
            new_l7policy_dict.pop(field, None)
    return driver_dm.L7Policy.from_dict(new_l7policy_dict)


def l7policy_dict_to_provider_dict(l7policy_dict):
    new_l7policy_dict = _base_to_provider_dict(l7policy_dict,
                                               include_project_id=True)
    new_l7policy_dict['l7policy_id'] = new_l7policy_dict.pop('id')
    # Allow ordinary policies and cleanup with an older provider library.
    if not REQUEST_URL_REWRITE_PAYLOAD_AVAILABLE:
        new_l7policy_dict.pop('request_url_rewrite', None)
    if not REQUEST_CORS_PAYLOAD_AVAILABLE:
        new_l7policy_dict.pop('request_cors', None)
    if not HTTP_REQUEST_POLICY_PAYLOAD_AVAILABLE:
        new_l7policy_dict.pop('http_request_policy', None)
    if not HTTP_REQUEST_MIRROR_PAYLOAD_AVAILABLE:
        new_l7policy_dict.pop('request_mirrors', None)
    if (not TCP_TLS_MIXED_MODE_PAYLOAD_AVAILABLE or
            not new_l7policy_dict.get('tcp_tls_passthrough')):
        new_l7policy_dict.pop('tcp_tls_passthrough', None)
    for attribute in ('request_header_operations',
                      'response_header_operations', 'https_listener_hostname'):
        if new_l7policy_dict.get(attribute) is None:
            new_l7policy_dict.pop(attribute, None)
    # Remove the DB back references
    if 'listener' in new_l7policy_dict:
        del new_l7policy_dict['listener']
    if 'redirect_pool' in new_l7policy_dict:
        del new_l7policy_dict['redirect_pool']
    if 'l7rules' in new_l7policy_dict and new_l7policy_dict['l7rules']:
        rules = new_l7policy_dict.pop('l7rules')
        provider_rules = []
        for rule in rules:
            provider_rule = l7rule_dict_to_provider_dict(rule)
            provider_rules.append(provider_rule)
        new_l7policy_dict['rules'] = provider_rules
    return new_l7policy_dict


def db_l7rules_to_provider_l7rules(db_l7rules):
    provider_l7rules = []
    for l7rule in db_l7rules:
        provider_l7rule = db_l7rule_to_provider_l7rule(l7rule)
        provider_l7rules.append(provider_l7rule)
    return provider_l7rules


def db_l7rule_to_provider_l7rule(db_l7rule):
    new_l7rule_dict = l7rule_dict_to_provider_dict(db_l7rule.to_dict())
    return driver_dm.L7Rule.from_dict(new_l7rule_dict)


def l7rule_dict_to_provider_dict(l7rule_dict):
    new_l7rule_dict = _base_to_provider_dict(l7rule_dict,
                                             include_project_id=True)
    new_l7rule_dict['l7rule_id'] = new_l7rule_dict.pop('id')
    # Remove the DB back references
    if 'l7policy' in new_l7rule_dict:
        del new_l7rule_dict['l7policy']
    return new_l7rule_dict


def vip_dict_to_provider_dict(vip_dict):
    new_vip_dict = {}
    if 'ip_address' in vip_dict:
        new_vip_dict['vip_address'] = vip_dict['ip_address']
    if 'network_id' in vip_dict:
        new_vip_dict['vip_network_id'] = vip_dict['network_id']
    if 'port_id' in vip_dict:
        new_vip_dict['vip_port_id'] = vip_dict['port_id']
    if 'subnet_id' in vip_dict:
        new_vip_dict['vip_subnet_id'] = vip_dict['subnet_id']
    if 'qos_policy_id' in vip_dict:
        new_vip_dict['vip_qos_policy_id'] = vip_dict['qos_policy_id']
    if constants.SG_IDS in vip_dict:
        new_vip_dict[lib_consts.VIP_SG_IDS] = vip_dict[constants.SG_IDS]
    if constants.OCTAVIA_OWNED in vip_dict:
        new_vip_dict[constants.OCTAVIA_OWNED] = vip_dict[
            constants.OCTAVIA_OWNED]
    return new_vip_dict


def additional_vip_dict_to_provider_dict(vip_dict):
    new_vip_dict = {}
    if 'ip_address' in vip_dict:
        new_vip_dict['ip_address'] = vip_dict['ip_address']
    if 'network_id' in vip_dict:
        new_vip_dict['network_id'] = vip_dict['network_id']
    if 'port_id' in vip_dict:
        new_vip_dict['port_id'] = vip_dict['port_id']
    if 'subnet_id' in vip_dict:
        new_vip_dict['subnet_id'] = vip_dict['subnet_id']
    return new_vip_dict


def provider_vip_dict_to_vip_obj(vip_dictionary):
    vip_obj = data_models.Vip()
    if 'vip_address' in vip_dictionary:
        vip_obj.ip_address = vip_dictionary['vip_address']
    if 'vip_network_id' in vip_dictionary:
        vip_obj.network_id = vip_dictionary['vip_network_id']
    if 'vip_port_id' in vip_dictionary:
        vip_obj.port_id = vip_dictionary['vip_port_id']
    if 'vip_subnet_id' in vip_dictionary:
        vip_obj.subnet_id = vip_dictionary['vip_subnet_id']
    if 'vip_qos_policy_id' in vip_dictionary:
        vip_obj.qos_policy_id = vip_dictionary['vip_qos_policy_id']
    if lib_consts.VIP_SG_IDS in vip_dictionary:
        vip_obj.sg_ids = vip_dictionary[lib_consts.VIP_SG_IDS]
    if constants.OCTAVIA_OWNED in vip_dictionary:
        vip_obj.octavia_owned = vip_dictionary[constants.OCTAVIA_OWNED]
    return vip_obj


def provider_additional_vip_dict_to_additional_vip_obj(vip_dictionary):
    vip_obj = data_models.AdditionalVip()
    if 'ip_address' in vip_dictionary:
        vip_obj.ip_address = vip_dictionary['ip_address']
    if 'network_id' in vip_dictionary:
        vip_obj.network_id = vip_dictionary['network_id']
    if 'port_id' in vip_dictionary:
        vip_obj.port_id = vip_dictionary['port_id']
    if 'subnet_id' in vip_dictionary:
        vip_obj.subnet_id = vip_dictionary['subnet_id']
    return vip_obj
