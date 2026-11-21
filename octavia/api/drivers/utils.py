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

HTTP_L7RULE_CAPABILITIES = {
    constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
        constants.GATEWAY_CAPABILITY_HTTP_HEADER_EXACT,
    constants.L7RULE_TYPE_HTTP_METHOD:
        constants.GATEWAY_CAPABILITY_HTTP_METHOD_MATCH,
}


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
    header_providers = api_settings.enabled_request_header_operation_providers
    if (driver.name in header_providers and
            getattr(driver, 'supports_request_header_operations',
                    False) is True):
        capabilities.append(
            constants.GATEWAY_CAPABILITY_REQUEST_HEADER_OPERATIONS)
    if (driver.name in api_settings.enabled_http_header_exact_providers and
            getattr(driver, 'supports_http_header_exact', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_HEADER_EXACT)
    if (driver.name in api_settings.enabled_http_method_match_providers and
            getattr(driver, 'supports_http_method_match', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_HTTP_METHOD_MATCH)
    if (driver.name in api_settings.enabled_backend_h2c_providers and
            getattr(driver, 'supports_backend_h2c', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_BACKEND_H2C)
    if (driver.name in api_settings.enabled_tls_sni_providers and
            getattr(driver, 'supports_tls_sni_passthrough', False) is True):
        capabilities.append(constants.GATEWAY_CAPABILITY_TLS_SNI)
        if (driver.name in api_settings.enabled_tls_sni_suffix_providers and
                getattr(driver, 'supports_tls_sni_suffix', False) is True):
            capabilities.append(constants.GATEWAY_CAPABILITY_TLS_SNI_SUFFIX)
    return capabilities


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


def uses_tls_sni_policy_path(driver, protocol):
    return (protocol == constants.PROTOCOL_TCP and
            getattr(driver, 'supports_tls_sni_passthrough', False) is True)


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


def require_tls_sni_rule_comparison(driver, compare_type):
    if compare_type == constants.L7RULE_COMPARE_TYPE_ENDS_WITH:
        require_tls_sni_suffix(driver)


def _unsupported_http_l7rule(driver, rule_type):
    if rule_type == constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
        message = _('Full-value exact HTTP header matching is unavailable '
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


def validate_l7rule_context(driver, rule_type, protocol, *,
                            admit_http_l7rule=True):
    if rule_type in HTTP_L7RULE_CAPABILITIES:
        if protocol not in (constants.PROTOCOL_HTTP,
                            constants.PROTOCOL_TERMINATED_HTTPS):
            raise exceptions.L7RuleValidation(error=_(
                '%(rule_type)s requires an HTTP or TERMINATED_HTTPS '
                'listener.') % {'rule_type': rule_type})
        if (admit_http_l7rule and HTTP_L7RULE_CAPABILITIES[rule_type] not in
                gateway_capabilities(driver)):
            raise _unsupported_http_l7rule(driver, rule_type)
    elif rule_type == constants.L7RULE_TYPE_TLS_SNI:
        if protocol != constants.PROTOCOL_TCP:
            raise exceptions.L7RuleValidation(error=_(
                'TLS_SNI requires a TCP listener.'))
        if not uses_tls_sni_policy_path(driver, protocol):
            require_tls_sni_passthrough(driver)
    elif uses_tls_sni_policy_path(driver, protocol):
        raise exceptions.L7RuleValidation(error=_(
            'TCP listener policies require TLS_SNI rules.'))


def require_gateway_policy_action(driver, action, protocol, *,
                                  request_header_operations=None):
    if action == constants.L7POLICY_ACTION_FIXED_RESPONSE:
        validate.validate_fixed_http_protocol(protocol)
        require_fixed_http_responses(driver)
    elif action == constants.L7POLICY_ACTION_WEIGHTED_TARGETS:
        validate.validate_weighted_l7policy_protocol(protocol)
        require_weighted_targets(driver)
    elif uses_tls_sni_policy_path(driver, protocol):
        require_tls_sni_passthrough(driver)
        if action != constants.L7POLICY_ACTION_REDIRECT_TO_POOL:
            raise exceptions.ValidationException(detail=_(
                'TCP listener policies require the REDIRECT_TO_POOL action.'))
    if request_header_operations:
        require_request_header_operations(driver)
        validate.validate_request_header_protocol(protocol)


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
    if new_listener_dict.get('default_http_response') is None:
        new_listener_dict.pop('default_http_response', None)
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


def listener_dict_to_provider_dict(listener_dict, for_delete=False):
    new_listener_dict = _base_to_provider_dict(listener_dict,
                                               include_project_id=True)
    new_listener_dict['listener_id'] = new_listener_dict.pop('id')
    if 'load_balancer_id' in new_listener_dict:
        new_listener_dict['loadbalancer_id'] = new_listener_dict.pop(
            'load_balancer_id')

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
    new_pool_dict = pool_dict_to_provider_dict(db_pool.to_dict(recurse=True),
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


def pool_dict_to_provider_dict(pool_dict, for_delete=False):
    new_pool_dict = _base_to_provider_dict(pool_dict, include_project_id=True)
    new_pool_dict['pool_id'] = new_pool_dict.pop('id')

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
    new_l7policy_dict = l7policy_dict_to_provider_dict(l7policy_dict)
    if 'l7rules' in new_l7policy_dict:
        del new_l7policy_dict['l7rules']
        new_l7rules = db_l7rules_to_provider_l7rules(db_l7policy.l7rules)
        new_l7policy_dict['rules'] = new_l7rules
    if not new_l7policy_dict.get('request_header_operations'):
        new_l7policy_dict.pop('request_header_operations', None)
    if new_l7policy_dict.get('fixed_response') is None:
        new_l7policy_dict.pop('fixed_response', None)
    return driver_dm.L7Policy.from_dict(new_l7policy_dict)


def l7policy_dict_to_provider_dict(l7policy_dict):
    new_l7policy_dict = _base_to_provider_dict(l7policy_dict,
                                               include_project_id=True)
    new_l7policy_dict['l7policy_id'] = new_l7policy_dict.pop('id')
    if new_l7policy_dict.get('request_header_operations') is None:
        new_l7policy_dict.pop('request_header_operations', None)
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
