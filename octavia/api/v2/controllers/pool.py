#    Copyright 2014 Rackspace
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

from contextlib import ExitStack

from octavia_lib.api.drivers import data_models as driver_dm
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_db import exception as odb_exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
from pecan import expose as pecan_expose
from pecan import request as pecan_request
from wsme import types as wtypes
from wsmeext import pecan as wsme_pecan

from octavia.api.drivers import driver_factory
from octavia.api.drivers import utils as driver_utils
from octavia.api.v2.controllers import base
from octavia.api.v2.controllers import health_monitor
from octavia.api.v2.controllers import member
from octavia.api.v2.types import pool as pool_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import listener_request_filters
from octavia.common import validate
from octavia.db import prepare as db_prepare
from octavia.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _validate_backend_h2c(driver, protocol, tls_enabled, *, enrolling):
    if protocol != constants.PROTOCOL_HTTP or tls_enabled is not False:
        raise exceptions.ValidationException(detail=_(
            'backend_h2c requires an HTTP pool with tls_enabled false.'))
    if (enrolling and constants.GATEWAY_CAPABILITY_BACKEND_H2C not in
            driver_utils.gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Cleartext HTTP/2 pool connections are unavailable '
                'for this provider.'))


def _validate_backend_tls_hostname(driver, protocol, hostname, tls_enabled,
                                   ca_ref, *, enrolling, system_ca=False):
    if not validate.is_exact_sni_name(hostname):
        raise exceptions.ValidationException(detail=_(
            'backend_tls_hostname must be a literal DNS hostname.'))
    if (protocol not in (constants.PROTOCOL_HTTP, constants.PROTOCOL_TCP) or
            tls_enabled is not True or not (ca_ref or system_ca)):
        raise exceptions.ValidationException(detail=_(
            'backend_tls_hostname requires an HTTP or TCP pool with '
            'tls_enabled true and a trusted CA source.'))
    if not enrolling:
        return
    if protocol == constants.PROTOCOL_TCP:
        if system_ca:
            driver_utils.require_tcp_tls_backend_auth(driver)
        else:
            driver_utils.require_tcp_pool_tls_auth(driver)
    elif (constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME not in
          driver_utils.gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Backend TLS hostname authentication is unavailable '
                'for this provider.'))


def _validate_backend_tls_system_ca(driver, hostname, ca_ref, *,
                                    enrolling):
    if hostname is None or ca_ref is not None:
        raise exceptions.ValidationException(detail=_(
            'backend_tls_system_ca requires backend_tls_hostname and '
            'cannot be combined with ca_tls_container_ref.'))
    if (enrolling and constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA
            not in driver_utils.gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Backend TLS system CA is unavailable in this region.'))


def _validate_backend_tls_require_h2(driver, protocol, hostname, *,
                                     enrolling):
    if protocol == constants.PROTOCOL_TCP:
        raise exceptions.ValidationException(detail=_(
            'backend_tls_require_h2 is unavailable on TCP pools.'))
    if hostname is None:
        raise exceptions.ValidationException(detail=_(
            'backend_tls_require_h2 requires backend_tls_hostname.'))
    if (enrolling and constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN
            not in driver_utils.gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Required backend TLS HTTP/2 ALPN is unavailable '
                'for this provider.'))


def _validate_backend_tls_subject_alt_names(driver, protocol, hostname, *,
                                            enrolling):
    if protocol == constants.PROTOCOL_TCP:
        raise exceptions.ValidationException(detail=_(
            'backend_tls_subject_alt_names is unavailable on TCP pools.'))
    if hostname is None:
        raise exceptions.ValidationException(detail=_(
            'backend_tls_subject_alt_names requires backend_tls_hostname.'))
    if (enrolling and
            constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES not in
            driver_utils.gateway_capabilities(driver)):
        raise exceptions.ProviderUnsupportedOptionError(
            prov=driver.name, user_msg=_(
                'Explicit backend TLS subject alternative names are '
                'unavailable for this provider.'))


def _has_named_http_cookie(persistence):
    return (persistence and
            persistence.get('type') ==
            constants.SESSION_PERSISTENCE_HTTP_COOKIE and
            persistence.get('cookie_name') is not None)


def _validate_session_persistence(persistence, protocol, *, for_update=False):
    if (protocol not in (constants.PROTOCOL_UDP, lib_consts.PROTOCOL_SCTP) and
            (persistence.get('persistence_timeout') is not None or
             persistence.get('persistence_granularity') is not None)):
        if for_update:
            detail = _('persistence_timeout and persistence_granularity '
                       'is only for UDP protocol pools.')
        else:
            detail = _('persistence_timeout and persistence_granularity '
                       'is only for UDP and SCTP protocol pools.')
        raise exceptions.ValidationException(detail=detail)
    validate.check_session_persistence(persistence)
    if persistence.get('type') == constants.SESSION_PERSISTENCE_HTTP_HEADER:
        if protocol != constants.PROTOCOL_HTTP:
            raise exceptions.ValidationException(detail=_(
                'HTTP_HEADER session persistence requires an HTTP pool.'))
        persistence['header_name'] = persistence['header_name'].lower()


def _validate_http_cookie_path(persistence, protocol):
    path = persistence.get('cookie_path')
    if path is None:
        return False
    if persistence.get('type') != constants.SESSION_PERSISTENCE_HTTP_COOKIE:
        raise exceptions.ValidationException(detail=_(
            'cookie_path requires HTTP_COOKIE session persistence.'))
    if path == constants.HTTP_COOKIE_DEFAULT_PATH:
        return False
    if protocol != constants.PROTOCOL_HTTP:
        raise exceptions.ValidationException(detail=_(
            'A custom HTTP_COOKIE path requires an HTTP pool.'))
    return True


def _validate_http_cookie_absolute_timeout(persistence, protocol):
    timeout = persistence.get('cookie_absolute_timeout_ms')
    scope = persistence.get('cookie_scope')
    if (('cookie_absolute_timeout_ms' in persistence) !=
            ('cookie_scope' in persistence) or
            (timeout is None) != (scope is None)):
        raise exceptions.ValidationException(detail=_(
            'Set cookie_absolute_timeout_ms and cookie_scope together, or '
            'set both to null.'))
    if timeout is None:
        return False
    if (protocol != constants.PROTOCOL_HTTP or
            not _has_named_http_cookie(persistence)):
        raise exceptions.ValidationException(detail=_(
            'An absolute cookie timeout requires a named HTTP_COOKIE on '
            'an HTTP pool.'))
    return True


def _validate_http_cookie_permanent(driver, has_absolute_timeout):
    if not has_absolute_timeout:
        raise exceptions.ValidationException(detail=_(
            'cookie_permanent requires a named HTTP_COOKIE with an '
            'absolute timeout and scope.'))
    driver_utils.require_http_cookie_permanent(driver)


class PoolsController(base.BaseController):
    RBAC_TYPE = constants.RBAC_POOL

    def __init__(self):
        super().__init__()

    @wsme_pecan.wsexpose(pool_types.PoolRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get(self, id, fields=None):
        """Gets a pool's details."""
        context = pecan_request.context.get('octavia_context')

        with context.session.begin():
            pool = self._get_db_pool(context.session, id, show_deleted=False)

            if not pool:
                raise exceptions.NotFound(
                    resource=data_models.Pool._name(),
                    id=id)

            self._auth_validate_action(context, pool.project_id,
                                       constants.RBAC_GET_ONE)

            result = pool_types.PoolResponse.from_db_obj(pool)

        if fields is not None:
            result = self._filter_fields([result], fields)[0]
        return pool_types.PoolRootResponse(pool=result)

    @wsme_pecan.wsexpose(pool_types.PoolsRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get_all(self, project_id=None, fields=None):
        """Lists all pools."""
        pcontext = pecan_request.context
        context = pcontext.get('octavia_context')

        query_filter = self._auth_get_all(context, project_id)

        with context.session.begin():
            pools, links = self.repositories.pool.get_all_API_list(
                context.session,
                show_deleted=False,
                pagination_helper=pcontext.get(constants.PAGINATION_HELPER),
                **query_filter
            )

            result = [
                pool_types.PoolResponse.from_db_obj(pool)
                for pool in pools
            ]

        if fields is not None:
            result = self._filter_fields(result, fields)
        return pool_types.PoolsRootResponse(pools=result, pools_links=links)

    def _get_affected_listener_ids(self, pool):
        """Gets a list of all listeners this request potentially affects."""
        listener_ids = [li.id for li in pool.listeners]
        return listener_ids

    def _test_lb_and_listener_statuses(self, session, lb_id, listener_ids):
        """Verify load balancer is in a mutable state."""
        # We need to verify that any listeners referencing this pool are also
        # mutable
        if not self.repositories.test_and_set_lb_and_listeners_prov_status(
                session, lb_id,
                constants.PENDING_UPDATE, constants.PENDING_UPDATE,
                listener_ids=listener_ids):
            LOG.info("Pool cannot be created or modified because the Load "
                     "Balancer is in an immutable state")
            raise exceptions.ImmutableObject(resource=_('Load Balancer'),
                                             id=lb_id)

    def _validate_create_pool(self, lock_session, pool_dict, listener_id=None,
                              driver=None):
        """Validate creating pool on load balancer.

        Update database for load balancer and (optional) listener based on
        provisioning status.
        """
        if pool_dict.get('backend_h2c', False) is None:
            raise exceptions.ValidationException(
                detail=_('backend_h2c must be true or false.'))
        require_h2 = pool_dict.get('backend_tls_require_h2', False)
        if require_h2 is None:
            raise exceptions.ValidationException(
                detail=_('backend_tls_require_h2 must be true or false.'))
        system_ca = pool_dict.get('backend_tls_system_ca', False)
        if system_ca is None:
            raise exceptions.ValidationException(
                detail=_('backend_tls_system_ca must be true or false.'))
        hostname = pool_dict.get('backend_tls_hostname')
        ca_ref = pool_dict.get('ca_tls_certificate_id')
        sans = pool_dict.get('backend_tls_subject_alt_names', [])
        if sans is None:
            validate.backend_tls_subject_alt_names(sans)
        budget = pool_dict.get('backend_retry_budget')
        persistence = pool_dict.get('session_persistence')
        tls_authorizer = constants.GATEWAY_HTTP_AUTH_TLS_POOL_TAG in (
            pool_dict.get('tags') or ())
        if tls_authorizer:
            if listener_id:
                listener_request_filters.require_non_http_tls_authorizer(
                    pool_dict['tags'])
            if not listener_request_filters.valid_pool(
                    data_models.Pool(protocol=pool_dict['protocol']),
                    tags=pool_dict['tags'], changes=pool_dict):
                raise exceptions.ValidationException(detail=_(
                    'An HTTP TLS authorizer pool requires verified '
                    'HTTP/1.1 over TLS and its own authorization role.'))
        named_http_cookie = _has_named_http_cookie(persistence)
        http_header_persistence = persistence and (
            persistence.get('type') ==
            constants.SESSION_PERSISTENCE_HTTP_HEADER)
        if persistence and (http_header_persistence or any(
                persistence.get(field) is not None for field in (
                    'header_name', 'header_absolute_timeout_ms'))):
            _validate_session_persistence(persistence, pool_dict['protocol'])
        custom_cookie_path = (
            persistence and _validate_http_cookie_path(
                persistence, pool_dict['protocol']))
        absolute_cookie_timeout = (
            persistence and _validate_http_cookie_absolute_timeout(
                persistence, pool_dict['protocol']))
        if (pool_dict.get('backend_h2c') or hostname is not None or
                system_ca or require_h2 or sans or budget is not None or
                named_http_cookie or custom_cookie_path or
                http_header_persistence or tls_authorizer):
            if driver is None:
                # Fully populated load balancer creation uses this path too.
                provider = self._get_db_lb(
                    lock_session, pool_dict['load_balancer_id']).provider
                driver = driver_factory.get_driver(provider)
        if tls_authorizer:
            driver_utils.require_http_tls_authorizer_pool(driver)
        if pool_dict.get('backend_h2c'):
            _validate_backend_h2c(driver, pool_dict['protocol'],
                                  pool_dict['tls_enabled'], enrolling=True)
        if system_ca:
            _validate_backend_tls_system_ca(
                driver, hostname, ca_ref, enrolling=True)
        if hostname is not None:
            _validate_backend_tls_hostname(
                driver, pool_dict['protocol'], hostname,
                pool_dict['tls_enabled'], ca_ref, enrolling=True,
                system_ca=system_ca)
        if require_h2:
            _validate_backend_tls_require_h2(
                driver, pool_dict['protocol'], hostname, enrolling=True)
        if sans:
            _validate_backend_tls_subject_alt_names(
                driver, pool_dict['protocol'], hostname, enrolling=True)

        if budget is not None:
            driver_utils.require_backend_retry_budget(
                driver, pool_dict['protocol'])
        if http_header_persistence:
            driver_utils.require_http_header_persistence(driver)
        if named_http_cookie:
            # Fully populated load balancer creation also reaches this path.
            _validate_session_persistence(persistence, pool_dict['protocol'])
            driver_utils.require_http_cookie_name(
                driver, pool_dict['protocol'])
            persistence['http_cookie_name_enabled'] = True
        if custom_cookie_path:
            driver_utils.require_http_cookie_path(driver)
        elif persistence:
            persistence.pop('cookie_path', None)
        if absolute_cookie_timeout:
            driver_utils.require_http_cookie_absolute_timeout(driver)
        if persistence and persistence.get('cookie_permanent') is True:
            _validate_http_cookie_permanent(driver, absolute_cookie_timeout)

        # Make sure we have a client CA if they specify a CRL
        if (pool_dict.get('crl_container_id') and
                not pool_dict.get('ca_tls_certificate_id')):
            raise exceptions.ValidationException(detail=_(
                "A CA certificate reference is required to "
                "specify a revocation list."))

        tls_certificate_id = pool_dict.get('tls_certificate_id', None)
        tls_refs = [tls_certificate_id] if tls_certificate_id else []
        self._validate_tls_refs(tls_refs)

        # Validate the client CA cert and optional client CRL
        if pool_dict.get('ca_tls_certificate_id'):
            self._validate_client_ca_and_crl_refs(
                pool_dict.get('ca_tls_certificate_id'),
                pool_dict.get('crl_container_id', None))

        # Check TLS cipher prohibit list
        if 'tls_ciphers' in pool_dict and pool_dict['tls_ciphers']:
            rejected_ciphers = validate.check_cipher_prohibit_list(
                pool_dict['tls_ciphers'])
            if rejected_ciphers:
                raise exceptions.ValidationException(detail=_(
                    'The following ciphers have been prohibited by an '
                    'administrator: ' + ', '.join(rejected_ciphers)))

        if pool_dict['tls_enabled']:
            # Validate TLS version list
            validate.check_tls_version_list(pool_dict['tls_versions'])
            # Validate TLS versions against minimum
            validate.check_tls_version_min(pool_dict['tls_versions'])
            # Validate ALPN protocol list
            validate.check_alpn_protocols(pool_dict['alpn_protocols'])

        try:
            ret = self.repositories.create_pool_on_load_balancer(
                lock_session, pool_dict,
                listener_id=listener_id)
            lock_session.flush()
            return ret
        except odb_exceptions.DBDuplicateEntry as e:
            raise exceptions.IDAlreadyExists() from e
        except odb_exceptions.DBReferenceError as e:
            raise exceptions.InvalidOption(value=pool_dict.get(e.key),
                                           option=e.key) from e
        except odb_exceptions.DBError as e:
            raise exceptions.APIException() from e

    def _is_only_specified_in_request(self, request, **kwargs):
        request_attrs = []
        check_attrs = kwargs['check_exist_attrs']
        escaped_attrs = ['from_db_obj', 'translate_key_to_db_obj',
                         'translate_dict_keys_to_db_obj', 'to_dict']

        for attr in dir(request):
            if attr.startswith('_') or attr in escaped_attrs:
                continue
            request_attrs.append(attr)

        for req_attr in request_attrs:
            if (getattr(request, req_attr) and req_attr not in check_attrs):
                return False
        return True

    def _validate_tcp_listener_pool_update(self, session, pool_id, current,
                                           changes, driver):
        if current.protocol != constants.PROTOCOL_TCP:
            return
        reopening = changes.admin_state_up is True and not current.enabled
        hostname = (current.backend_tls_hostname
                    if changes.backend_tls_hostname is wtypes.Unset
                    else changes.backend_tls_hostname)
        ca_ref = (current.ca_tls_certificate_id
                  if changes.ca_tls_container_ref is wtypes.Unset
                  else changes.ca_tls_container_ref)
        system_ca = (current.backend_tls_system_ca
                     if changes.backend_tls_system_ca is wtypes.Unset
                     else changes.backend_tls_system_ca)
        identity_changed = (system_ca != current.backend_tls_system_ca or
                            hostname != current.backend_tls_hostname or
                            (hostname is not None and
                             ca_ref != current.ca_tls_certificate_id))
        client_tls_changed = any(
            requested is not wtypes.Unset and requested != previous
            for requested, previous in (
                (changes.tls_container_ref, current.tls_certificate_id),
                (changes.crl_container_ref, current.crl_container_id)))
        transport_changed = (
            identity_changed or reopening or changes.tls_enabled is True)
        if not (transport_changed or client_tls_changed):
            return
        tls_enabled = (current.tls_enabled
                       if changes.tls_enabled is wtypes.Unset
                       else changes.tls_enabled)
        policy_repo = self.repositories.l7policy
        listener_repo = self.repositories.listener
        if reopening and policy_repo.get_policy_using_pool(
                session, pool_id, tcp_tls_termination=None,
                tcp_tls_mixed_mode=True):
            driver_utils.require_tcp_tls_mixed_mode(driver)
        if listener_repo.has_default_pool_listener(
                session, pool_id, tcp_tls_termination=False,
                tcp_default_pool_tls=True):
            driver_utils.validate_tcp_pool_attachment(
                driver, current.protocol, tls_enabled, hostname=hostname,
                ca_ref=ca_ref, system_ca=system_ca, tcp_default_pool_tls=True)

        if not transport_changed:
            return
        if (listener_repo.has_default_pool_listener(
                session, pool_id, tcp_tls_termination=True) or
                policy_repo.get_policy_using_pool(
                    session, pool_id, tcp_tls_termination=True)):
            if identity_changed and hostname is None:
                raise exceptions.ValidationException(detail=_(
                    'Detach the pool from terminating TCP listeners and '
                    'their policies before removing backend TLS hostname '
                    'authentication.'))
            validate.validate_tcp_redirect_pool_protocol(
                current.protocol, tls_enabled, tcp_tls_termination=True,
                hostname=hostname, ca_ref=ca_ref, system_ca=system_ca)
            if reopening:
                driver_utils.require_tcp_tls_termination(driver)
            if hostname is not None and (identity_changed or reopening):
                driver_utils.require_tcp_tls_backend_auth(driver)
            if ((reopening or identity_changed) and
                    policy_repo.has_active_tls_sni_weighted_pool(
                        session, pool_id)):
                driver_utils.require_tls_sni_weighted_pools(driver)

        if hostname is not None and (identity_changed or reopening):
            if (listener_repo.has_default_pool_listener(
                    session, pool_id, tcp_tls_termination=False,
                    tcp_default_pool_tls=False) or
                    policy_repo.get_policy_using_pool(
                        session, pool_id, tcp_only=False)):
                validate.validate_tcp_tls_backend_listener(
                    False, current.protocol, hostname)
            monitor_repo = self.repositories.health_monitor
            monitor_type = monitor_repo.get_enabled_type_for_pool(
                session, pool_id)
            if monitor_type is not None:
                validate.validate_tcp_tls_backend_monitor(monitor_type)
        elif (driver_utils.uses_tls_sni_policy_path(
                driver, current.protocol) and
                policy_repo.get_policy_using_pool(session, pool_id)):
            if reopening and policy_repo.has_active_tls_sni_weighted_pool(
                    session, pool_id, passthrough=True):
                driver_utils.require_tls_sni_weighted_pools(
                    driver, passthrough=True)
            validate.validate_tcp_redirect_pool_protocol(
                current.protocol, tls_enabled)
            driver_utils.require_tls_sni_passthrough(driver)
            if (policy_repo.has_enabled_tls_sni_suffix_rule(
                    session, redirect_pool_id=pool_id,
                    tcp_tls_termination=False) or
                    (reopening and
                     policy_repo.has_active_tls_sni_weighted_pool(
                         session, pool_id, passthrough=True, compare_type=(
                             constants.L7RULE_COMPARE_TYPE_ENDS_WITH)))):
                driver_utils.require_tls_sni_suffix(driver)

    def _validate_pool_request_for_udp_sctp(self, request):
        if request.session_persistence:
            if (request.session_persistence.type ==
                    constants.SESSION_PERSISTENCE_SOURCE_IP and
                    not self._is_only_specified_in_request(
                        request.session_persistence,
                        check_exist_attrs=['type', 'persistence_timeout',
                                           'persistence_granularity'])):
                raise exceptions.ValidationException(detail=_(
                    "session_persistence %s type for UDP and SCTP protocols "
                    "only accepts: type, persistence_timeout, "
                    "persistence_granularity.") % (
                        constants.SESSION_PERSISTENCE_SOURCE_IP))
            if request.session_persistence.cookie_name:
                raise exceptions.ValidationException(detail=_(
                    "Cookie names are not supported for %s pools.") %
                    "/".join((constants.PROTOCOL_UDP,
                              lib_consts.PROTOCOL_SCTP)))
            if request.session_persistence.type in [
                constants.SESSION_PERSISTENCE_HTTP_COOKIE,
                    constants.SESSION_PERSISTENCE_APP_COOKIE,
                    constants.SESSION_PERSISTENCE_HTTP_HEADER]:
                raise exceptions.ValidationException(detail=_(
                    "Session persistence of type %(type)s is not supported "
                    "for %(protocol)s protocol pools.") % {
                    'type': request.session_persistence.type,
                    'protocol': "/".join((constants.PROTOCOL_UDP,
                                          lib_consts.PROTOCOL_SCTP))})

    @wsme_pecan.wsexpose(pool_types.PoolRootResponse,
                         body=pool_types.PoolRootPOST, status_code=201)
    def post(self, pool_):
        """Creates a pool on a load balancer or listener.

        Note that this can optionally take a listener_id with which the pool
        should be associated as the listener's default_pool. If specified,
        the pool creation will fail if the listener specified already has
        a default_pool.
        """
        # For some API requests the listener_id will be passed in the
        # pool_dict:
        pool = pool_.pool
        context = pecan_request.context.get('octavia_context')
        listener = None

        context.session.begin()
        try:
            if pool.loadbalancer_id:
                pool.project_id, provider = self._get_lb_project_id_provider(
                    context.session, pool.loadbalancer_id)
            elif pool.listener_id:
                listener = self._get_db_listener(
                    context.session, pool.listener_id, show_deleted=False)
                pool.loadbalancer_id = listener.load_balancer_id
                pool.project_id, provider = self._get_lb_project_id_provider(
                    context.session, pool.loadbalancer_id)
            else:
                msg = _("Must provide at least one of: "
                        "loadbalancer_id, listener_id")
                raise exceptions.ValidationException(detail=msg)

            self._auth_validate_action(context, pool.project_id,
                                       constants.RBAC_POST)

            if pool.listener_id:
                if listener is None:
                    listener = self._get_db_listener(
                        context.session, pool.listener_id, show_deleted=False)
                if listener.load_balancer_id != pool.loadbalancer_id:
                    raise exceptions.ValidationException(
                        detail=_('The listener belongs to a different load '
                                 'balancer.'))
                if listener.protocol == lib_consts.PROTOCOL_PROMETHEUS:
                    raise exceptions.ListenerNoChildren(
                        protocol=lib_consts.PROTOCOL_PROMETHEUS)
                self._validate_protocol(listener.protocol, pool.protocol)

            if pool.protocol in (constants.PROTOCOL_UDP,
                                 lib_consts.PROTOCOL_SCTP):
                self._validate_pool_request_for_udp_sctp(pool)

            if pool.session_persistence:
                sp_dict = pool.session_persistence.to_dict(render_unsets=False)
                _validate_session_persistence(sp_dict, pool.protocol)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            if self.repositories.check_quota_met(
                    context.session,
                    data_models.Pool,
                    pool.project_id):
                raise exceptions.QuotaException(
                    resource=data_models.Pool._name())

            pool_dict = pool.to_dict(render_unsets=True)
            if pool.session_persistence:
                pool_dict['session_persistence'] = sp_dict
            if pool.backend_tls_subject_alt_names is wtypes.Unset:
                pool_dict.pop('backend_tls_subject_alt_names')
            pool_dict = db_prepare.create_pool(pool_dict)

            listener_id = pool_dict.pop('listener_id', None)
            self._test_lb_and_listener_statuses(
                context.session, lb_id=pool_dict['load_balancer_id'],
                listener_ids=[])

            if listener_id:
                listener = self.repositories.listener.get_for_update(
                    context.session, listener_id, show_deleted=False)
                if listener.https_virtual_hosts is not None:
                    raise exceptions.ValidationException(detail=_(
                        'A scoped HTTPS listener cannot have a default pool.'))
                if listener.tcp_tls_mixed_mode:
                    validate.validate_tcp_tls_mixed_default_pool(pool_dict)
                if listener.default_pool_id:
                    raise exceptions.DuplicatePoolEntry()
                validate.validate_default_http_response(
                    listener.protocol, listener.default_http_response,
                    pool_dict['id'])
                if listener.tcp_tls_termination:
                    driver_utils.require_tcp_tls_termination(driver)
                driver_utils.validate_tcp_pool_attachment(
                    driver, pool_dict['protocol'], pool_dict['tls_enabled'],
                    tcp_tls_termination=listener.tcp_tls_termination,
                    hostname=pool_dict.get('backend_tls_hostname'),
                    ca_ref=pool_dict.get('ca_tls_certificate_id'),
                    system_ca=pool_dict.get('backend_tls_system_ca'),
                    tcp_default_pool_tls=listener.tcp_default_pool_tls)
                listener.provisioning_status = constants.PENDING_UPDATE

            db_pool = self._validate_create_pool(
                context.session, pool_dict, listener_id, driver)

            # Prepare the data for the driver data model
            provider_pool = (
                driver_utils.db_pool_to_provider_pool(db_pool))

            # Dispatch to the driver
            LOG.info("Sending create Pool %s to provider %s",
                     db_pool.id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.pool_create, provider_pool)

            context.session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                context.session.rollback()

        with context.session.begin():
            pool = self._get_db_pool(context.session, db_pool.id)
            result = pool_types.PoolResponse.from_db_obj(pool)

        return pool_types.PoolRootResponse(pool=result)

    def _graph_create(self, session, pool_dict):
        load_balancer_id = pool_dict['load_balancer_id']
        pool_dict = db_prepare.create_pool(
            pool_dict, load_balancer_id)
        members = pool_dict.pop('members', []) or []
        hm = pool_dict.pop('health_monitor', None)
        db_pool = self._validate_create_pool(
            session, pool_dict)

        # Check quotas for healthmonitors
        if hm and self.repositories.check_quota_met(
                session, data_models.HealthMonitor,
                db_pool.project_id):
            raise exceptions.QuotaException(
                resource=data_models.HealthMonitor._name())

        # Now possibly create a healthmonitor
        if hm:
            if (db_pool.protocol == constants.PROTOCOL_TCP and
                    db_pool.backend_tls_hostname and hm.get('enabled', True)):
                validate.validate_tcp_tls_backend_monitor(hm['type'])
            hm[constants.POOL_ID] = db_pool.id
            hm[constants.PROJECT_ID] = db_pool.project_id
            new_hm = health_monitor.HealthMonitorController()._graph_create(
                session, hm)
            if db_pool.protocol in (constants.PROTOCOL_UDP,
                                    lib_consts.PROTOCOL_SCTP):
                health_monitor.HealthMonitorController(
                )._validate_healthmonitor_request_for_udp_sctp(new_hm,
                                                               db_pool)
            else:
                if new_hm.type in (constants.HEALTH_MONITOR_UDP_CONNECT,
                                   lib_consts.HEALTH_MONITOR_SCTP):
                    raise exceptions.ValidationException(detail=_(
                        "The %(type)s type is only supported for pools of "
                        "type %(protocol)s.") % {
                            'type': new_hm.type,
                            'protocol': '/'.join((constants.PROTOCOL_UDP,
                                                  lib_consts.PROTOCOL_SCTP))})
            db_pool.health_monitor = new_hm

        # Now check quotas for members
        if members and self.repositories.check_quota_met(
                session, data_models.Member,
                db_pool.project_id, count=len(members)):
            raise exceptions.QuotaException(
                resource=data_models.Member._name())

        # Now create members
        new_members = []
        for m in members:
            validate.ip_not_reserved(m["ip_address"])

            m['project_id'] = db_pool.project_id
            new_members.append(
                member.MembersController(db_pool.id)._graph_create(
                    session, m))
        db_pool.members = new_members
        return db_pool

    def _validate_backend_transport_update(self, pool, current, driver):
        if pool.backend_h2c is None:
            raise exceptions.ValidationException(
                detail=_('backend_h2c must be true or false.'))
        h2c = (current.backend_h2c if pool.backend_h2c is wtypes.Unset
               else pool.backend_h2c)
        tls = (current.tls_enabled if pool.tls_enabled is wtypes.Unset
               else pool.tls_enabled)
        reopening = pool.admin_state_up is True and not current.enabled
        if h2c:
            _validate_backend_h2c(driver, current.protocol, tls,
                                  enrolling=pool.backend_h2c is True or
                                  reopening)

        hostname = pool.backend_tls_hostname
        if hostname is wtypes.Unset:
            hostname = current.backend_tls_hostname
        require_h2 = pool.backend_tls_require_h2
        if require_h2 is None:
            raise exceptions.ValidationException(
                detail=_('backend_tls_require_h2 must be true or false.'))
        if require_h2 is wtypes.Unset:
            require_h2 = current.backend_tls_require_h2
        enrolling_h2 = require_h2 and not current.backend_tls_require_h2
        if not require_h2 and current.backend_tls_require_h2 and (
                current.enabled or reopening):
            raise exceptions.ValidationException(detail=_(
                'Disable the pool before removing required backend TLS '
                'HTTP/2 ALPN.'))
        if require_h2:
            _validate_backend_tls_require_h2(
                driver, current.protocol, hostname, enrolling=(
                    pool.backend_tls_require_h2 is True or reopening))
        requested_sans = pool.backend_tls_subject_alt_names
        if requested_sans is None:
            validate.backend_tls_subject_alt_names(requested_sans)
        has_san_update = requested_sans is not wtypes.Unset
        sans = (requested_sans if has_san_update
                else current.backend_tls_subject_alt_names)
        if sans:
            _validate_backend_tls_subject_alt_names(
                driver, current.protocol, hostname,
                enrolling=reopening or has_san_update)
        system_ca = pool.backend_tls_system_ca
        if system_ca is None:
            raise exceptions.ValidationException(
                detail=_('backend_tls_system_ca must be true or false.'))
        if system_ca is wtypes.Unset:
            system_ca = current.backend_tls_system_ca
        if current.backend_tls_system_ca and not system_ca and (
                current.enabled or reopening):
            raise exceptions.ValidationException(detail=_(
                'Disable the pool before removing backend TLS system CA.'))
        ca_ref = (current.ca_tls_certificate_id
                  if pool.ca_tls_container_ref is wtypes.Unset
                  else pool.ca_tls_container_ref)
        if system_ca:
            _validate_backend_tls_system_ca(
                driver, hostname, ca_ref, enrolling=(
                    not current.backend_tls_system_ca or reopening))
        if hostname is None:
            if current.backend_tls_hostname and (current.enabled or reopening):
                raise exceptions.ValidationException(detail=_(
                    'Disable the pool before removing backend TLS hostname '
                    'authentication.'))
            return

        enrolling_hostname = hostname != current.backend_tls_hostname
        tcp_trust_changed = (current.protocol == constants.PROTOCOL_TCP and
                             ca_ref != current.ca_tls_certificate_id)
        _validate_backend_tls_hostname(
            driver, current.protocol, hostname, tls, ca_ref,
            system_ca=system_ca,
            enrolling=(enrolling_hostname or tcp_trust_changed or
                       reopening or enrolling_h2))

    def _validate_request_transform_exposure(self, session, driver, pool_id,
                                             current, changes, lb_id):
        policy_repo = self.repositories.l7policy
        enabled = (changes.admin_state_up
                   if isinstance(changes.admin_state_up, bool)
                   else current.enabled)
        hostname = (
            current.backend_tls_hostname
            if changes.backend_tls_hostname is wtypes.Unset
            else changes.backend_tls_hostname)
        tls_tag = constants.GATEWAY_BACKEND_TLS_POOL_TAG
        tagged = (current.gateway_backend_tls_tagged
                  if changes.tags is wtypes.Unset
                  else tls_tag in (changes.tags or ()))
        http_pool = current.protocol == constants.PROTOCOL_HTTP
        was_routable = (
            current.enabled or current.backend_tls_hostname is not None or
            (http_pool and current.gateway_backend_tls_tagged))
        routable = enabled or hostname is not None or (http_pool and tagged)

        if enabled and not current.enabled:
            driver_utils.require_no_active_request_transforms(
                driver, policy_repo, session, load_balancer_id=lb_id,
                restoring_pool=pool_id)
        elif not was_routable and routable:
            driver_utils.require_no_active_request_transforms(
                driver, policy_repo, session, load_balancer_id=lb_id,
                activating_closed_pool=pool_id)
        elif was_routable and not routable:
            driver_utils.require_no_exposed_request_transforms(
                driver, policy_repo, session, disabling_pool=pool_id)

    def _validate_authorization_pool_update(
            self, session, pool_id, current, changes):
        if not changes.keys() & {
                'tags', 'tls_enabled', 'backend_h2c',
                'backend_tls_require_h2', 'backend_tls_hostname',
                'ca_tls_certificate_id', 'backend_tls_system_ca',
                'crl_container_id', 'alpn_protocols'}:
            return
        previous_tags = self.repositories.pool.get_tags_for_update(
            session, pool_id)
        tags = changes.get('tags', previous_tags) or ()
        role = constants.GATEWAY_HTTP_AUTH_TLS_POOL_TAG
        if (role in previous_tags) != (role in tags):
            raise exceptions.ValidationException(detail=_(
                'The HTTP TLS authorizer role is set when the pool is '
                'created.'))
        listener_id = (self.repositories.listener
                       .get_request_filter_listener_using_pool(
                           session, pool_id))
        policies = (self.repositories.l7policy
                    .get_external_auth_policies_using_pool(session, pool_id))
        protocol = ('GRPC' if constants.GATEWAY_GRPC_AUTH_POOL_TAG in
                    previous_tags else constants.PROTOCOL_HTTP)
        if listener_id and not listener_request_filters.valid_pool(
                current, protocol=protocol, tags=tags, changes=changes):
            raise exceptions.PoolInUseByListenerRequestFilter(
                id=pool_id, listener_id=listener_id)
        for policy in policies:
            protocol = ('GRPC' if validate.is_grpc_external_auth(
                policy.external_auth) else constants.PROTOCOL_HTTP)
            if not listener_request_filters.valid_pool(
                    current, protocol=protocol, tags=tags, changes=changes):
                raise exceptions.PoolInUseByL7Policy(
                    id=pool_id, l7policy_id=policy.l7policy_id)
        if role in tags and not listener_request_filters.valid_pool(
                current, tags=tags, changes=changes):
            raise exceptions.ValidationException(detail=_(
                'An HTTP TLS authorizer pool requires verified '
                'HTTP/1.1 over TLS and its own authorization role.'))

    def _validate_pool_persistence_update(self, session, pool_id, pool,
                                          current, driver):
        changes = pool.session_persistence
        if changes:
            old = self.repositories.session_persistence.get_for_update(
                session, pool_id)
            old_timed = old is not None and (
                old.cookie_absolute_timeout_ms is not None or
                old.cookie_scope is not None)
            path_update = (changes.type is wtypes.Unset and
                           changes.cookie_path is not wtypes.Unset)
            replacing_policy = changes.type is not wtypes.Unset
            if not changes.type and old is not None:
                changes.type = old.type
            if changes.type == constants.SESSION_PERSISTENCE_HTTP_HEADER:
                self._validate_http_header_persistence_update(
                    changes, old, current.protocol, driver, replacing_policy)
                return
            if changes.cookie_name is wtypes.Unset:
                setting_timeout = changes.cookie_absolute_timeout_ms not in (
                    wtypes.Unset, None)
                preserve_name = (old is not None and
                                 changes.type == old.type and
                                 old.http_cookie_name_enabled and
                                 (old_timed or setting_timeout or path_update))
                changes.cookie_name = (
                    old.cookie_name if preserve_name else None)

        if current.protocol in (constants.PROTOCOL_UDP,
                                lib_consts.PROTOCOL_SCTP):
            self._validate_pool_request_for_udp_sctp(pool)
        if not changes:
            return

        persistence = changes.to_dict(render_unsets=False)
        _validate_session_persistence(persistence, current.protocol,
                                      for_update=True)
        if old is not None and (
                old.type == constants.SESSION_PERSISTENCE_HTTP_HEADER):
            changes.header_name = None
            changes.header_absolute_timeout_ms = None
        old_path = old.cookie_path if old is not None else None
        if _validate_http_cookie_path(persistence, current.protocol):
            if changes.cookie_path != old_path:
                driver_utils.require_http_cookie_path(driver)
        elif (changes.cookie_path is not wtypes.Unset or
              (old is not None and old.type != changes.type)):
            # Send an explicit null to withdraw an enrolled path.
            changes.cookie_path = (
                wtypes.Unset if old_path in
                (None, constants.HTTP_COOKIE_DEFAULT_PATH) else None)
        enrolling_timeout = _validate_http_cookie_absolute_timeout(
            persistence, current.protocol)
        keep_name = (old is not None and (old_timed or path_update) and
                     old.type == changes.type and
                     old.cookie_name == changes.cookie_name and
                     old.http_cookie_name_enabled)
        if (old_timed and
                changes.cookie_absolute_timeout_ms is wtypes.Unset and
                not keep_name):
            raise exceptions.ValidationException(detail=_(
                'Clear or replace the absolute cookie timeout when changing '
                'its persistence type or cookie name.'))
        if _has_named_http_cookie(persistence) and not keep_name:
            driver_utils.require_http_cookie_name(driver, current.protocol)
        if enrolling_timeout:
            driver_utils.require_http_cookie_absolute_timeout(driver)
        # Omission preserves the stored lifetime. Replacing the policy
        # still enrolls the new name, scope or deadline in Permanent.
        replacing_permanent = (
            changes.cookie_permanent is wtypes.Unset and
            old_timed and old.cookie_permanent and enrolling_timeout and
            (not keep_name or old.cookie_scope != changes.cookie_scope or
             old.cookie_absolute_timeout_ms !=
             changes.cookie_absolute_timeout_ms))
        if changes.cookie_permanent is True or replacing_permanent:
            _validate_http_cookie_permanent(
                driver, enrolling_timeout or
                (keep_name and
                 changes.cookie_absolute_timeout_ms is wtypes.Unset and
                 validate.is_valid_http_cookie_absolute_timeout(
                     old.cookie_absolute_timeout_ms) and
                 validate.is_valid_http_cookie_scope(old.cookie_scope)))
        elif (old is not None and old.cookie_permanent and
                changes.cookie_absolute_timeout_ms is None):
            changes.cookie_permanent = False

    @staticmethod
    def _validate_http_header_persistence_update(
            changes, old, protocol, driver, replacing_policy):
        had_header = old is not None and (
            old.type == constants.SESSION_PERSISTENCE_HTTP_HEADER)
        if had_header and not replacing_policy:
            if changes.header_name is wtypes.Unset:
                changes.header_name = old.header_name
            if changes.header_absolute_timeout_ms is wtypes.Unset:
                changes.header_absolute_timeout_ms = (
                    old.header_absolute_timeout_ms)
        persistence = changes.to_dict(render_unsets=False)
        _validate_session_persistence(persistence, protocol, for_update=True)
        changes.header_name = persistence['header_name']
        if changes.header_absolute_timeout_ms is wtypes.Unset:
            changes.header_absolute_timeout_ms = None
        if (not had_header or old.header_name != changes.header_name or
                old.header_absolute_timeout_ms !=
                changes.header_absolute_timeout_ms):
            driver_utils.require_http_header_persistence(driver)
        if old is not None and old.type in (
                constants.SESSION_PERSISTENCE_APP_COOKIE,
                constants.SESSION_PERSISTENCE_HTTP_COOKIE):
            changes.cookie_name = None
            changes.cookie_path = None
            changes.cookie_scope = None
            changes.cookie_absolute_timeout_ms = None
            changes.cookie_permanent = False

    def _validate_pool_PUT(self, pool, current):

        crl_ref = None
        # If we got a crl_ref and it's not unset, use it
        if (pool.crl_container_ref and
                pool.crl_container_ref != wtypes.Unset):
            crl_ref = pool.crl_container_ref
        # If we got Unset and a CRL exists in the DB, use the DB crl_ref
        elif (current.crl_container_id and
              pool.crl_container_ref == wtypes.Unset):
            crl_ref = current.crl_container_id

        ca_ref = None
        db_ca_ref = current.ca_tls_certificate_id
        if pool.ca_tls_container_ref != wtypes.Unset:
            if not pool.ca_tls_container_ref and db_ca_ref and crl_ref:
                raise exceptions.ValidationException(detail=_(
                    "A CA reference cannot be removed when a "
                    "certificate revocation list is present."))

            if not pool.ca_tls_container_ref and not db_ca_ref and crl_ref:
                raise exceptions.ValidationException(detail=_(
                    "A CA reference is required to "
                    "specify a certificate revocation list."))
            if pool.ca_tls_container_ref:
                ca_ref = pool.ca_tls_container_ref
        elif db_ca_ref and pool.ca_tls_container_ref == wtypes.Unset:
            ca_ref = db_ca_ref
        elif crl_ref and not db_ca_ref:
            raise exceptions.ValidationException(detail=_(
                "A CA reference is required to "
                "specify a certificate revocation list."))

        if pool.tls_container_ref:
            self._validate_tls_refs([pool.tls_container_ref])

        # Validate the client CA cert and optional client CRL
        # Recheck unchanged CA material on activation or TLS enrollment.
        if ca_ref and (not current.backend_tls_hostname or
                       pool.backend_tls_hostname not in (wtypes.Unset, None) or
                       pool.ca_tls_container_ref is not wtypes.Unset or
                       pool.crl_container_ref is not wtypes.Unset or
                       (pool.backend_tls_require_h2 is True and
                        not current.backend_tls_require_h2) or
                       (pool.backend_tls_subject_alt_names and
                        pool.backend_tls_subject_alt_names !=
                        current.backend_tls_subject_alt_names) or
                       (pool.admin_state_up is True and not current.enabled)):
            self._validate_client_ca_and_crl_refs(ca_ref, crl_ref)

        # Check TLS cipher prohibit list
        if pool.tls_ciphers:
            rejected_ciphers = validate.check_cipher_prohibit_list(
                pool.tls_ciphers)
            if rejected_ciphers:
                raise exceptions.ValidationException(detail=_(
                    "The following ciphers have been prohibited by an "
                    "administrator: " + ', '.join(rejected_ciphers)))

        if pool.tls_versions is not wtypes.Unset:
            # Validate TLS version list
            validate.check_tls_version_list(pool.tls_versions)
            # Validate TLS version against minimum
            validate.check_tls_version_min(pool.tls_versions)

        if pool.alpn_protocols is not wtypes.Unset:
            # Validate ALPN protocol list
            validate.check_alpn_protocols(pool.alpn_protocols)

    @wsme_pecan.wsexpose(pool_types.PoolRootResponse, wtypes.text,
                         body=pool_types.PoolRootPut, status_code=200)
    def put(self, id, pool_):
        """Updates a pool on a load balancer."""
        pool = pool_.pool
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_pool = self._get_db_pool(context.session, id,
                                        show_deleted=False)

            project_id, provider = self._get_lb_project_id_provider(
                context.session, db_pool.load_balancer_id)

            self._auth_validate_action(context, project_id, constants.RBAC_PUT)

            if pool.tls_versions is None:
                pool.tls_versions = CONF.api_settings.default_pool_tls_versions
            if pool.tls_ciphers is None:
                pool.tls_ciphers = CONF.api_settings.default_pool_ciphers

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            self._test_lb_and_listener_statuses(
                context.session, lb_id=db_pool.load_balancer_id,
                listener_ids=self._get_affected_listener_ids(db_pool))

            current = self.repositories.pool.get_transport_for_update(
                context.session, id)
            if (current.udp_packet_drop is not None and
                    (pool.session_persistence or
                     pool.lb_algorithm not in
                     (wtypes.Unset, constants.LB_ALGORITHM_ROUND_ROBIN))):
                raise exceptions.ValidationException(detail=_(
                    'Managed UDP pools require round-robin without session '
                    'persistence.'))
            self._validate_pool_persistence_update(
                context.session, id, pool, current, driver)
            self._validate_backend_transport_update(pool, current, driver)
            if (pool.backend_retry_budget is not wtypes.Unset and
                    pool.backend_retry_budget is not None):
                driver_utils.require_backend_retry_budget(
                    driver, current.protocol)
            listener_repo = self.repositories.listener
            pool_dict = pool.to_dict(render_unsets=False)
            self._validate_authorization_pool_update(
                context.session, id, current, pool_dict)
            transport_fields = {
                'backend_h2c', 'backend_tls_require_h2', 'tls_enabled',
                'alpn_protocols'}
            if transport_fields.intersection(pool_dict):
                tracing_listener_id = (
                    listener_repo.get_otlp_tracing_listener_using_pool(
                        context.session, id))
                if tracing_listener_id:
                    validate.validate_otlp_collector_transport(
                        current.protocol,
                        pool_dict.get('backend_h2c', current.backend_h2c),
                        pool_dict.get('backend_tls_require_h2',
                                      current.backend_tls_require_h2),
                        pool_dict.get('tls_enabled', current.tls_enabled),
                        pool_dict.get('alpn_protocols',
                                      current.alpn_protocols))
            self._validate_pool_PUT(pool, current)
            self._validate_tcp_listener_pool_update(
                context.session, id, current, pool, driver)
            self._validate_request_transform_exposure(
                context.session, driver, id, current, pool,
                db_pool.load_balancer_id)

            # Prepare the data for the driver data model
            pool_dict['id'] = id
            pool_dict['project_id'] = project_id
            provider_pool_dict = driver_utils.pool_dict_to_provider_dict(
                pool_dict, for_update=True)

            # Also prepare the baseline object data
            old_provider_pool = driver_utils.db_pool_to_provider_pool(
                db_pool, for_delete=True)

            # Dispatch to the driver
            LOG.info("Sending update Pool %s to provider %s", id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.pool_update,
                old_provider_pool,
                driver_dm.Pool.from_dict(provider_pool_dict))

            # Update the database to reflect what the driver just accepted
            pool.provisioning_status = constants.PENDING_UPDATE
            db_pool_dict = pool.to_dict(render_unsets=False)
            if pool.backend_tls_system_ca is not wtypes.Unset or (
                    current.backend_tls_system_ca and any(
                        field in db_pool_dict for field in (
                            'enabled', 'backend_tls_hostname',
                            'backend_tls_subject_alt_names',
                            'tls_enabled', 'tls_certificate_id'))):
                db_pool_dict['backend_tls_system_ca_sha256'] = None
                db_pool_dict['backend_tls_system_ca_peers'] = None
            persistence = db_pool_dict.get('session_persistence')
            if persistence:
                persistence['http_cookie_name_enabled'] = (
                    _has_named_http_cookie(persistence))
                if ('cookie_absolute_timeout_ms' in persistence and
                        persistence['cookie_absolute_timeout_ms'] is None):
                    persistence['cookie_absolute_timeout_error'] = False
            self.repositories.update_pool_and_sp(context.session, id,
                                                 db_pool_dict)

        # Force SQL alchemy to query the DB, otherwise we get inconsistent
        # results
        context.session.expire_all()

        with context.session.begin():
            pool = self._get_db_pool(context.session, id)
            result = pool_types.PoolResponse.from_db_obj(pool)

        return pool_types.PoolRootResponse(pool=result)

    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, id):
        """Deletes a pool from a load balancer."""
        context = pecan_request.context.get('octavia_context')
        session = context.session
        with session.begin():
            pool = self._get_db_pool(session, id, show_deleted=False)
            lb_id, protocol = pool.load_balancer_id, pool.protocol
        with ExitStack() as render_locks, session.begin():
            operation = None
            if protocol == constants.PROTOCOL_UDP:
                lb_repo = self.repositories.load_balancer
                lb = lb_repo.get_for_update(session, lb_id)
                if lb is None or lb.provisioning_status == constants.DELETED:
                    raise exceptions.NotFound(resource='Pool', id=id)
                project_id, provider = lb.project_id, lb.provider
                db_pool = (
                    self.repositories.pool.get_on_load_balancer_for_update(
                        session, lb_id, project_id, id,
                        include_pending_delete=True))
                if db_pool.udp_packet_drop is not None:
                    operation = lb_repo.pending_udp_pool_operation(lb, id)
            else:
                db_pool = self._get_db_pool(session, id, show_deleted=False)
                project_id, provider = self._get_lb_project_id_provider(
                    session, lb_id)

            self._auth_validate_action(
                context,
                project_id,
                constants.RBAC_DELETE
            )

            if db_pool.l7policies:
                raise exceptions.PoolInUseByL7Policy(
                    id=db_pool.id, l7policy_id=db_pool.l7policies[0].id)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            managed_udp = db_pool.udp_packet_drop is not None
            if managed_udp:
                driver_utils.require_listener_render_lock(render_locks, lb_id)
            if operation:
                deleting = (operation.get('action') ==
                            constants.UDP_POOL_DELETE_ACTION)
                expected = (constants.PENDING_DELETE if deleting else
                            constants.PENDING_UPDATE)
                if (db_pool.provisioning_status != expected or
                        db_pool.tcp_member_batch_id != operation['id']):
                    raise exceptions.ImmutableObject(
                        resource='Load Balancer', id=lb_id)
            else:
                self._test_lb_and_listener_statuses(
                    session, lb_id=lb_id,
                    listener_ids=self._get_affected_listener_ids(db_pool))
            listener_repo = self.repositories.listener
            filter_listener_id = (
                listener_repo.get_request_filter_listener_using_pool(
                    context.session, db_pool.id))
            if filter_listener_id:
                raise exceptions.PoolInUseByListenerRequestFilter(
                    id=id, listener_id=filter_listener_id)
            tracing_listener_id = (
                listener_repo.get_otlp_tracing_listener_using_pool(
                    context.session, db_pool.id))
            if tracing_listener_id:
                raise exceptions.PoolInUseByListenerOtlpTracing(
                    id=id, listener_id=tracing_listener_id)
            policy_repo = self.repositories.l7policy
            policy_id = (policy_repo.get_external_auth_policy_using_pool(
                context.session, db_pool.id) or
                policy_repo.get_weighted_policy_using_pool(
                    context.session, db_pool.id) or
                policy_repo.get_mirroring_policy_using_pool(
                    context.session, db_pool.id) or
                policy_repo.get_policy_using_pool(
                    context.session, db_pool.id) or
                policy_repo.get_policy_using_pool(
                    context.session, db_pool.id, tcp_tls_termination=True))
            if policy_id:
                raise exceptions.PoolInUseByL7Policy(
                    id=db_pool.id, l7policy_id=policy_id)
            if managed_udp:
                self._schedule_managed_udp_pool_delete(
                    driver, lb, db_pool, operation)
                return
            self.repositories.pool.update(
                context.session, db_pool.id,
                provisioning_status=constants.PENDING_DELETE)

            LOG.info("Sending delete Pool %s to provider %s", id, driver.name)
            provider_pool = (
                driver_utils.db_pool_to_provider_pool(db_pool,
                                                      for_delete=True))
            driver_utils.call_provider(driver.name, driver.pool_delete,
                                       provider_pool)

    @staticmethod
    def _schedule_managed_udp_pool_delete(driver, lb, pool, operation):
        if (operation is None or
                operation.get('action') != constants.UDP_POOL_DELETE_ACTION):
            pool.provisioning_status = constants.PENDING_DELETE
            pool.tcp_member_batch_id = uuidutils.generate_uuid()
            lb.tcp_member_batch = {
                'id': pool.tcp_member_batch_id,
                'pool_id': pool.id,
                'listener_ids': [listener.id for listener in pool.listeners],
                'protocol': constants.PROTOCOL_UDP,
                'action': constants.UDP_POOL_DELETE_ACTION,
                'phase': constants.TCP_MEMBER_BATCH_PENDING,
            }
        driver_utils.call_provider(
            driver.name, driver.delete_managed_udp_pool,
            lb.id, pool.id, pool.tcp_member_batch_id)

    @pecan_expose()
    def _lookup(self, pool_id, *remainder):
        """Overridden pecan _lookup method for custom routing.

        Verifies that the pool passed in the url exists, and if so decides
        which controller, if any, should control be passed.
        """
        context = pecan_request.context.get('octavia_context')
        if pool_id and remainder and remainder[0] == 'members':
            remainder = remainder[1:]
            with context.session.begin():
                db_pool = self.repositories.pool.get_orm(context.session,
                                                         id=pool_id)
                if not db_pool:
                    LOG.info("Pool %s not found.", pool_id)
                    raise exceptions.NotFound(
                        resource=data_models.Pool._name(),
                        id=pool_id
                    )
                if remainder:
                    return (
                        member.MemberController(pool_id=db_pool.id),
                        remainder
                    )
                return member.MembersController(pool_id=db_pool.id), remainder
        return None
