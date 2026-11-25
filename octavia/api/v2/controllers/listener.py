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

from octavia_lib.api.drivers import data_models as driver_dm
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_db import exception as odb_exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from pecan import expose as pecan_expose
from pecan import request as pecan_request
from wsme import types as wtypes
from wsmeext import pecan as wsme_pecan

from octavia.api.drivers import driver_factory
from octavia.api.drivers import utils as driver_utils
from octavia.api.v2.controllers import base
from octavia.api.v2.controllers import l7policy
from octavia.api.v2.types import listener as listener_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import listener_request_filters
from octavia.common import stats
from octavia.common import utils as common_utils
from octavia.common import validate
from octavia.db import prepare as db_prepare
from octavia.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _validate_frontend_client_auth_fallback(
        protocol, client_auth, ca_ref, server_cert, sni_certs):
    if (protocol != constants.PROTOCOL_TERMINATED_HTTPS or
            client_auth != constants.CLIENT_AUTH_MANDATORY or not ca_ref):
        raise exceptions.ValidationException(detail=_(
            'Insecure frontend client authentication fallback requires a '
            'TERMINATED_HTTPS listener with MANDATORY client authentication '
            'and a client CA reference.'))
    if not (server_cert or sni_certs):
        raise exceptions.ValidationException(detail=_(
            'Insecure frontend client authentication fallback requires a '
            'default or SNI server certificate reference.'))


def validate_policy_options_on_create(
        driver, listener, *, creating_load_balancer=False):
    protocol = listener['protocol']
    if creating_load_balancer and listener.get('otlp_tracing') is not None:
        raise exceptions.ValidationException(detail=_(
            'Configure listener OTLP tracing after creating the load '
            'balancer and collector pool.'))
    if listener.get('client_authentication_insecure_fallback') is True:
        _validate_frontend_client_auth_fallback(
            protocol, listener.get('client_authentication'),
            listener.get('client_ca_tls_certificate_id'),
            listener.get('tls_certificate_id'), listener.get('sni_containers'))
        driver_utils.require_frontend_client_auth_fallback(driver)
    tcp_tls_termination = listener.get('tcp_tls_termination', False)
    mixed_mode = listener.get('tcp_tls_mixed_mode', False)
    if not isinstance(tcp_tls_termination, bool):
        raise exceptions.ValidationException(detail=_(
            'tcp_tls_termination must be true or false.'))
    if not isinstance(mixed_mode, bool):
        raise exceptions.ValidationException(detail=_(
            'tcp_tls_mixed_mode must be true or false.'))
    if tcp_tls_termination:
        if protocol != constants.PROTOCOL_TCP:
            raise exceptions.ValidationException(detail=_(
                'tcp_tls_termination requires a TCP listener.'))
        if not listener.get('tls_certificate_id'):
            raise exceptions.ValidationException(detail=_(
                'tcp_tls_termination requires default_tls_container_ref.'))
        driver_utils.require_tcp_tls_termination(driver)
    if mixed_mode:
        if not tcp_tls_termination:
            raise exceptions.ValidationException(detail=_(
                'tcp_tls_mixed_mode requires tcp_tls_termination.'))
        validate.validate_tcp_tls_mixed_default_pool(
            listener.get('default_pool_id') or listener.get('default_pool'))
        driver_utils.require_tcp_tls_mixed_mode(driver)

    default_response = listener.get('default_http_response')
    hosts = listener.get('https_virtual_hosts')
    if hosts is not None:
        driver_utils.require_https_listener_isolation(driver)
        hosts = validate.https_virtual_hosts(hosts)
        listener['https_virtual_hosts'] = hosts
        validate.validate_https_listener(
            protocol, listener.get('tls_certificate_id'),
            listener.get('sni_containers'),
            listener.get('default_pool_id') or listener.get('default_pool'),
            default_response)
    validate.validate_default_http_response(
        protocol, default_response,
        listener.get('default_pool_id') or listener.get('default_pool'))
    if default_response is not None:
        driver_utils.require_fixed_http_responses(driver)

    tcp_policy = driver_utils.uses_tls_sni_policy_path(
        driver, protocol, tcp_tls_termination)
    for policy in listener.get('l7policies') or []:
        passthrough = policy.get('tcp_tls_passthrough', False)
        driver_utils.validate_tcp_tls_policy_mode(
            driver, mixed_mode, passthrough)
        hostname = validate.validate_https_policy_hostname(
            hosts, policy.get('https_listener_hostname'))
        if hostname is not None:
            policy['https_listener_hostname'] = hostname
        action = policy.get('action')
        for rule in policy.get('rules') or []:
            driver_utils.validate_l7rule_context(
                driver, rule['type'], protocol,
                tcp_tls_termination=tcp_tls_termination)
            if tcp_policy:
                try:
                    validate.l7rule_data(data_models.L7Rule.from_dict(rule))
                except exceptions.InvalidL7Rule as e:
                    raise exceptions.L7RuleValidation(error=e) from e
                driver_utils.require_tls_sni_rule_comparison(
                    driver, rule['compare_type'],
                    tcp_tls_termination and not passthrough)
        if (not tcp_policy and
                action not in (constants.L7POLICY_ACTION_FIXED_RESPONSE,
                               constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
                               constants.L7POLICY_ACTION_REDIRECT_REQUEST) and
                policy.get('fixed_response') is None and
                policy.get('redirect_request') is None and
                policy.get('request_url_rewrite') is None and
                policy.get('request_cors') is None and
                policy.get('http_request_policy') is None and
                not policy.get('request_mirrors') and
                policy.get('targets') is None and
                'request_header_operations' not in policy and
                'response_header_operations' not in policy):
            continue
        checked = validate.sanitize_l7policy_api_args(
            policy.copy(), create=True)
        if creating_load_balancer and validate.request_mirror_pool_ids(
                checked.get('request_mirrors'), checked.get('targets')):
            raise exceptions.ValidationException(
                detail=_('Create request mirrors from the L7 policy '
                         'endpoint after creating the load balancer and '
                         'pools.'))
        driver_utils.require_gateway_policy_action(
            driver, checked['action'], protocol,
            tcp_tls_termination=tcp_tls_termination,
            tcp_tls_mixed_mode=mixed_mode, tcp_tls_passthrough=passthrough,
            request_url_rewrite=checked.get('request_url_rewrite'),
            targets=checked.get('targets'),
            request_cors=checked.get('request_cors'),
            http_request_policy=checked.get('http_request_policy'),
            request_mirrors=checked.get('request_mirrors'))
        l7policy.validate_policy_headers(checked, protocol, driver)
        if not creating_load_balancer:
            raise exceptions.ValidationException(
                detail=_('Create extended policies from the L7 policy '
                         'endpoint after creating the listener.'))
        if (action == constants.L7POLICY_ACTION_WEIGHTED_TARGETS and
                any('pool_id' in target for target in checked['targets'])):
            raise exceptions.ValidationException(
                detail=_('Create weighted pool targets from the L7 policy '
                         'endpoint after creating the load balancer and '
                         'pools.'))


class ListenersController(base.BaseController):
    RBAC_TYPE = constants.RBAC_LISTENER

    def __init__(self):
        super().__init__()

    @wsme_pecan.wsexpose(listener_types.ListenerRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get_one(self, id, fields=None):
        """Gets a single listener's details."""
        context = pecan_request.context.get('octavia_context')

        with context.session.begin():
            listener = self._get_db_listener(
                context.session,
                id,
                show_deleted=False
            )

            if not listener:
                raise exceptions.NotFound(
                    resource=data_models.Listener._name(),
                    id=id
                )

            self._auth_validate_action(context, listener.project_id,
                                       constants.RBAC_GET_ONE)

            result = listener_types.ListenerResponse.from_db_obj(listener)

        if fields is not None:
            result = self._filter_fields([result], fields)[0]
        return listener_types.ListenerRootResponse(listener=result)

    @wsme_pecan.wsexpose(listener_types.ListenersRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get_all(self, project_id=None, fields=None):
        """Lists all listeners."""
        pcontext = pecan_request.context
        context = pcontext.get('octavia_context')

        query_filter = self._auth_get_all(context, project_id)

        with context.session.begin():
            listeners, links = self.repositories.listener.get_all_API_list(
                context.session,
                show_deleted=False,
                pagination_helper=pcontext.get(constants.PAGINATION_HELPER),
                **query_filter
            )

            result = [
                listener_types.ListenerResponse.from_db_obj(listener)
                for listener in listeners
            ]

        if fields is not None:
            result = self._filter_fields(result, fields)
        return listener_types.ListenersRootResponse(
            listeners=result, listeners_links=links)

    def _test_lb_and_listener_statuses(
            self, session, lb_id, id=None,
            listener_status=constants.PENDING_UPDATE, *, allow_error=False):
        """Verify load balancer is in a mutable state."""
        lb_repo = self.repositories.load_balancer
        if id:
            if not self.repositories.test_and_set_lb_and_listeners_prov_status(
                    session, lb_id, constants.PENDING_UPDATE,
                    listener_status, listener_ids=[id]):
                LOG.info("Load Balancer %s is immutable.", lb_id)
                db_lb = lb_repo.get_orm(session, id=lb_id)
                raise exceptions.ImmutableObject(resource=db_lb._name(),
                                                 id=lb_id)
        else:
            if not lb_repo.test_and_set_provisioning_status(
                    session, lb_id, constants.PENDING_UPDATE,
                    **({'allow_error': True} if allow_error else {})):
                db_lb = lb_repo.get_orm(session, id=lb_id)
                LOG.info("Load Balancer %s is immutable.", db_lb.id)
                raise exceptions.ImmutableObject(resource=db_lb._name(),
                                                 id=lb_id)

    def _validate_pool(self, session, lb_id, pool_id, listener_protocol):
        """Validate pool given exists on same load balancer as listener."""
        db_pool = self.repositories.pool.get_orm(
            session, load_balancer_id=lb_id, id=pool_id)
        if not db_pool:
            raise exceptions.NotFound(
                resource=data_models.Pool._name(), id=pool_id)
        self._validate_protocol(listener_protocol, db_pool.protocol)

    def _has_tls_container_refs(self, listener_dict):
        return (listener_dict.get('tls_certificate_id') or
                listener_dict.get('client_ca_tls_certificate_id') or
                listener_dict.get('client_crl_container_id') or
                listener_dict.get('sni_containers'))

    def _is_tls_or_insert_header(self, listener_dict):
        return (self._has_tls_container_refs(listener_dict) or
                listener_dict.get('insert_headers'))

    def _validate_insert_headers(self, insert_header_list, listener_protocol):
        if (listener_protocol not in
                constants.LISTENER_PROTOCOLS_SUPPORTING_HEADER_INSERTION):
            raise exceptions.InvalidOption(
                value='insert-headers',
                option=f'a {listener_protocol} protocol listener.')
        if list(set(insert_header_list) - (
                set(constants.SUPPORTED_HTTP_HEADERS +
                    constants.SUPPORTED_SSL_HEADERS))):
            raise exceptions.InvalidOption(
                value=insert_header_list,
                option='insert_headers')
        if not listener_protocol == constants.PROTOCOL_TERMINATED_HTTPS:
            is_matched = len(
                constants.SUPPORTED_SSL_HEADERS) > len(
                list(set(constants.SUPPORTED_SSL_HEADERS) - set(
                    insert_header_list)))
            if is_matched:
                headers = []
                for header_name in insert_header_list:
                    if header_name in constants.SUPPORTED_SSL_HEADERS:
                        headers.append(header_name)
                raise exceptions.InvalidOption(
                    value=headers,
                    option=f'{listener_protocol} protocol listener.')

    def _validate_cidr_compatible_with_vip(self, db_vip: data_models.Vip,
                                           vips: list[str],
                                           allowed_cidrs: list[str]):
        if allowed_cidrs and db_vip.sg_ids:
            msg = _("Allowed CIDRs are not allowed when using custom VIP "
                    "Security Groups.")
            raise exceptions.ValidationException(
                detail=msg)

        for cidr in allowed_cidrs:
            for vip in vips:
                # Check if CIDR IP version matches VIP IP version
                if (common_utils.is_cidr_ipv6(cidr) ==
                        common_utils.is_ipv6(vip)):
                    break
            else:
                msg = _("CIDR %(cidr)s IP version incompatible with all VIPs "
                        "%(vips)s IP version.")
                raise exceptions.ValidationException(
                    detail=msg % {'cidr': cidr, 'vips': vips})

    def _validate_create_listener(self, lock_session, listener_dict, driver):
        """Validate listener for wrong protocol or duplicate listeners

        Update the load balancer db when provisioning status changes.
        """
        listener_protocol = listener_dict.get('protocol')

        _can_tls_offload = (
            listener_dict.get('tcp_tls_termination') is True or
            listener_protocol == constants.PROTOCOL_TERMINATED_HTTPS or
            (listener_protocol == constants.PROTOCOL_PROMETHEUS and
             self._has_tls_container_refs(listener_dict)))

        if listener_dict and listener_dict.get('insert_headers'):
            self._validate_insert_headers(
                listener_dict['insert_headers'].keys(), listener_protocol)

        # Check for UDP/SCTP compatibility
        if (listener_protocol in (constants.PROTOCOL_UDP,
                                  lib_consts.PROTOCOL_SCTP) and
                self._is_tls_or_insert_header(listener_dict)):
            raise exceptions.ValidationException(
                detail=_("%s protocol listener does not "
                         "support TLS.") % listener_protocol)

        # Check for TLS disabled
        if (not CONF.api_settings.allow_tls_terminated_listeners and
                _can_tls_offload):
            if listener_protocol == constants.PROTOCOL_PROMETHEUS:
                msg = f"{listener_protocol} with TLS"
            else:
                msg = listener_protocol
            raise exceptions.DisabledOption(value=msg, option='protocol')

        # Check for PROMETHEUS listeners disabled
        if (not CONF.api_settings.allow_prometheus_listeners and
                listener_protocol == lib_consts.PROTOCOL_PROMETHEUS):
            raise exceptions.DisabledOption(
                value=lib_consts.PROTOCOL_PROMETHEUS, option='protocol')

        # Check for certs when not TLS offload capable
        if (not _can_tls_offload and
                self._has_tls_container_refs(listener_dict)):
            raise exceptions.ValidationException(detail=_(
                "Certificate container references are not allowed on "
                "%s protocol listeners.") % listener_protocol)

        # Make sure a base certificate exists if specifying a client ca
        if (listener_dict.get('client_ca_tls_certificate_id') and
            not (listener_dict.get('tls_certificate_id') or
                 listener_dict.get('sni_containers'))):
            raise exceptions.ValidationException(detail=_(
                "An SNI or default certificate container reference must "
                "be provided with a client CA container reference."))

        # Make sure a certificate container is specified for TLS protocols
        if (_can_tls_offload and
            not (listener_dict.get('tls_certificate_id') or
                 listener_dict.get('sni_containers'))):
            if listener_protocol == constants.PROTOCOL_PROMETHEUS:
                msg = f"{listener_protocol} with TLS"
            else:
                msg = listener_protocol
            raise exceptions.ValidationException(detail=_(
                "An SNI or default certificate container reference must "
                "be provided for %s protocol listeners.") % msg)

        # Make sure we have a client CA cert if they enable client auth
        if (listener_dict.get('client_authentication') !=
            constants.CLIENT_AUTH_NONE and not
                listener_dict.get('client_ca_tls_certificate_id')):
            raise exceptions.ValidationException(detail=_(
                "Client authentication setting %s requires a client CA "
                "container reference.") %
                listener_dict.get('client_authentication'))

        # Make sure we have a client CA if they specify a CRL
        if (listener_dict.get('client_crl_container_id') and
                not listener_dict.get('client_ca_tls_certificate_id')):
            raise exceptions.ValidationException(detail=_(
                "A client authentication CA reference is required to "
                "specify a client authentication revocation list."))

        # Check TLS cipher prohibit list
        if 'tls_ciphers' in listener_dict and listener_dict['tls_ciphers']:
            rejected_ciphers = validate.check_cipher_prohibit_list(
                listener_dict['tls_ciphers'])
            if rejected_ciphers:
                raise exceptions.ValidationException(detail=_(
                    'The following ciphers have been prohibited by an '
                    'administrator: ' + ', '.join(rejected_ciphers)))

        # Validate the TLS containers
        sni_containers = listener_dict.pop('sni_containers', [])
        tls_refs = [sni['tls_container_id'] for sni in sni_containers]
        if listener_dict.get('tls_certificate_id'):
            tls_refs.append(listener_dict.get('tls_certificate_id'))
        self._validate_tls_refs(tls_refs)

        # Validate the client CA cert and optional client CRL
        if listener_dict.get('client_ca_tls_certificate_id'):
            self._validate_client_ca_and_crl_refs(
                listener_dict.get('client_ca_tls_certificate_id'),
                listener_dict.get('client_crl_container_id', None),
                require_ca_bundle=(listener_dict.get(
                    'client_authentication_insecure_fallback') is True))

        # Validate that the L4 protocol (UDP, TCP or SCTP) is not already used
        # for the specified protocol_port in this load balancer
        pcontext = pecan_request.context
        query_filter = {
            'project_id': listener_dict['project_id'],
            'load_balancer_id': listener_dict['load_balancer_id'],
            'protocol_port': listener_dict['protocol_port']
        }

        # Get listeners on the same load balancer that use the same
        # protocol port
        db_listeners = self.repositories.listener.get_all_orm(
            lock_session, show_deleted=False,
            pagination_helper=pcontext.get(constants.PAGINATION_HELPER),
            **query_filter)[0]

        if db_listeners:
            l4_protocol = constants.L4_PROTOCOL_MAP[listener_protocol]

            # List supported protocols that share the same L4 protocol as our
            # new listener
            disallowed_protocols = [
                p
                for p, l4_p in constants.L4_PROTOCOL_MAP.items()
                if l4_p == l4_protocol
            ]

            for db_l in db_listeners:
                # Check if l4 protocol ports conflict
                if db_l.protocol in disallowed_protocols:
                    raise exceptions.DuplicateListenerEntry(
                        protocol=db_l.protocol,
                        port=listener_dict.get('protocol_port'))

        # Validate allowed CIDRs
        allowed_cidrs = listener_dict.get('allowed_cidrs', []) or []
        lb_id = listener_dict.get('load_balancer_id')
        lb_db = self.repositories.load_balancer.get_orm(
            lock_session, id=lb_id)
        vip_addresses = [lb_db.vip.ip_address]
        vip_addresses.extend([vip.ip_address for vip in lb_db.additional_vips])
        self._validate_cidr_compatible_with_vip(lb_db.vip,
                                                vip_addresses, allowed_cidrs)

        if _can_tls_offload:
            # Validate TLS version list
            validate.check_tls_version_list(listener_dict['tls_versions'])
            # Validate TLS versions against minimum
            validate.check_tls_version_min(listener_dict['tls_versions'])
            # Validate ALPN protocol list
            validate.check_alpn_protocols(listener_dict['alpn_protocols'])

        validate.check_hsts_options(listener_dict)

        if listener_dict.get('default_pool_id'):
            pool = self.repositories.pool.get_transport_for_update(
                lock_session, listener_dict['default_pool_id'])
            driver_utils.validate_tcp_pool_attachment(
                driver, pool.protocol, pool.tls_enabled,
                tcp_tls_termination=listener_dict.get('tcp_tls_termination'),
                hostname=pool.backend_tls_hostname,
                ca_ref=pool.ca_tls_certificate_id,
                system_ca=pool.backend_tls_system_ca)

        try:
            db_listener = self.repositories.listener.create(
                lock_session, **listener_dict)
            lock_session.flush()
            if sni_containers:
                for container in sni_containers:
                    sni_dict = {'listener_id': db_listener.id,
                                'tls_container_id': container.get(
                                    'tls_container_id')}
                    self.repositories.sni.create(lock_session, **sni_dict)
                lock_session.flush()
                # DB listener needs to be refreshed
                db_listener = self.repositories.listener.get_orm(
                    lock_session, id=db_listener.id)

            return db_listener
        except odb_exceptions.DBDuplicateEntry as e:
            raise exceptions.DuplicateListenerEntry(
                protocol=listener_dict.get('protocol'),
                port=listener_dict.get('protocol_port')) from e
        except odb_exceptions.DBError as e:
            raise exceptions.InvalidOption(value=listener_dict.get('protocol'),
                                           option='protocol') from e

    @wsme_pecan.wsexpose(listener_types.ListenerRootResponse,
                         body=listener_types.ListenerRootPOST, status_code=201)
    def post(self, listener_):
        """Creates a listener on a load balancer."""
        listener = listener_.listener
        context = pecan_request.context.get('octavia_context')

        load_balancer_id = listener.loadbalancer_id

        context.session.begin()
        try:
            listener.project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(context, listener.project_id,
                                       constants.RBAC_POST)

            if (listener.protocol == constants.PROTOCOL_UDP and
                    listener.default_pool_id):
                self.repositories.load_balancer.lock(
                    context.session, load_balancer_id)
                pool = (
                    self.repositories.pool.get_on_load_balancer_for_update(
                        context.session, load_balancer_id,
                        listener.project_id, listener.default_pool_id))
                if pool.udp_packet_drop is not None:
                    raise exceptions.ValidationException(detail=_(
                        'A managed UDP pool belongs to its existing '
                        'listener.'))

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            if self.repositories.check_quota_met(
                    context.session,
                    data_models.Listener,
                    listener.project_id):
                raise exceptions.QuotaException(
                    resource=data_models.Listener._name())

            listener_dict = db_prepare.create_listener(
                listener.to_dict(render_unsets=True), None)
            if listener.request_filter_sections is wtypes.Unset:
                listener_dict.pop('request_filter_sections', None)
            validate_policy_options_on_create(driver, listener_dict)

            if listener_dict['default_pool_id']:
                if (listener_dict.get('protocol') ==
                        lib_consts.PROTOCOL_PROMETHEUS):
                    raise exceptions.ListenerNoChildren(
                        protocol=lib_consts.PROTOCOL_PROMETHEUS)
                self._validate_pool(context.session, load_balancer_id,
                                    listener_dict['default_pool_id'],
                                    listener.protocol)

            self._test_lb_and_listener_statuses(
                context.session, lb_id=load_balancer_id)

            self._validate_otlp_tracing(
                context.session, driver, listener.protocol,
                listener_dict.get('otlp_tracing'), load_balancer_id,
                listener.project_id)

            if 'request_filter_sections' in listener_dict:
                self._validate_listener_request_filters(
                    context.session, driver, listener_dict['protocol'],
                    listener_dict['request_filter_sections'], load_balancer_id,
                    listener.project_id)

            db_listener = self._validate_create_listener(
                context.session, listener_dict, driver)

            # Prepare the data for the driver data model
            provider_listener = (
                driver_utils.db_listener_to_provider_listener(db_listener))

            # re-inject the sni container references lost due to SNI
            # being a separate table in the DB
            if listener.sni_container_refs != wtypes.Unset:
                provider_listener.sni_container_refs = (
                    listener.sni_container_refs)

            # Dispatch to the driver
            LOG.info("Sending create Listener %s to provider %s",
                     db_listener.id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.listener_create, provider_listener)

            context.session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                context.session.rollback()

        with context.session.begin():
            listener = self._get_db_listener(context.session, db_listener.id)
            result = listener_types.ListenerResponse.from_db_obj(listener)

        return listener_types.ListenerRootResponse(listener=result)

    def _graph_create(self, lock_session, listener_dict, driver,
                      l7policies=None, pool_name_ids=None):
        load_balancer_id = listener_dict['load_balancer_id']
        listener_dict = db_prepare.create_listener(
            listener_dict, load_balancer_id)
        l7policies = listener_dict.pop('l7policies', l7policies)
        if listener_dict.get('default_pool_id'):
            if listener_dict.get('protocol') == lib_consts.PROTOCOL_PROMETHEUS:
                raise exceptions.ListenerNoChildren(
                    protocol=lib_consts.PROTOCOL_PROMETHEUS)
            self._validate_pool(lock_session, load_balancer_id,
                                listener_dict['default_pool_id'],
                                listener_dict['protocol'])
        db_listener = self._validate_create_listener(
            lock_session, listener_dict, driver)

        if (listener_dict.get('protocol') == lib_consts.PROTOCOL_PROMETHEUS and
                l7policies):
            raise exceptions.ListenerNoChildren(
                protocol=lib_consts.PROTOCOL_PROMETHEUS)

        for l7p in l7policies:
            l7p['project_id'] = db_listener.project_id
            l7p['load_balancer_id'] = load_balancer_id
            l7p['listener_id'] = db_listener.id
            redirect_pool = l7p.pop('redirect_pool', None)
            if redirect_pool:
                pool_name = redirect_pool['name']
                pool_id = pool_name_ids.get(pool_name)
                if not pool_id:
                    raise exceptions.SingleCreateDetailsMissing(
                        type='Pool', name=pool_name)
                l7p['redirect_pool_id'] = pool_id
            l7policy.L7PolicyController()._graph_create(lock_session, l7p)

        return db_listener

    def _validate_listener_PUT(self, listener, db_listener):
        _can_tls_offload = (
            db_listener.tcp_tls_termination or
            db_listener.protocol == constants.PROTOCOL_TERMINATED_HTTPS or
            (db_listener.protocol == constants.PROTOCOL_PROMETHEUS and
             self._has_tls_container_refs(listener.to_dict())))

        # TODO(rm_work): Do we need something like this? What do we do on an
        # empty body for a PUT?
        if not listener:
            raise exceptions.ValidationException(
                detail='No listener object supplied.')

        # Check for UDP/SCTP compatibility
        if (db_listener.protocol in (constants.PROTOCOL_UDP,
                                     lib_consts.PROTOCOL_SCTP) and
                self._is_tls_or_insert_header(listener.to_dict())):
            raise exceptions.ValidationException(detail=_(
                "%s protocol listener does not support TLS or header "
                "insertion.") % db_listener.protocol)

        # Check for certs when not TLS offload capable
        if (not _can_tls_offload and
                self._has_tls_container_refs(listener.to_dict())):
            raise exceptions.ValidationException(detail=_(
                "Certificate container references are not allowed on "
                "%s protocol listeners.") % db_listener.protocol)

        if not db_listener.tcp_tls_termination:
            self._validate_listener_tls_references(listener, db_listener)

        if listener.insert_headers:
            self._validate_insert_headers(
                list(listener.insert_headers.keys()), db_listener.protocol)

        # Validate allowed CIDRs
        if (listener.allowed_cidrs and listener.allowed_cidrs != wtypes.Unset):
            vip_addresses = [db_listener.load_balancer.vip.ip_address]
            vip_addresses.extend(
                [vip.ip_address
                 for vip in db_listener.load_balancer.additional_vips]
            )
            self._validate_cidr_compatible_with_vip(
                db_listener.load_balancer.vip,
                vip_addresses, listener.allowed_cidrs)

        # Check TLS cipher prohibit list
        if listener.tls_ciphers:
            rejected_ciphers = validate.check_cipher_prohibit_list(
                listener.tls_ciphers)
            if rejected_ciphers:
                raise exceptions.ValidationException(detail=_(
                    'The following ciphers have been prohibited by an '
                    'administrator: ' + ', '.join(rejected_ciphers)))

        if listener.tls_versions is not wtypes.Unset:
            # Validate TLS versions
            validate.check_tls_version_list(listener.tls_versions)
            validate.check_tls_version_min(listener.tls_versions)

        if listener.alpn_protocols is not wtypes.Unset:
            # Validate ALPN protocol list
            validate.check_alpn_protocols(listener.alpn_protocols)

        validate.check_hsts_options_put(listener, db_listener)

    def _validate_listener_tls_references(self, listener, db_listener):
        # Make sure we have a client CA cert if they enable client auth
        if (listener.client_authentication not in
                (wtypes.Unset, constants.CLIENT_AUTH_NONE) and
            not (db_listener.client_ca_tls_certificate_id or
                 listener.client_ca_tls_container_ref)):
            raise exceptions.ValidationException(detail=_(
                "Client authentication setting %s requires a client CA "
                "container reference.") %
                listener.client_authentication)

        sni_containers = listener.sni_container_refs or []
        tls_refs = list(sni_containers)
        if listener.default_tls_container_ref:
            tls_refs.append(listener.default_tls_container_ref)
        self._validate_tls_refs(tls_refs)

        ca_ref = None
        if (listener.client_ca_tls_container_ref and
                listener.client_ca_tls_container_ref != wtypes.Unset):
            ca_ref = listener.client_ca_tls_container_ref
        elif db_listener.client_ca_tls_certificate_id:
            ca_ref = db_listener.client_ca_tls_certificate_id

        crl_ref = None
        if (listener.client_crl_container_ref and
                listener.client_crl_container_ref != wtypes.Unset):
            crl_ref = listener.client_crl_container_ref
        elif db_listener.client_crl_container_id:
            crl_ref = db_listener.client_crl_container_id

        if crl_ref and not ca_ref:
            raise exceptions.ValidationException(detail=_(
                "A client authentication CA reference is required to "
                "specify a client authentication revocation list."))

        if ca_ref or crl_ref:
            fallback = listener.client_authentication_insecure_fallback
            if fallback is wtypes.Unset:
                fallback = db_listener.client_authentication_insecure_fallback
            self._validate_client_ca_and_crl_refs(
                ca_ref, crl_ref, require_ca_bundle=fallback is True)

    def _validate_tcp_tls_update(self, session, listener, updates, driver,
                                 reopening):
        if ('tcp_tls_termination' in updates and
                updates['tcp_tls_termination'] is not
                listener.tcp_tls_termination):
            raise exceptions.ValidationException(detail=_(
                'tcp_tls_termination can only be set at listener creation.'))
        pool_id = updates.get('default_pool_id', listener.default_pool_id)
        mixed_mode = listener.tcp_tls_mixed_mode
        if updates.pop('tcp_tls_mixed_mode', mixed_mode) is not mixed_mode:
            raise exceptions.ValidationException(detail=_(
                'tcp_tls_mixed_mode can only be set at listener creation.'))
        if mixed_mode:
            validate.validate_tcp_tls_mixed_default_pool(pool_id)
        new_pool = pool_id and pool_id != listener.default_pool_id
        if not listener.tcp_tls_termination:
            if new_pool:
                driver_utils.validate_existing_tcp_pool_attachment(
                    driver, self.repositories.l7policy, session, listener,
                    pool_id)
            if reopening:
                driver_utils.require_active_tls_sni_weighted_policies(
                    driver, self.repositories.l7policy, session, listener.id)
            return

        tls_fields = {
            'tls_certificate_id', 'sni_containers',
            'client_ca_tls_certificate_id', 'client_authentication',
            'client_crl_container_id', 'tls_ciphers', 'tls_versions',
            'alpn_protocols',
        }
        admits_pool = pool_id and (reopening or new_pool)
        checks_tls = reopening or tls_fields.intersection(updates)
        if checks_tls or admits_pool:
            driver_utils.require_tcp_tls_termination(driver)
            if mixed_mode:
                driver_utils.require_tcp_tls_mixed_mode(driver)
        if checks_tls:
            server_cert = updates.get('tls_certificate_id',
                                      listener.tls_certificate_id)
            if not server_cert:
                raise exceptions.ValidationException(detail=_(
                    'tcp_tls_termination requires default_tls_container_ref.'))
            if 'sni_containers' in updates:
                sni_certs = updates['sni_containers'] or []
            else:
                sni_certs = self.repositories.sni.get_refs_for_update(
                    session, listener.id)
            ca_ref = updates.get('client_ca_tls_certificate_id',
                                 listener.client_ca_tls_certificate_id)
            crl_ref = updates.get('client_crl_container_id',
                                  listener.client_crl_container_id)
            client_auth = updates.get('client_authentication',
                                      listener.client_authentication)
            if ((crl_ref or client_auth != constants.CLIENT_AUTH_NONE) and
                    not ca_ref):
                raise exceptions.ValidationException(detail=_(
                    'Client authentication and revocation lists require a '
                    'client CA certificate reference.'))
            self._validate_tls_refs([server_cert, *sni_certs])
            if ca_ref:
                self._validate_client_ca_and_crl_refs(ca_ref, crl_ref)

        policy_repo = self.repositories.l7policy
        if admits_pool:
            driver_utils.validate_existing_tcp_pool_attachment(
                driver, policy_repo, session, listener, pool_id,
                skip_disabled_pool=not new_pool)
        if reopening:
            if (mixed_mode and policy_repo.has_enabled_tls_sni_suffix_rule(
                    session, listener_id=listener.id,
                    tcp_tls_passthrough=True)):
                driver_utils.require_tls_sni_suffix(driver)
            driver_utils.require_active_tls_sni_weighted_policies(
                driver, policy_repo, session, listener.id)
            for pool in policy_repo.get_active_protected_tcp_policy_pools(
                    session, listener.id):
                driver_utils.validate_tcp_pool_attachment(
                    driver, pool.protocol, pool.tls_enabled,
                    tcp_tls_termination=True,
                    hostname=pool.backend_tls_hostname,
                    ca_ref=pool.ca_tls_certificate_id,
                    system_ca=pool.backend_tls_system_ca)

    def _validate_otlp_tracing(self, session, driver, protocol, tracing,
                               lb_id, project_id):
        if tracing is None:
            return
        if protocol not in (constants.PROTOCOL_HTTP,
                            constants.PROTOCOL_TERMINATED_HTTPS):
            raise exceptions.ValidationException(detail=_(
                'OTLP tracing requires an HTTP or TERMINATED_HTTPS listener.'))
        driver_utils.require_listener_otlp_tracing(
            driver, sampling='sampling' in tracing,
            attributes='attributes' in tracing)
        pool = self.repositories.pool.get_on_load_balancer_for_update(
            session, lb_id, project_id, tracing['collector_pool_id'])
        validate.validate_otlp_collector_transport(
            pool.protocol, pool.backend_h2c, pool.backend_tls_require_h2,
            pool.tls_enabled, pool.alpn_protocols)

    @staticmethod
    def _is_otlp_withdrawal(listener, tracing):
        current = listener.otlp_tracing
        if tracing is None:
            return (current is not None or listener.otlp_tracing_status in (
                constants.PENDING_UPDATE, constants.ERROR))
        return (current is not None and 'attributes' in current and
                tracing == {key: value for key, value in current.items()
                            if key != 'attributes'})

    def _validate_listener_request_filters(
            self, session, driver, protocol, sections, lb_id, project_id):
        if sections is None:
            raise exceptions.ValidationException(detail=_(
                'request_filter_sections must be an array.'))
        if sections:
            driver_utils.require_listener_request_filters(driver)
            listener_request_filters.validate_listener(protocol, sections)
            self.repositories.listener.validate_request_filter_pools(
                session, sections, lb_id, project_id)

    def _validate_https_listener_update(
            self, session, driver, db_listener, updates):
        old_hosts = db_listener.https_virtual_hosts
        hosts = updates.get('https_virtual_hosts', old_hosts)
        if old_hosts is None and hosts is None:
            return
        if hosts is None:
            raise exceptions.ValidationException(detail=_(
                'Replace the listener to remove HTTPS listener isolation.'))

        hosts = validate.https_virtual_hosts(hosts)
        if 'https_virtual_hosts' in updates:
            updates['https_virtual_hosts'] = hosts
        if hosts != old_hosts or (updates.get('enabled') is True and
                                  not db_listener.enabled):
            driver_utils.require_https_listener_isolation(driver)
        validate.validate_https_listener(
            db_listener.protocol,
            updates.get('tls_certificate_id', db_listener.tls_certificate_id),
            updates.get('sni_containers', db_listener.sni_containers),
            updates.get('default_pool_id', db_listener.default_pool_id),
            updates.get('default_http_response',
                        db_listener.default_http_response))
        if hosts != old_hosts:
            policy_repo = self.repositories.l7policy
            for hostname in policy_repo.get_https_listener_hostnames(
                    session, db_listener.id):
                validate.validate_https_policy_hostname(hosts, hostname)
            removed = set(old_hosts or ()) - set(hosts)
            if removed and updates.get('enabled', db_listener.enabled):
                driver_utils.require_no_active_request_transforms(
                    driver, policy_repo, session, listener_id=db_listener.id,
                    removed_https_hosts=removed)

    @staticmethod
    def _validate_frontend_client_auth_fallback_update(
            listener, updates, driver, reopening):
        field = 'client_authentication_insecure_fallback'
        previous = listener.client_authentication_insecure_fallback
        if updates.get(field, previous) is not True:
            return

        ca_ref = updates.get('client_ca_tls_certificate_id',
                             listener.client_ca_tls_certificate_id)
        client_auth = updates.get('client_authentication',
                                  listener.client_authentication)
        server_cert = updates.get('tls_certificate_id',
                                  listener.tls_certificate_id)
        sni_certs = updates.get('sni_containers', listener.sni_containers)
        _validate_frontend_client_auth_fallback(
            listener.protocol, client_auth, ca_ref, server_cert, sni_certs)
        if (reopening or
                {field, 'client_ca_tls_certificate_id',
                 'client_crl_container_id',
                 'client_authentication', 'tls_certificate_id',
                 'sni_containers'}.intersection(updates)):
            driver_utils.require_frontend_client_auth_fallback(driver)

    def _set_default_on_none(self, listener, tcp_tls_termination=False):
        """Reset settings to their default values if None/null was passed in

        A None/null value can be passed in to clear a value. PUT values
        that were not provided by the user have a type of wtypes.UnsetType.
        If the user is attempting to clear values, they should either
        be set to None (for example in the name field) or they should be
        reset to their default values.
        This method is intended to handle those values that need to be set
        back to a default value.
        """
        if listener.connection_limit is None:
            listener.connection_limit = constants.DEFAULT_CONNECTION_LIMIT
        if listener.timeout_client_data is None:
            listener.timeout_client_data = (
                CONF.haproxy_amphora.timeout_client_data)
        if listener.timeout_member_connect is None:
            listener.timeout_member_connect = (
                CONF.haproxy_amphora.timeout_member_connect)
        if listener.timeout_member_data is None:
            listener.timeout_member_data = (
                CONF.haproxy_amphora.timeout_member_data)
        if listener.timeout_tcp_inspect is None:
            listener.timeout_tcp_inspect = (
                CONF.haproxy_amphora.timeout_tcp_inspect)
        if listener.client_authentication is None:
            listener.client_authentication = constants.CLIENT_AUTH_NONE
        if listener.tls_ciphers is None:
            listener.tls_ciphers = CONF.api_settings.default_listener_ciphers
        if listener.tls_versions is None:
            listener.tls_versions = (
                CONF.api_settings.default_listener_tls_versions)
        if listener.alpn_protocols is None and not tcp_tls_termination:
            listener.alpn_protocols = (
                CONF.api_settings.default_listener_alpn_protocols)
        if listener.hsts_include_subdomains is None:
            listener.hsts_include_subdomains = False
        if listener.hsts_preload is None:
            listener.hsts_preload = False

    @wsme_pecan.wsexpose(listener_types.ListenerRootResponse, wtypes.text,
                         body=listener_types.ListenerRootPUT, status_code=200)
    def put(self, id, listener_: listener_types.ListenerRootPUT):
        """Updates a listener on a load balancer."""
        listener = listener_.listener
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_listener = self._get_db_listener(context.session, id,
                                                show_deleted=False)
            load_balancer_id = db_listener.load_balancer_id

            project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(context, project_id, constants.RBAC_PUT)

            self._validate_listener_PUT(listener, db_listener)
            self._set_default_on_none(listener,
                                      db_listener.tcp_tls_termination)

            if listener.default_pool_id:
                if db_listener.protocol == lib_consts.PROTOCOL_PROMETHEUS:
                    raise exceptions.ListenerNoChildren(
                        protocol=lib_consts.PROTOCOL_PROMETHEUS)
                self._validate_pool(context.session, load_balancer_id,
                                    listener.default_pool_id,
                                    db_listener.protocol)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            listener_dict = listener.to_dict(render_unsets=False)
            withdrawing = (
                listener_dict.keys() == {'otlp_tracing'} and
                self._is_otlp_withdrawal(db_listener,
                                         listener_dict['otlp_tracing']))
            self._test_lb_and_listener_statuses(
                context.session, load_balancer_id, allow_error=withdrawing)
            db_listener = self.repositories.listener.get_for_update(
                context.session, id, show_deleted=False)
            if (withdrawing and listener_dict['otlp_tracing'] is not None and
                    not self._is_otlp_withdrawal(
                        db_listener, listener_dict['otlp_tracing'])):
                # Only a withdrawal of the current profile may bypass ERROR.
                raise exceptions.ImmutableObject(
                    resource=data_models.Listener._name(), id=id)

            new_pool_id = listener_dict.get('default_pool_id',
                                            db_listener.default_pool_id)
            if (db_listener.protocol == constants.PROTOCOL_UDP and
                    new_pool_id != db_listener.default_pool_id):
                for pool_id in (db_listener.default_pool_id, new_pool_id):
                    if pool_id is None:
                        continue
                    current = self.repositories.pool.get_transport_for_update(
                        context.session, pool_id)
                    if current.udp_packet_drop is not None:
                        raise exceptions.ValidationException(detail=_(
                            'A managed UDP pool belongs to its existing '
                            'listener.'))
            self._validate_https_listener_update(
                context.session, driver, db_listener, listener_dict)
            default_http_response = listener_dict.get(
                'default_http_response', db_listener.default_http_response)
            reopening = (listener_dict.get('enabled') is True and
                         not db_listener.enabled)
            if 'otlp_tracing' in listener_dict or reopening:
                self._validate_otlp_tracing(
                    context.session, driver, db_listener.protocol,
                    listener_dict.get('otlp_tracing',
                                      db_listener.otlp_tracing),
                    load_balancer_id, project_id)
            if ('request_filter_sections' in listener_dict or
                    (reopening and db_listener.request_filter_sections)):
                self._validate_listener_request_filters(
                    context.session, driver, db_listener.protocol,
                    listener_dict.get('request_filter_sections',
                                      db_listener.request_filter_sections),
                    load_balancer_id, project_id)
            self._validate_frontend_client_auth_fallback_update(
                db_listener, listener_dict, driver, reopening)
            self._validate_tcp_tls_update(context.session, db_listener,
                                          listener_dict, driver, reopening)
            if (reopening or 'default_http_response' in listener_dict or
                    'default_pool_id' in listener_dict):
                validate.validate_default_http_response(
                    db_listener.protocol, default_http_response,
                    listener_dict.get('default_pool_id',
                                      db_listener.default_pool_id))
            if (listener_dict.get('default_http_response') is not None or
                    (reopening and default_http_response is not None)):
                driver_utils.require_fixed_http_responses(driver)
            if reopening:
                policy_repo = self.repositories.l7policy
                if db_listener.protocol in (
                        constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
                    driver_utils.require_active_http_l7rule_capabilities(
                        driver, policy_repo, context.session, listener_id=id)
                policies = policy_repo.get_enabled_gateway_policies(
                    context.session, id, db_listener.protocol)
                for action, request_ops, response_ops in policies:
                    if (db_listener.protocol == constants.PROTOCOL_TCP and
                            action ==
                            constants.L7POLICY_ACTION_WEIGHTED_TARGETS):
                        # The TCP reopening path checks active SNI rules
                        # together with the target pools.
                        continue
                    driver_utils.require_gateway_policy_action(
                        driver, action, db_listener.protocol,
                        request_header_operations=request_ops,
                        response_header_operations=response_ops,
                        tcp_tls_termination=db_listener.tcp_tls_termination)
                driver_utils.require_no_active_request_transforms(
                    driver, policy_repo, context.session, listener_id=id,
                    reopening='listener')
                if (not db_listener.tcp_tls_termination and
                        driver_utils.uses_tls_sni_policy_path(
                            driver, db_listener.protocol) and
                        policy_repo.has_enabled_tls_sni_suffix_rule(
                            context.session, listener_id=id)):
                    driver_utils.require_tls_sni_suffix(driver)

            db_listener.provisioning_status = constants.PENDING_UPDATE

            # Prepare the data for the driver data model
            provider_listener_dict = (
                driver_utils.listener_dict_to_provider_dict(
                    dict(listener_dict, id=id),
                    clear_client_auth_fallback=(
                        db_listener.client_authentication_insecure_fallback
                        is True and listener_dict.get(
                            'client_authentication_insecure_fallback')
                        is False)))

            # Also prepare the baseline object data
            old_provider_listener = (
                driver_utils.db_listener_to_provider_listener(db_listener,
                                                              for_delete=True))

            # Dispatch to the driver
            LOG.info("Sending update Listener %s to provider %s", id,
                     driver.name)
            driver_utils.call_provider(
                driver.name, driver.listener_update,
                old_provider_listener,
                driver_dm.Listener.from_dict(provider_listener_dict))

            # Update the database to reflect what the driver just accepted
            self.repositories.listener.update(
                context.session, id, **listener_dict)

        # Force SQL alchemy to query the DB, otherwise we get inconsistent
        # results
        context.session.expire_all()

        with context.session.begin():
            listener = self._get_db_listener(context.session, id)
            result = listener_types.ListenerResponse.from_db_obj(listener)

        return listener_types.ListenerRootResponse(listener=result)

    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, id):
        """Deletes a listener from a load balancer."""
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_listener = self._get_db_listener(context.session, id,
                                                show_deleted=False)
            load_balancer_id = db_listener.load_balancer_id

            project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(
                context,
                project_id,
                constants.RBAC_DELETE
            )

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            self._test_lb_and_listener_statuses(
                context.session, load_balancer_id,
                id=id, listener_status=constants.PENDING_DELETE)

            LOG.info("Sending delete Listener %s to provider %s", id,
                     driver.name)
            provider_listener = (
                driver_utils.db_listener_to_provider_listener(
                    db_listener, for_delete=True))
            driver_utils.call_provider(driver.name, driver.listener_delete,
                                       provider_listener)

    @pecan_expose()
    def _lookup(self, id, *remainder):
        """Overridden pecan _lookup method for custom routing.

        Currently it checks if this was a stats request and routes
        the request to the StatsController.
        """
        if id and remainder and remainder[0] == 'stats':
            return StatisticsController(listener_id=id), remainder[1:]
        if id and remainder and remainder[0] == 'l7policy_activation':
            return l7policy.L7PolicyActivationController(id), remainder[1:]
        return None


class StatisticsController(base.BaseController, stats.StatsMixin):
    RBAC_TYPE = constants.RBAC_LISTENER

    def __init__(self, listener_id):
        super().__init__()
        self.id = listener_id

    @wsme_pecan.wsexpose(listener_types.StatisticsRootResponse, wtypes.text,
                         status_code=200)
    def get(self):
        context = pecan_request.context.get('octavia_context')

        with context.session.begin():
            listener = self._get_db_listener(
                context.session,
                self.id,
                show_deleted=False
            )
            if not listener:
                LOG.info("Listener %s not found.", id)
                raise exceptions.NotFound(
                    resource=data_models.Listener._name(),
                    id=id)

            self._auth_validate_action(context, listener.project_id,
                                       constants.RBAC_GET_STATS)

            listener_stats = self.get_listener_stats(context.session, self.id)

            result = (
                listener_types.ListenerStatisticsResponse
                .from_db_obj(listener_stats)
            )

        return listener_types.StatisticsRootResponse(stats=result)
