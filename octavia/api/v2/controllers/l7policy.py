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
from octavia.api.v2.controllers import l7rule
from octavia.api.v2.types import l7policy as l7policy_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import validate
from octavia.db import prepare as db_prepare
from octavia.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def validate_policy_headers(policy, protocol, driver, old_policy=None):
    for field, require in (
            ('request_header_operations',
             driver_utils.require_request_header_operations),
            ('response_header_operations',
             driver_utils.require_response_header_operations)):
        if field not in policy:
            continue
        operations = policy[field]
        clearing = (not operations and old_policy is not None and
                    getattr(old_policy, field) is not None and
                    getattr(driver, 'supports_' + field, False) is True)
        if not clearing:
            require(driver)
        if operations:
            validate.validate_header_protocol(protocol)


class L7PolicyController(base.BaseController):
    RBAC_TYPE = constants.RBAC_L7POLICY

    def __init__(self):
        super().__init__()

    @wsme_pecan.wsexpose(l7policy_types.L7PolicyRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get(self, id, fields=None):
        """Gets a single l7policy's details."""
        context = pecan_request.context.get('octavia_context')

        with context.session.begin():
            l7policy = self._get_db_l7policy(
                context.session,
                id,
                show_deleted=False
            )

            self._auth_validate_action(context, l7policy.project_id,
                                       constants.RBAC_GET_ONE)

            result = l7policy_types.L7PolicyResponse.from_db_obj(l7policy)

        if fields is not None:
            result = self._filter_fields([result], fields)[0]
        return l7policy_types.L7PolicyRootResponse(l7policy=result)

    @wsme_pecan.wsexpose(l7policy_types.L7PoliciesRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get_all(self, project_id=None, fields=None):
        """Lists all l7policies of a listener."""
        pcontext = pecan_request.context
        context = pcontext.get('octavia_context')

        query_filter = self._auth_get_all(context, project_id)

        with context.session.begin():
            l7policies, links = self.repositories.l7policy.get_all_API_list(
                context.session,
                show_deleted=False,
                pagination_helper=pcontext.get(constants.PAGINATION_HELPER),
                **query_filter
            )

            result = [
                l7policy_types.L7PolicyResponse.from_db_obj(l7policy)
                for l7policy in l7policies
            ]

        if fields is not None:
            result = self._filter_fields(result, fields)
        return l7policy_types.L7PoliciesRootResponse(
            l7policies=result, l7policies_links=links)

    def _test_lb_and_listener_statuses(self, session, lb_id, listener_ids):
        """Verify load balancer is in a mutable state."""
        if not self.repositories.test_and_set_lb_and_listeners_prov_status(
                session, lb_id,
                constants.PENDING_UPDATE, constants.PENDING_UPDATE,
                listener_ids=listener_ids):
            LOG.info("L7Policy cannot be created or modified because the "
                     "Load Balancer is in an immutable state")
            raise exceptions.ImmutableObject(resource='Load Balancer',
                                             id=lb_id)

    def _validate_redirect_pool_protocol(self, session, listener, pool_id):
        pool = self.repositories.l7policy.get_redirect_pool_for_update(
            session, listener, pool_id)
        self._validate_protocol(listener.protocol, pool.protocol)

    def _validate_create_l7policy(self, lock_session, l7policy_dict):
        try:
            # Set the default HTTP redirect code here so it's explicit
            if ((l7policy_dict.get('redirect_url') or
                l7policy_dict.get('redirect_prefix')) and
                    not l7policy_dict.get('redirect_http_code')):
                l7policy_dict['redirect_http_code'] = 302

            return self.repositories.l7policy.create(lock_session,
                                                     **l7policy_dict)
        except odb_exceptions.DBDuplicateEntry as e:
            raise exceptions.IDAlreadyExists() from e
        except odb_exceptions.DBReferenceError as e:
            raise exceptions.InvalidOption(value=l7policy_dict.get(e.key),
                                           option=e.key) from e
        except odb_exceptions.DBError as e:
            raise exceptions.APIException() from e

    @wsme_pecan.wsexpose(l7policy_types.L7PolicyRootResponse,
                         body=l7policy_types.L7PolicyRootPOST, status_code=201)
    def post(self, l7policy_):
        """Creates a l7policy on a listener."""
        l7policy = l7policy_.l7policy
        context = pecan_request.context.get('octavia_context')

        # Verify the parent listener exists
        listener_id = l7policy.listener_id
        with context.session.begin():
            listener = self._get_db_listener(
                context.session, listener_id)
            load_balancer_id = listener.load_balancer_id
            l7policy.project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(context, l7policy.project_id,
                                       constants.RBAC_POST)

            # PROMETHEUS listeners cannot have l7policies attached
            if listener.protocol == lib_consts.PROTOCOL_PROMETHEUS:
                raise exceptions.ListenerNoChildren(
                    protocol=lib_consts.PROTOCOL_PROMETHEUS)

            if l7policy.rules:
                raise exceptions.ValidationException(detail=_(
                    'Create the policy first, then use POST '
                    '/v2/lbaas/l7policies/{id}/rules.'))

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

        lock_session = context.session
        lock_session.begin()
        try:
            if self.repositories.check_quota_met(
                    lock_session,
                    data_models.L7Policy,
                    l7policy.project_id):
                raise exceptions.QuotaException(
                    resource=data_models.L7Policy._name())

            l7policy_dict = db_prepare.create_l7policy(
                l7policy.to_dict(render_unsets=True),
                load_balancer_id, listener_id)
            driver_utils.require_gateway_policy_action(
                driver, l7policy_dict['action'], listener.protocol,
                tcp_tls_termination=listener.tcp_tls_termination)
            validate_policy_headers(
                l7policy_dict, listener.protocol, driver)

            self._test_lb_and_listener_statuses(
                lock_session, lb_id=load_balancer_id,
                listener_ids=[listener_id])
            listener = self.repositories.listener.get_for_update(
                lock_session, listener_id, show_deleted=False)
            hostname = validate.validate_https_policy_hostname(
                listener.https_virtual_hosts,
                l7policy_dict.get('https_listener_hostname'))
            if hostname is not None:
                driver_utils.require_https_listener_isolation(driver)
                l7policy_dict['https_listener_hostname'] = hostname
            pool_id = l7policy_dict.get('redirect_pool_id')
            if driver_utils.uses_tls_sni_policy_path(
                    driver, listener.protocol, listener.tcp_tls_termination):
                self.repositories.l7policy.validate_tcp_redirect_pool(
                    lock_session, listener, pool_id)
            elif pool_id:
                self._validate_redirect_pool_protocol(
                    lock_session, listener, pool_id)
            db_l7policy = self._validate_create_l7policy(
                lock_session, l7policy_dict)

            # Prepare the data for the driver data model
            provider_l7policy = (
                driver_utils.db_l7policy_to_provider_l7policy(db_l7policy))

            # Dispatch to the driver
            LOG.info("Sending create L7 Policy %s to provider %s",
                     db_l7policy.id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.l7policy_create, provider_l7policy)

            lock_session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                lock_session.rollback()

        with context.session.begin():
            l7policy = self._get_db_l7policy(context.session, db_l7policy.id)
            result = l7policy_types.L7PolicyResponse.from_db_obj(l7policy)

        return l7policy_types.L7PolicyRootResponse(l7policy=result)

    def _graph_create(self, lock_session, policy_dict):
        load_balancer_id = policy_dict.pop('load_balancer_id', None)
        listener_id = policy_dict['listener_id']
        policy_dict = db_prepare.create_l7policy(
            policy_dict, load_balancer_id, listener_id)
        rules = policy_dict.pop('l7rules', []) or []
        db_policy = self._validate_create_l7policy(lock_session, policy_dict)

        new_rules = []
        for r in rules:
            r['project_id'] = db_policy.project_id
            new_rules.append(
                l7rule.L7RuleController(db_policy.id)._graph_create(
                    lock_session, r))

        db_policy.l7rules = new_rules
        return db_policy

    @wsme_pecan.wsexpose(l7policy_types.L7PolicyRootResponse,
                         wtypes.text, body=l7policy_types.L7PolicyRootPUT,
                         status_code=200)
    def put(self, id, l7policy_):
        """Updates a l7policy."""
        l7policy = l7policy_.l7policy
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_l7policy = self._get_db_l7policy(context.session, id,
                                                show_deleted=False)
            load_balancer_id, listener_id = (
                self._get_listener_and_loadbalancer_id(db_l7policy))
            project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(context, project_id, constants.RBAC_PUT)

            lock_session = context.session

            self._test_lb_and_listener_statuses(lock_session,
                                                lb_id=load_balancer_id,
                                                listener_ids=[listener_id])

            db_l7policy = self.repositories.l7policy.get_for_update(
                lock_session, id, show_deleted=False)

            l7policy_dict = validate.sanitize_l7policy_api_args(
                l7policy.to_dict(render_unsets=False), old_policy=db_l7policy)

            listener = self.repositories.listener.get_for_update(
                lock_session, db_l7policy.listener_id, show_deleted=False)
            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)
            action = l7policy_dict.get('action', db_l7policy.action)
            routing_changed = {'action', 'fixed_response', 'targets',
                               'redirect_request'}
            if action == constants.L7POLICY_ACTION_REDIRECT_REQUEST:
                routing_changed.add('redirect_http_code')
            tcp_policy = driver_utils.uses_tls_sni_policy_path(
                driver, listener.protocol, listener.tcp_tls_termination)
            pool_id = l7policy_dict.get('redirect_pool_id')
            if tcp_policy:
                if l7policy.redirect_pool_id is None:
                    raise exceptions.ValidationException(detail=_(
                        'A TCP listener policy requires a redirect pool.'))
                if pool_id:
                    routing_changed.add('redirect_pool_id')
            elif pool_id:
                self._validate_redirect_pool_protocol(
                    lock_session, listener, pool_id)
            enabled = l7policy_dict.get('enabled', db_l7policy.enabled)
            reopening = enabled and not db_l7policy.enabled
            hostname = validate.validate_https_policy_hostname(
                listener.https_virtual_hosts, l7policy_dict.get(
                    'https_listener_hostname',
                    db_l7policy.https_listener_hostname))
            if 'https_listener_hostname' in l7policy_dict:
                l7policy_dict['https_listener_hostname'] = hostname
            https_routing_changed = routing_changed | {
                'position', 'redirect_pool_id', 'redirect_url',
                'redirect_prefix', 'redirect_http_code',
                'request_header_operations', 'response_header_operations',
                'https_listener_hostname'}
            if (hostname is not None and
                    (reopening or
                     https_routing_changed.intersection(l7policy_dict))):
                driver_utils.require_https_listener_isolation(driver)
            policy_repo = self.repositories.l7policy
            if reopening and not tcp_policy:
                driver_utils.require_active_http_l7rule_capabilities(
                    driver, policy_repo, lock_session, policy_id=id)
            activates_policy = enabled and (
                reopening or
                l7policy_dict.get('position', db_l7policy.position) !=
                db_l7policy.position)
            if activates_policy or routing_changed.intersection(l7policy_dict):
                retained_headers = {
                    field: getattr(db_l7policy, field)
                    for field in ('request_header_operations',
                                  'response_header_operations')
                    if field not in l7policy_dict}
                driver_utils.require_gateway_policy_action(
                    driver, action, listener.protocol,
                    tcp_tls_termination=listener.tcp_tls_termination,
                    **retained_headers)
                if tcp_policy:
                    if (not listener.tcp_tls_termination and
                            policy_repo.has_enabled_tls_sni_suffix_rule(
                                lock_session, policy_id=id)):
                        driver_utils.require_tls_sni_suffix(driver)
                    target = l7policy_dict.get(
                        'redirect_pool_id', db_l7policy.redirect_pool_id)
                    self.repositories.l7policy.validate_tcp_redirect_pool(
                        lock_session, listener, target)
            validate_policy_headers(
                l7policy_dict, listener.protocol, driver,
                old_policy=db_l7policy)

            # Prepare the data for the driver data model
            provider_l7policy_dict = (
                driver_utils.l7policy_dict_to_provider_dict(
                    dict(l7policy_dict, id=id)))

            # Also prepare the baseline object data
            old_provider_l7policy = (
                driver_utils.db_l7policy_to_provider_l7policy(db_l7policy))

            update_values = dict(
                l7policy_dict, provisioning_status=constants.PENDING_UPDATE)
            persist_before_dispatch = (any(
                policy_action in (constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
                                  constants.L7POLICY_ACTION_REDIRECT_REQUEST)
                for policy_action in (action, db_l7policy.action)))
            if persist_before_dispatch:
                # Validate target pool references before sending them to a
                # provider. The write rolls back if the provider rejects it.
                self.repositories.l7policy.update(
                    lock_session, id, **update_values)

            # Dispatch to the driver
            LOG.info("Sending update L7 Policy %s to provider %s",
                     id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.l7policy_update,
                old_provider_l7policy,
                driver_dm.L7Policy.from_dict(provider_l7policy_dict))

            if not persist_before_dispatch:
                self.repositories.l7policy.update(
                    lock_session, id, **update_values)

        # Force SQL alchemy to query the DB, otherwise we get inconsistent
        # results
        context.session.expire_all()

        with context.session.begin():
            l7policy = self._get_db_l7policy(context.session, id)
            result = l7policy_types.L7PolicyResponse.from_db_obj(l7policy)

        return l7policy_types.L7PolicyRootResponse(l7policy=result)

    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, id):
        """Deletes a l7policy."""
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_l7policy = self._get_db_l7policy(context.session, id,
                                                show_deleted=False)
            load_balancer_id, listener_id = (
                self._get_listener_and_loadbalancer_id(db_l7policy))
            project_id, provider = self._get_lb_project_id_provider(
                context.session, load_balancer_id)

            self._auth_validate_action(
                context,
                project_id,
                constants.RBAC_DELETE
            )

            if db_l7policy.provisioning_status == constants.DELETED:
                return

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            self._test_lb_and_listener_statuses(context.session,
                                                lb_id=load_balancer_id,
                                                listener_ids=[listener_id])
            self.repositories.l7policy.update(
                context.session, db_l7policy.id,
                provisioning_status=constants.PENDING_DELETE)

            LOG.info("Sending delete L7 Policy %s to provider %s",
                     id, driver.name)
            provider_l7policy = driver_utils.db_l7policy_to_provider_l7policy(
                db_l7policy)
            driver_utils.call_provider(driver.name, driver.l7policy_delete,
                                       provider_l7policy)

    @pecan_expose()
    def _lookup(self, l7policy_id, *remainder):
        """Overridden pecan _lookup method for custom routing.

        Verifies that the l7policy passed in the url exists, and if so decides
        which controller, if any, should control be passed.
        """
        context = pecan_request.context.get('octavia_context')
        if l7policy_id and remainder and remainder[0] == 'rules':
            remainder = remainder[1:]
            with context.session.begin():
                db_l7policy = self.repositories.l7policy.get_orm(
                    context.session, id=l7policy_id)
                if not db_l7policy:
                    LOG.info("L7Policy %s not found.", l7policy_id)
                    raise exceptions.NotFound(
                        resource='L7Policy', id=l7policy_id)
                return l7rule.L7RuleController(
                    l7policy_id=db_l7policy.id), remainder
        return None
