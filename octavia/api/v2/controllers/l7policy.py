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
from oslo_utils import uuidutils
from pecan import expose as pecan_expose
from pecan import request as pecan_request
from wsme import types as wtypes
from wsmeext import pecan as wsme_pecan

from octavia.api.drivers import driver_factory
from octavia.api.drivers import utils as driver_utils
from octavia.api.v2.controllers import base
from octavia.api.v2.controllers import l7rule
from octavia.api.v2.types import l7policy as l7policy_types
from octavia.api.v2.types import l7policy_activation as activation_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import l7policy_activation
from octavia.common import validate
from octavia.db import prepare as db_prepare
from octavia.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

ACTIVATION_PROTOCOLS = (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS)


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


def _only_removes_mirrors(previous, mirrors):
    remaining = iter(previous or [])
    return all(mirror in remaining for mirror in mirrors or [])


def _requires_target_filter_capability(previous, targets, expands_scope,
                                       *, mirrors=False):
    """Allow removal of existing filters after regional withdrawal."""
    previous, targets = previous or [], targets or []
    if previous == targets and not expands_scope:
        return False

    # The draw selects an occurrence by its ordered weight. An unchanged
    # positive filter may remain in the same or a narrower selection interval.
    previous_total = sum(target['weight'] for target in previous)
    total = sum(target['weight'] for target in targets)
    previous_start = start = 0
    for index, target in enumerate(targets):
        old = previous[index] if index < len(previous) else {}
        previous_end = previous_start + old.get('weight', 0)
        end = start + target['weight']
        filters = validate.target_request_filters(target)
        copies = target.get('request_mirrors', [])
        has_filters = bool(copies if mirrors else filters)
        if has_filters:
            if mirrors:
                changed = (not _only_removes_mirrors(
                    old.get('request_mirrors'), copies) or
                    filters != validate.target_request_filters(old))
            else:
                changed = any(old.get(field) != value
                              for field, value in filters.items())
            if (target.get('pool_id') != old.get('pool_id') or
                    changed):
                return True
            extends_draw = (start * previous_total < previous_start * total or
                            end * previous_total > previous_end * total)
            if target['weight'] and (expands_scope or extends_draw):
                return True
        previous_start, start = previous_end, end
    return False


class L7PolicyActivationController(base.BaseController):
    RBAC_TYPE = constants.RBAC_L7POLICY

    def __init__(self, listener_id):
        super().__init__()
        self.listener_id = listener_id

    def _parent_id(self, context):
        # End the listener lookup transaction so the subsequent snapshot has
        # no pre-lock consistent reads on MySQL REPEATABLE READ.
        with context.session.begin():
            return self._get_db_listener(
                context.session, self.listener_id,
                show_deleted=False).load_balancer_id

    def _get_listener_and_provider(self, context, lb_id, action):
        session = context.session
        # Use the same lock as individual L7 policy/rule mutations. Current
        # reads after it avoid reusing a pre-lock MySQL repeatable-read view.
        lb = self.repositories.load_balancer.get_for_update(
            session, lb_id)
        listener = self.repositories.listener.get_for_update(
            session, self.listener_id, show_deleted=False)
        if not lb or lb.provisioning_status == constants.DELETED:
            raise exceptions.NotFound(resource='Listener', id=self.listener_id)
        self._auth_validate_action(context, lb.project_id, action)
        if (listener.load_balancer_id != lb.id or
                listener.project_id != lb.project_id):
            raise exceptions.L7PolicyActivationConflict()
        driver = driver_factory.get_driver(lb.provider)
        if (constants.GATEWAY_CAPABILITY_L7POLICY_BATCH_ACTIVATION not in
                driver_utils.gateway_capabilities(driver) or
                listener.protocol not in ACTIVATION_PROTOCOLS):
            raise exceptions.ProviderNotImplementedError(
                prov=driver.name, user_msg=_(
                    'Grouped L7 policy activation is unavailable for this '
                    'listener.'))
        return listener, lb, driver

    @wsme_pecan.wsexpose(activation_types.L7PolicyActivationRootResponse)
    def get(self):
        """Read the ordered policies and the backend graph."""
        context = pecan_request.context.get('octavia_context')
        lb_id = self._parent_id(context)
        with context.session.begin():
            listener, lb, _driver = self._get_listener_and_provider(
                context, lb_id, constants.RBAC_GET_ONE)
            if (lb.provisioning_status.startswith('PENDING_') and
                    not self.repositories.load_balancer._batch_pending(lb)):
                raise exceptions.L7PolicyActivationConflict()
            for resource in (constants.RBAC_LOADBALANCER,
                             constants.RBAC_LISTENER,
                             constants.RBAC_L7RULE, constants.RBAC_POOL,
                             constants.RBAC_MEMBER,
                             constants.RBAC_HEALTHMONITOR):
                self._auth_validate_action(
                    context, lb.project_id, constants.RBAC_GET_ONE,
                    rbac_type=resource)
            graph, _policies = l7policy_activation.snapshot(
                context.session, self.repositories, lb, listener)
        return activation_types.L7PolicyActivationRootResponse(
            l7policy_activation=graph)

    @wsme_pecan.wsexpose(
        None, body=activation_types.L7PolicyActivationRootPOST,
        status_code=204)
    def post(self, activation_):
        """Enable prepared policies while preserving the listener's order."""
        activation = activation_.l7policy_activation if activation_ else None
        if not activation:
            raise exceptions.ValidationException(detail=_(
                'Supply an l7policy_activation object.'))
        revisions = {item.id: item.revision for item in activation.policies}
        if len(revisions) != len(activation.policies):
            raise exceptions.ValidationException(detail=_(
                'L7 policy IDs must be unique.'))
        request = {
            'graph_revision': activation.expected_graph_revision,
            'order': activation.expected_order,
            'policies': revisions,
        }

        context = pecan_request.context.get('octavia_context')
        session = context.session
        lb_id = self._parent_id(context)
        with session.begin():
            listener, lb, driver = self._get_listener_and_provider(
                context, lb_id, constants.RBAC_PUT)
            operation = lb.l7policy_activation or {}
            replay = (operation.get('listener_id') == listener.id and
                      operation.get('request') == request)
            if operation.get('phase') in l7policy_activation.PENDING:
                if not replay:
                    raise exceptions.L7PolicyActivationConflict()
                self._dispatch(driver, lb.id, operation['id'])
                return
            if (lb.provisioning_status != constants.ACTIVE or
                    listener.provisioning_status != constants.ACTIVE or
                    not listener.enabled or not lb.enabled):
                raise exceptions.L7PolicyActivationConflict()

            graph, order = l7policy_activation.snapshot(
                session, self.repositories, lb, listener)
            policies = [policy for policy in order if policy.id in revisions]
            if (replay and operation['phase'] == 'applied' and
                    graph.graph_revision == operation['applied_revision'] and
                    all(p.enabled and p.provisioning_status == constants.ACTIVE
                        for p in policies)):
                return
            if (graph.graph_revision != request['graph_revision'] or
                    [policy.id for policy in order] != request['order'] or
                    len(policies) != len(revisions)):
                raise exceptions.L7PolicyActivationConflict()
            for policy in policies:
                if (policy.enabled or
                        policy.provisioning_status != constants.ACTIVE or
                        not any(rule.enabled for rule in policy.l7rules) or
                        any(rule.provisioning_status != constants.ACTIVE
                            for rule in policy.l7rules) or
                        l7policy_activation.policy_revision(policy) !=
                        revisions[policy.id]):
                    raise exceptions.L7PolicyActivationConflict()
                self._validate_policy(session, policy, listener, driver)

            operation_id = uuidutils.generate_uuid()
            lb.l7policy_activation = {
                'id': operation_id,
                'listener_id': listener.id,
                'request': request,
                'phase': 'pending',
            }
            listener.provisioning_status = constants.PENDING_UPDATE
            lb.provisioning_status = constants.PENDING_UPDATE
            for policy in policies:
                policy.provisioning_status = constants.PENDING_UPDATE
            self._dispatch(driver, lb.id, operation_id)

    @staticmethod
    def _dispatch(driver, lb_id, operation_id):
        driver_utils.call_provider(
            driver.name, driver.l7policy_batch_activate, {
                'id': operation_id, 'loadbalancer_id': lb_id,
            })

    def _validate_policy(self, session, policy, listener, driver):
        repo = self.repositories.l7policy
        protocol = listener.protocol
        hostname = validate.validate_https_policy_hostname(
            listener.https_virtual_hosts, policy.https_listener_hostname)
        if hostname is not None:
            driver_utils.require_https_listener_isolation(driver)
        for rule in policy.l7rules:
            if rule.enabled:
                driver_utils.validate_l7rule_context(driver, rule.type,
                                                     protocol)
        driver_utils.require_gateway_policy_action(
            driver, policy.action, protocol,
            request_header_operations=policy.request_header_operations,
            response_header_operations=policy.response_header_operations,
            request_url_rewrite=policy.request_url_rewrite,
            request_cors=policy.request_cors, targets=policy.targets,
            http_request_policy=policy.http_request_policy,
            request_mirrors=policy.request_mirrors)
        repo.validate_mirror_pools(
            session, listener, policy.request_mirrors, policy.targets)
        if policy.redirect_pool_id:
            pool = repo.get_redirect_pool_for_update(
                session, listener, policy.redirect_pool_id)
            self._validate_protocol(protocol, pool.protocol)
        pool_ids = {target['pool_id'] for target in policy.targets
                    if 'pool_id' in target}
        for pool_id in sorted(pool_ids):
            pool = repo.get_redirect_pool_for_update(
                session, listener, pool_id)
            self._validate_protocol(protocol, pool.protocol)
        if policy.action == constants.L7POLICY_ACTION_REDIRECT_REQUEST:
            driver_utils.require_no_transform_exposed_by_ordered_redirect(
                driver, repo, session, listener.id, hostname, policy.position,
                policy_id=policy.id)


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
        validate.validate_tcp_tls_backend_listener(
            listener.tcp_tls_termination, pool.protocol,
            pool.backend_tls_hostname)

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
        if not l7policy_ or not l7policy_.l7policy:
            raise exceptions.ValidationException(detail=_(
                'The request must contain an l7policy object.'))
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

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)
            if l7policy.rules:
                capabilities = driver_utils.gateway_capabilities(driver)
                if (listener.protocol not in (
                        lib_consts.PROTOCOL_HTTP,
                        lib_consts.PROTOCOL_TERMINATED_HTTPS) or
                        constants.GATEWAY_CAPABILITY_L7POLICY_INITIAL_RULES
                        not in capabilities):
                    raise exceptions.ValidationException(detail=_(
                        'Create the policy first, then use POST '
                        '/v2/lbaas/l7policies/{id}/rules.'))
                self._auth_validate_action(
                    context, l7policy.project_id, constants.RBAC_POST,
                    rbac_type=constants.RBAC_L7RULE)
                if l7policy.admin_state_up is not False:
                    raise exceptions.ValidationException(detail=_(
                        'An L7 policy with initial rules must be created '
                        'with admin_state_up set to false.'))
                for rule in l7policy.rules:
                    l7rule.validate_create_rule_data(rule)

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
            rules = l7policy_dict.pop('l7rules', []) or []
            if rules:
                if self.repositories.check_quota_met(
                        lock_session, data_models.L7Rule,
                        l7policy.project_id, count=len(rules),
                        ensure_project=False):
                    raise exceptions.QuotaException(
                        resource=data_models.L7Rule._name())

            driver_utils.require_gateway_policy_action(
                driver, l7policy_dict['action'], listener.protocol,
                tcp_tls_termination=listener.tcp_tls_termination,
                request_url_rewrite=l7policy_dict.get('request_url_rewrite'),
                targets=l7policy_dict.get('targets'),
                request_cors=l7policy_dict.get('request_cors'))
            validate_policy_headers(
                l7policy_dict, listener.protocol, driver)

            self._test_lb_and_listener_statuses(
                lock_session, lb_id=load_balancer_id,
                listener_ids=[listener_id])
            listener = self.repositories.listener.get_for_update(
                lock_session, listener_id, show_deleted=False)
            if l7policy_dict.get('http_request_policy') is not None:
                driver_utils.require_http_request_policy(
                    driver, listener.protocol)
            if validate.request_mirror_pool_ids(
                    l7policy_dict.get('request_mirrors'),
                    l7policy_dict.get('targets')):
                driver_utils.require_http_request_mirror(
                    driver, listener.protocol)
            passthrough = l7policy_dict.get('tcp_tls_passthrough', False)
            driver_utils.validate_tcp_tls_policy_mode(
                driver, listener.tcp_tls_mixed_mode, passthrough)
            hostname = validate.validate_https_policy_hostname(
                listener.https_virtual_hosts,
                l7policy_dict.get('https_listener_hostname'))
            if hostname is not None:
                driver_utils.require_https_listener_isolation(driver)
                l7policy_dict['https_listener_hostname'] = hostname
            pool_id = l7policy_dict.get('redirect_pool_id')
            if driver_utils.uses_tls_sni_policy_path(
                    driver, listener.protocol, listener.tcp_tls_termination):
                driver_utils.validate_existing_tcp_pool_attachment(
                    driver, self.repositories.l7policy, lock_session,
                    listener, pool_id, tls_sni_policy=True,
                    passthrough=passthrough)
            elif pool_id:
                self._validate_redirect_pool_protocol(
                    lock_session, listener, pool_id)
            for rule in rules:
                driver_utils.validate_l7rule_context(
                    driver, rule['type'], listener.protocol,
                    tcp_tls_termination=listener.tcp_tls_termination)
            db_l7policy = self._validate_create_l7policy(
                lock_session, l7policy_dict)
            if rules:
                self._create_rules(lock_session, db_l7policy, rules)

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

        if rules:
            self._create_rules(lock_session, db_policy, rules)
        return db_policy

    def _create_rules(self, lock_session, db_policy, rules):
        controller = l7rule.L7RuleController(db_policy.id)
        new_rules = []
        for rule in rules:
            rule['project_id'] = db_policy.project_id
            new_rules.append(controller._graph_create(lock_session, rule))
        db_policy.l7rules = new_rules

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
            passthrough = db_l7policy.tcp_tls_passthrough
            if (l7policy_dict.pop('tcp_tls_passthrough', passthrough)
                    is not passthrough):
                raise exceptions.ValidationException(detail=_(
                    'tcp_tls_passthrough can only be set at policy creation.'))
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
            if l7policy_dict.get('request_url_rewrite'):
                https_routing_changed.add('request_url_rewrite')
            cors = l7policy_dict.get('request_cors', db_l7policy.request_cors)
            cors_changed = cors != db_l7policy.request_cors
            if cors_changed and cors is not None:
                https_routing_changed.add('request_cors')
            previous_request_policy = db_l7policy.http_request_policy
            request_policy = l7policy_dict.get(
                'http_request_policy', previous_request_policy)
            request_policy_changed = request_policy != previous_request_policy
            if request_policy is not None and request_policy_changed:
                https_routing_changed.add('http_request_policy')
            previous_mirrors = db_l7policy.request_mirrors
            mirrors = l7policy_dict.get('request_mirrors', previous_mirrors)
            adds_mirrors = not _only_removes_mirrors(previous_mirrors, mirrors)
            if adds_mirrors:
                https_routing_changed.add('request_mirrors')
            if (hostname is not None and
                    (reopening or
                     https_routing_changed.intersection(l7policy_dict))):
                driver_utils.require_https_listener_isolation(driver)
            policy_repo = self.repositories.l7policy
            if reopening and not tcp_policy:
                driver_utils.require_active_http_l7rule_capabilities(
                    driver, policy_repo, lock_session, policy_id=id)
            if (action == constants.L7POLICY_ACTION_REDIRECT_REQUEST and
                    enabled and listener.enabled and
                    hostname != db_l7policy.https_listener_hostname):
                routing_changed.add('https_listener_hostname')
            activates_policy = enabled and (
                reopening or
                l7policy_dict.get('position', db_l7policy.position) !=
                db_l7policy.position)
            rewrite = l7policy_dict.get('request_url_rewrite',
                                        db_l7policy.request_url_rewrite)
            if rewrite and (
                    'request_url_rewrite' in l7policy_dict or
                    (enabled and (
                        activates_policy or routing_changed.intersection(
                            l7policy_dict) or pool_id or
                        hostname != db_l7policy.https_listener_hostname))):
                driver_utils.require_request_url_rewrite(
                    driver, listener.protocol)
            old_targets = db_l7policy.targets
            targets = l7policy_dict.get('targets', old_targets)
            routing_changed_or_disabled = (
                not enabled or action != db_l7policy.action or
                ('redirect_pool_id' in l7policy_dict and
                 pool_id != db_l7policy.redirect_pool_id) or
                hostname != db_l7policy.https_listener_hostname or
                ('redirect_request' in l7policy_dict and
                 l7policy_dict['redirect_request'] !=
                 db_l7policy.redirect_request))
            if cors is not None and (
                    cors_changed or (enabled and (
                        activates_policy or routing_changed_or_disabled or
                        targets != old_targets))):
                driver_utils.require_request_cors(driver, listener.protocol)
            updated_request_transform = any(
                l7policy_dict.get(field) and
                l7policy_dict[field] != getattr(db_l7policy, field)
                for field in validate.TARGET_REQUEST_FILTER_FIELDS)
            expands_filter_scope = enabled and (
                activates_policy or updated_request_transform or
                hostname != db_l7policy.https_listener_hostname)
            if request_policy is not None and (
                    request_policy_changed or (enabled and (
                        activates_policy or routing_changed_or_disabled or
                        targets != old_targets))):
                driver_utils.require_http_request_policy(
                    driver, listener.protocol)
            if _requires_target_filter_capability(
                    old_targets, targets, expands_filter_scope):
                driver_utils.require_weighted_target_request_filters(
                    driver, listener.protocol)
            if (adds_mirrors or
                    (mirrors and enabled and
                     (expands_filter_scope or routing_changed_or_disabled)) or
                    _requires_target_filter_capability(
                        old_targets, targets, expands_filter_scope,
                        mirrors=True)):
                driver_utils.require_http_request_mirror(
                    driver, listener.protocol)
            position = l7policy_dict.get('position') or db_l7policy.position
            if routing_changed_or_disabled or (
                    position > db_l7policy.position and
                    action != constants.L7POLICY_ACTION_REJECT):
                driver_utils.require_no_exposed_request_transforms(
                    driver, policy_repo, lock_session, policy_id=id,
                    new_position=(
                        None if routing_changed_or_disabled else position))
            if (action == constants.L7POLICY_ACTION_REDIRECT_REQUEST and
                    enabled and (routing_changed_or_disabled or reopening or
                                 position > db_l7policy.position)):
                driver_utils.require_no_transform_exposed_by_ordered_redirect(
                    driver, policy_repo, lock_session, listener_id, hostname,
                    position, policy_id=id)
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
                    driver_utils.validate_tcp_tls_policy_mode(
                        driver, listener.tcp_tls_mixed_mode, passthrough)
                    if ((passthrough or not listener.tcp_tls_termination) and
                            policy_repo.has_enabled_tls_sni_suffix_rule(
                                lock_session, policy_id=id)):
                        driver_utils.require_tls_sni_suffix(driver)
                    target = l7policy_dict.get(
                        'redirect_pool_id', db_l7policy.redirect_pool_id)
                    driver_utils.validate_existing_tcp_pool_attachment(
                        driver, policy_repo, lock_session, listener, target,
                        tls_sni_policy=True, passthrough=passthrough)
            elif (listener.tcp_tls_mixed_mode and enabled and
                    position != db_l7policy.position):
                driver_utils.require_tcp_tls_mixed_mode(driver)
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
                for policy_action in (action, db_l7policy.action)) or
                'request_url_rewrite' in l7policy_dict or
                'request_cors' in l7policy_dict or
                'request_mirrors' in l7policy_dict or
                'http_request_policy' in l7policy_dict)
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
            policy_repo = self.repositories.l7policy
            driver_utils.require_no_exposed_request_transforms(
                driver, policy_repo, context.session, policy_id=id)
            policy_repo.update(
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
