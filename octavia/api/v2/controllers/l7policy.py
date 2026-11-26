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
from octavia.api.v2.types import l7policy_removal as removal_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import l7policy_activation
from octavia.common import l7policy_removal
from octavia.common import validate
from octavia.db import api as db_apis
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


def _only_removes_mirrors(previous, mirrors):
    remaining = iter(previous or [])
    return all(mirror in remaining for mirror in mirrors or [])


def _expands_retry_backoff(previous_policy, policy):
    retry = policy.get('retry', {})
    backoff = retry.get('backoff_ms')
    if backoff is None:
        return False
    previous_retry = (previous_policy or {}).get('retry', {})
    previous_backoff = previous_retry.get('backoff_ms')
    if previous_backoff is None or backoff > previous_backoff:
        return True
    attempts = retry.get('attempts', 1)
    return attempts > previous_retry.get('attempts', 1) or (
        attempts > 0 and bool(set(retry.get('codes', [])) -
                              set(previous_retry.get('codes', []))))


def _weighted_draws(targets):
    total = sum(target['weight'] for target in targets)
    start = 0
    for target in targets:
        end = start + target['weight']
        yield target, start, end, total
        start = end


def _extends_draw(previous, current):
    _, old_start, old_end, old_total = previous
    _, start, end, total = current
    return (start * old_total < old_start * total or
            end * old_total > old_end * total)


def _requires_target_filter_capability(previous, targets, expands_scope,
                                       *, mirrors=False):
    """Allow removal of existing filters after regional withdrawal."""
    previous, targets = previous or [], targets or []
    if previous == targets and not expands_scope:
        return False

    # The draw selects an occurrence by its ordered weight. An unchanged
    # positive filter may remain in the same or a narrower selection interval.
    old_draws = list(_weighted_draws(previous))
    missing = ({}, 0, 0, old_draws[-1][-1] if old_draws else 0)
    for index, draw in enumerate(_weighted_draws(targets)):
        target = draw[0]
        previous_draw = old_draws[index] if index < len(old_draws) else missing
        old = previous_draw[0]
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
            if target['weight'] and (
                    expands_scope or _extends_draw(previous_draw, draw)):
                return True
    return False


def _expanded_target_header_operations(previous, targets, expands_scope,
                                       *, field, select=None):
    def operations(target):
        values = target.get(field) or []
        return select(values) if select else values

    if previous == targets and not expands_scope:
        return
    # Match each retained occurrence once, including when a sibling was
    # removed. An occurrence cannot inherit a wider share of the draw.
    retained = [
        (draw, operations(draw[0]))
        for draw in _weighted_draws(previous or [])]
    draws = sorted(_weighted_draws(targets or []),
                   key=lambda draw: draw[0]['weight'] == 0)
    for draw in draws:
        target = draw[0]
        metadata = operations(target)
        if not metadata:
            continue
        if target['weight'] and expands_scope:
            yield metadata
            continue
        for index, (old, old_metadata) in enumerate(retained):
            same_pool = old[0].get('pool_id') == target.get('pool_id')
            retains_metadata = all(op in old_metadata for op in metadata)
            draw_fits = not target['weight'] or (
                old[0]['weight'] and not _extends_draw(old, draw))
            if same_pool and retains_metadata and draw_fits:
                retained.pop(index)
                break
        else:
            yield metadata


def _expands_weighted_forwarding(previous, targets):
    old_pools = {target['pool_id'] for target in previous
                 if 'pool_id' in target and target['weight']}
    pools = {target['pool_id'] for target in targets
             if 'pool_id' in target and target['weight']}
    return bool(pools - old_pools) or (
        sum(target['weight'] for target in targets if 'pool_id' in target) *
        sum(target['weight'] for target in previous) >
        sum(target['weight'] for target in previous if 'pool_id' in target) *
        sum(target['weight'] for target in targets))


class L7PolicyRemovalController(base.BaseController):
    RBAC_TYPE = constants.RBAC_L7POLICY

    def __init__(self, policy_id):
        super().__init__()
        self.policy_id = policy_id

    def _parent_ids(self, session):
        # End the lookup transaction before taking current reads under lock.
        with session.begin():
            scope = self.repositories.l7policy.get_parent_scope(
                session, self.policy_id, show_deleted=False)
            if scope is None:
                raise exceptions.NotFound(resource='L7Policy',
                                          id=self.policy_id)
            return scope.load_balancer_id, scope.listener_id

    def _authorize(self, context, lb, policy_action, rules_action):
        self._auth_validate_action(context, lb.project_id, policy_action)
        self._auth_validate_action(context, lb.project_id, rules_action,
                                   rbac_type=constants.RBAC_L7RULE)
        driver = driver_factory.get_driver(lb.provider)
        if not driver_utils.l7policy_conditional_removal_available(driver):
            raise exceptions.ProviderNotImplementedError(
                prov=driver.name, user_msg=_(
                    'Conditional L7 policy removal is unavailable.'))
        return driver

    @wsme_pecan.wsexpose(removal_types.L7PolicyRemovalRootResponse)
    def get(self):
        """Read the policy and its complete rule set for removal."""
        context = pecan_request.context.get('octavia_context')
        session = context.session
        lb_id, listener_id = self._parent_ids(session)
        with session.begin():
            lb = l7policy_removal.lock_load_balancer(
                session, self.repositories, lb_id)
            self._authorize(context, lb, constants.RBAC_GET_ONE,
                            constants.RBAC_GET_ALL)
            policy = l7policy_removal.lock_policy(
                session, self.repositories, lb, listener_id, self.policy_id)
            result, revision = l7policy_removal.snapshot(lb, policy)
        return removal_types.L7PolicyRemovalRootResponse(
            l7policy_removal=removal_types.L7PolicyRemovalSnapshot(
                revision=revision, loadbalancer_id=lb_id, policy=result))

    @wsme_pecan.wsexpose(
        None, body=removal_types.L7PolicyRemovalRootPOST, status_code=202)
    def post(self, removal_):
        """Request removal of the disabled policy at the observed revision."""
        if not removal_:
            raise exceptions.ValidationException(detail=_(
                'Supply an l7policy_removal object.'))
        expected_revision = removal_.l7policy_removal.expected_revision
        context = pecan_request.context.get('octavia_context')
        session = context.session
        lb_id, listener_id = self._parent_ids(session)
        with session.begin():
            lb = l7policy_removal.lock_load_balancer(
                session, self.repositories, lb_id)
            driver = self._authorize(context, lb, constants.RBAC_DELETE,
                                     constants.RBAC_DELETE)
            policy = l7policy_removal.lock_policy(
                session, self.repositories, lb, listener_id, self.policy_id,
                removing=True)
            l7policy_removal.validate_removal(lb, policy, expected_revision)
            driver_utils.require_no_exposed_request_transforms(
                driver, self.repositories.l7policy, session,
                policy_id=self.policy_id)
            project_id = lb.project_id
        driver_utils.call_provider(
            driver.name, driver.l7policy_conditional_remove, {
                constants.LOADBALANCER_ID: lb_id,
                constants.LISTENER_ID: listener_id,
                constants.L7POLICY_ID: self.policy_id,
                constants.PROJECT_ID: project_id,
                'expected_revision': expected_revision,
            })


class L7PolicyActivationController(base.BaseController):
    grpc_auth_transition = False
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
        return listener, lb, driver

    @staticmethod
    def _batch_available(driver, listener):
        return driver_utils.l7policy_batch_activation_available(
            driver, listener)

    def _require_batch_activation(self, driver, listener):
        if not self._batch_available(driver, listener):
            raise exceptions.ProviderNotImplementedError(
                prov=driver.name, user_msg=_(
                    'Grouped L7 policy activation is unavailable for this '
                    'listener.'))

    @wsme_pecan.wsexpose(activation_types.L7PolicyActivationRootResponse)
    def get(self):
        """Read the ordered policies and the backend graph."""
        return self._observe()

    def _observe(self, additional_pools=()):
        context = pecan_request.context.get('octavia_context')
        lb_id = self._parent_id(context)
        with context.session.begin():
            listener, lb, driver = self._get_listener_and_provider(
                context, lb_id, constants.RBAC_GET_ONE)
            operation = lb.l7policy_activation or {}
            if (operation.get('listener_id') != listener.id or
                    self.grpc_auth_transition !=
                    l7policy_activation.grpc_auth_operation(operation,
                                                            listener.id)):
                self._require_batch_activation(driver, listener)
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
                context.session, self.repositories, lb, listener,
                additional_pools=additional_pools)
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
        self._submit(request)

    def _submit(self, request):
        revisions = request['policies']
        transition = request.get('grpc_auth_transition')
        additional_pools = l7policy_activation.transition_pools(request)
        context = pecan_request.context.get('octavia_context')
        session = context.session
        lb_id = self._parent_id(context)
        with session.begin():
            listener, lb, driver = self._get_listener_and_provider(
                context, lb_id, constants.RBAC_PUT)
            if transition:
                self._auth_validate_action(
                    context, lb.project_id, constants.RBAC_PUT,
                    rbac_type=constants.RBAC_L7RULE)
            operation = lb.l7policy_activation or {}
            replay = (operation.get('listener_id') == listener.id and
                      operation.get('request') == request)
            if operation.get('phase') in l7policy_activation.PENDING:
                if not replay:
                    raise exceptions.L7PolicyActivationConflict()
                if transition:
                    # A restoration replay cannot establish current access.
                    # The recovery endpoint only dispatches compensation.
                    return
                if not self._batch_available(driver, listener):
                    lb.l7policy_activation = {
                        **operation, 'phase': 'reverting'}
                self._dispatch(driver, lb.id, operation['id'])
                return
            if not replay:
                self._require_batch_activation(driver, listener)
            if (lb.provisioning_status != constants.ACTIVE or
                    self.repositories.load_balancer.tcp_batch_pending(lb) or
                    listener.provisioning_status != constants.ACTIVE or
                    not listener.enabled or not lb.enabled):
                raise exceptions.L7PolicyActivationConflict()

            if listener.request_filter_sections:
                driver_utils.require_listener_request_filters(
                    driver, listener.protocol,
                    listener.request_filter_sections, session=session,
                    lb_id=lb.id, project_id=listener.project_id)
            graph, order = l7policy_activation.snapshot(
                session, self.repositories, lb, listener,
                additional_pools=additional_pools)
            policies = [policy for policy in order if policy.id in revisions]
            if (replay and operation['phase'] == 'applied' and
                    graph.graph_revision == operation['applied_revision'] and
                    all(p.enabled and p.provisioning_status == constants.ACTIVE
                        for p in policies)):
                return
            if replay:
                self._require_batch_activation(driver, listener)
            if (graph.graph_revision != request['graph_revision'] or
                    [policy.id for policy in order] != request['order'] or
                    len(policies) != len(revisions)):
                raise exceptions.L7PolicyActivationConflict()
            for policy in policies:
                if (policy.enabled != bool(transition) or
                        policy.provisioning_status != constants.ACTIVE or
                        not any(rule.enabled for rule in policy.l7rules) or
                        any(rule.provisioning_status != constants.ACTIVE
                            for rule in policy.l7rules) or
                        l7policy_activation.policy_revision(policy) !=
                        revisions[policy.id]):
                    raise exceptions.L7PolicyActivationConflict()
                if transition:
                    l7policy_activation.validate_transition(
                        session, self.repositories, policy, listener, driver,
                        transition[policy.id])
                else:
                    self._validate_policy(session, policy, listener, driver)

            operation_id = uuidutils.generate_uuid()
            lb.tcp_member_batch = None
            lb.l7policy_activation = {
                'id': operation_id,
                'listener_id': listener.id,
                'request': request,
                'phase': 'pending',
            }
            if transition:
                lb.l7policy_activation = {
                    **lb.l7policy_activation,
                    'recover_after': (
                        l7policy_activation.grpc_auth_recovery_deadline()),
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
        if protocol == constants.PROTOCOL_TCP:
            if (policy.action != constants.L7POLICY_ACTION_WEIGHTED_TARGETS or
                    (listener.tcp_tls_termination and
                     not policy.tcp_tls_passthrough)):
                raise exceptions.ValidationException(detail=_(
                    'TCP batch activation requires weighted TLS SNI '
                    'passthrough policies.'))
            driver_utils.validate_tcp_tls_policy_mode(
                driver, listener.tcp_tls_mixed_mode,
                policy.tcp_tls_passthrough)
        for rule in policy.l7rules:
            if rule.enabled:
                driver_utils.validate_l7rule_context(
                    driver, rule.type, protocol,
                    compare_type=rule.compare_type, key=rule.key,
                    value=rule.value,
                    reactivating=True,
                    tcp_tls_termination=listener.tcp_tls_termination)
                if protocol == constants.PROTOCOL_TCP:
                    driver_utils.require_tls_sni_rule_comparison(
                        driver, rule.compare_type)
        if any(rule.enabled and
               rule.type == constants.L7RULE_TYPE_GRPC_CONTENT_TYPE
               for rule in policy.l7rules):
            driver_utils.require_grpc_request_metadata(
                driver, protocol, policy.request_header_operations,
                policy.targets)
            driver_utils.require_grpc_target_response_metadata(
                driver, protocol, policy.targets)
            for target in policy.targets:
                validate.validate_grpc_target_response_headers(
                    target.get('response_header_operations'))
        driver_utils.require_gateway_policy_action(
            driver, policy.action, protocol,
            tcp_tls_termination=listener.tcp_tls_termination,
            tcp_tls_mixed_mode=listener.tcp_tls_mixed_mode,
            tcp_tls_passthrough=policy.tcp_tls_passthrough,
            request_header_operations=policy.request_header_operations,
            response_header_operations=policy.response_header_operations,
            request_url_rewrite=policy.request_url_rewrite,
            request_cors=policy.request_cors, targets=policy.targets,
            http_request_policy=policy.http_request_policy,
            request_mirrors=policy.request_mirrors,
            external_auth=policy.external_auth)
        driver_utils.require_l7policy_external_auth_transport(
            driver, session, listener, policy.external_auth)
        if protocol == constants.PROTOCOL_TCP:
            driver_utils.validate_tcp_policy_targets(
                driver, repo, session, listener, policy.action,
                policy.redirect_pool_id, policy.targets,
                policy.tcp_tls_passthrough, active_targets_only=True)
            return
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


class GRPCAuthTransitionController(L7PolicyActivationController):
    grpc_auth_transition = True

    @staticmethod
    def _batch_available(driver, listener):
        return l7policy_activation.grpc_auth_transition_available(
            driver, listener)

    @wsme_pecan.wsexpose(
        activation_types.L7PolicyActivationRootResponse, wtypes.text)
    def get(self, pool_ids=None):
        pool_ids = pool_ids.split(',') if pool_ids else []
        if (len(pool_ids) > 2 * constants.MAX_L7POLICY_BATCH_ACTIVATION or
                any(not uuidutils.is_uuid_like(pool) for pool in pool_ids)):
            raise exceptions.ValidationException(detail=_(
                'Expected additional destination pool IDs.'))
        return self._observe(pool_ids)

    @wsme_pecan.wsexpose(
        None, body=activation_types.GRPCAuthTransitionRootPOST,
        status_code=204)
    def post(self, body):
        transition = body.l7policy_grpc_auth_transition if body else None
        if not transition:
            raise exceptions.ValidationException(detail=_(
                'Supply an l7policy_grpc_auth_transition object.'))
        policies = transition.policies
        revisions = {policy.id: policy.revision for policy in policies}
        if (len(revisions) != len(policies) or
                not 1 <= len(policies) <=
                constants.MAX_L7POLICY_BATCH_ACTIVATION):
            raise exceptions.ValidationException(detail=_(
                'Supply one to 64 distinct L7 policy IDs.'))
        changes = {}
        for policy in policies:
            fields = policy.to_dict(render_unsets=False)
            pool, auth = fields.get('redirect_pool_id'), fields.get(
                'external_auth')
            if bool(pool) != bool(auth):
                raise exceptions.ValidationException(detail=_(
                    'Forwarding requires an origin and a gRPC authorizer.'))
            changes[policy.id] = {
                'tags': policy.tags,
                'rules': {rule.id: rule.tags for rule in policy.rules},
                'origin': pool,
                'external_auth': auth,
            }
            if len(changes[policy.id]['rules']) != len(policy.rules):
                raise exceptions.ValidationException(detail=_(
                    'Supply unique L7 rule IDs.'))
            for tags in [policy.tags, *(rule.tags for rule in policy.rules)]:
                if len(tags) != len(set(tags)):
                    raise exceptions.ValidationException(detail=_(
                        'Supply unique tags on each policy and rule.'))
        if len({bool(change['origin']) for change in changes.values()}) != 1:
            raise exceptions.ValidationException(detail=_(
                'Select either withdrawal or restoration for the batch.'))
        self._submit({
            'graph_revision': transition.expected_graph_revision,
            'order': transition.expected_order,
            'policies': revisions,
            'grpc_auth_transition': changes,
        })

    @pecan_expose()
    def _lookup(self, action, *remainder):
        if action == 'recovery':
            return GRPCAuthRecoveryController(self.listener_id), remainder
        return None


class GRPCAuthRecoveryController(L7PolicyActivationController):

    @wsme_pecan.wsexpose(activation_types.GRPCAuthRecovery)
    def get(self):
        context = pecan_request.context.get('octavia_context')
        lb_id = self._parent_id(context)
        with context.session.begin():
            listener, lb, _driver = self._get_listener_and_provider(
                context, lb_id, constants.RBAC_GET_ONE)
            operation = lb.l7policy_activation or {}
            if (not l7policy_activation.grpc_auth_operation(
                    operation, listener.id) or
                    not l7policy_activation.grpc_auth_recovery_ready(
                        operation)):
                raise exceptions.NotFound(resource='gRPC auth recovery',
                                          id=listener.id)
            return activation_types.GRPCAuthRecovery(
                operation_id=operation['id'])

    @wsme_pecan.wsexpose(None, body=activation_types.GRPCAuthRecovery,
                         status_code=204)
    def post(self, body):
        context = pecan_request.context.get('octavia_context')
        lb_id = self._parent_id(context)
        # Use the worker's lock order. A controller poll must never interrupt
        # a live render.
        with db_apis.listener_render_lock(lb_id) as acquired:
            if not acquired:
                raise exceptions.L7PolicyActivationConflict()
            with context.session.begin():
                listener, lb, driver = self._get_listener_and_provider(
                    context, lb_id, constants.RBAC_PUT)
                self._auth_validate_action(
                    context, lb.project_id, constants.RBAC_PUT,
                    rbac_type=constants.RBAC_L7RULE)
                operation = lb.l7policy_activation or {}
                if (not body or not l7policy_activation.grpc_auth_operation(
                        operation, listener.id) or
                        body.operation_id != operation['id']):
                    raise exceptions.L7PolicyActivationConflict()
                if operation['phase'] in ('applied', 'failed'):
                    return
                if not l7policy_activation.grpc_auth_recovery_ready(operation):
                    raise exceptions.L7PolicyActivationConflict()
                lb.l7policy_activation = {**operation, 'phase': 'reverting'}
                operation_id = operation['id']
        self._dispatch(driver, lb_id, operation_id)


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
                http_listener = listener.protocol in (
                        lib_consts.PROTOCOL_HTTP,
                        lib_consts.PROTOCOL_TERMINATED_HTTPS)
                weighted_tls_sni = (
                    listener.protocol == constants.PROTOCOL_TCP and
                    l7policy.action ==
                    constants.L7POLICY_ACTION_WEIGHTED_TARGETS)
                if (not (http_listener or weighted_tls_sni) or
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
                tcp_tls_mixed_mode=listener.tcp_tls_mixed_mode,
                tcp_tls_passthrough=l7policy_dict.get(
                    'tcp_tls_passthrough', False),
                request_url_rewrite=l7policy_dict.get('request_url_rewrite'),
                targets=l7policy_dict.get('targets'),
                request_cors=l7policy_dict.get('request_cors'),
                external_auth=l7policy_dict.get('external_auth'))
            validate_policy_headers(
                l7policy_dict, listener.protocol, driver)

            self._test_lb_and_listener_statuses(
                lock_session, lb_id=load_balancer_id,
                listener_ids=[listener_id])
            listener = self.repositories.listener.get_for_update(
                lock_session, listener_id, show_deleted=False)
            if listener.tcp_default_pool_tls:
                raise exceptions.ValidationException(detail=_(
                    'L7 policies are unavailable on tcp_default_pool_tls '
                    'listeners.'))
            driver_utils.require_l7policy_external_auth_transport(
                driver, lock_session, listener,
                l7policy_dict.get('external_auth'))
            request_policy = l7policy_dict.get('http_request_policy')
            if request_policy is not None:
                driver_utils.require_http_request_policy(
                    driver, listener.protocol)
                if 'backoff_ms' in request_policy.get('retry', {}):
                    driver_utils.require_http_retry_backoff(
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
                driver_utils.validate_tcp_policy_targets(
                    driver, self.repositories.l7policy, lock_session,
                    listener, l7policy_dict['action'], pool_id,
                    l7policy_dict.get('targets'), passthrough)
            elif pool_id:
                self._validate_redirect_pool_protocol(
                    lock_session, listener, pool_id)
            for rule in rules:
                driver_utils.validate_l7rule_context(
                    driver, rule['type'], listener.protocol,
                    compare_type=rule['compare_type'], key=rule.get('key'),
                    value=rule['value'],
                    tcp_tls_termination=listener.tcp_tls_termination)
                if weighted_tls_sni:
                    driver_utils.require_tls_sni_rule_comparison(
                        driver, rule['compare_type'],
                        listener.tcp_tls_termination and not passthrough)
            if any(rule['enabled'] and
                   rule['type'] == constants.L7RULE_TYPE_GRPC_CONTENT_TYPE
                   for rule in rules):
                driver_utils.require_grpc_request_metadata(
                    driver, listener.protocol,
                    l7policy_dict.get('request_header_operations'),
                    l7policy_dict.get('targets'))
                driver_utils.require_grpc_target_response_metadata(
                    driver, listener.protocol, l7policy_dict.get('targets'))
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
            weighted_action = constants.L7POLICY_ACTION_WEIGHTED_TARGETS
            weighted_tcp = tcp_policy and action == weighted_action
            pool_id = l7policy_dict.get('redirect_pool_id')
            if tcp_policy:
                if not weighted_tcp and l7policy.redirect_pool_id is None:
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
            auth = l7policy_dict.get('external_auth',
                                     db_l7policy.external_auth)
            if auth is not None and (
                    auth != db_l7policy.external_auth or (enabled and (
                        activates_policy or
                        hostname != db_l7policy.https_listener_hostname or
                        set(l7policy_dict).intersection(
                            routing_changed | {'redirect_pool_id'})))):
                driver_utils.require_l7policy_external_auth(
                    driver, listener.protocol, auth)
                driver_utils.require_l7policy_external_auth_transport(
                    driver, lock_session, listener, auth)
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
            expands_request_policy_scope = enabled and (
                activates_policy or routing_changed_or_disabled or
                targets != old_targets)
            if request_policy is not None and (
                    request_policy_changed or expands_request_policy_scope):
                driver_utils.require_http_request_policy(
                    driver, listener.protocol)
                if ('backoff_ms' in request_policy.get('retry', {}) and
                        (expands_request_policy_scope or
                         _expands_retry_backoff(
                             previous_request_policy, request_policy))):
                    driver_utils.require_http_retry_backoff(
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
            gate_routing = bool(routing_changed.intersection(l7policy_dict))
            if tcp_policy and db_l7policy.action == weighted_action:
                if enabled and not weighted_tcp:
                    # Changing an active selector to a scalar pool can
                    # redirect a share that was deliberately closed.
                    driver_utils.require_tls_sni_weighted_pools(
                        driver, passthrough=(
                            passthrough or not listener.tcp_tls_termination))
                if weighted_tcp and gate_routing:
                    old_positive = [target for target in old_targets
                                    if target['weight'] > 0]
                    positive = [target for target in targets
                                if target['weight'] > 0]
                    gate_routing = (positive != old_positive or
                                    any(targets.count(target) >
                                        old_targets.count(target)
                                        for target in targets))
            if activates_policy or gate_routing:
                retained_headers = {
                    field: getattr(db_l7policy, field)
                    for field in ('request_header_operations',
                                  'response_header_operations')
                    if field not in l7policy_dict}
                driver_utils.require_gateway_policy_action(
                    driver, action, listener.protocol,
                    tcp_tls_termination=listener.tcp_tls_termination,
                    tcp_tls_mixed_mode=listener.tcp_tls_mixed_mode,
                    tcp_tls_passthrough=passthrough,
                    targets=targets if weighted_tcp else None,
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
                    driver_utils.validate_tcp_policy_targets(
                        driver, policy_repo, lock_session, listener, action,
                        target, targets, passthrough,
                        active_targets_only=reopening)
            elif (listener.tcp_tls_mixed_mode and enabled and
                    position != db_l7policy.position):
                driver_utils.require_tcp_tls_mixed_mode(driver)
            validate_policy_headers(
                l7policy_dict, listener.protocol, driver,
                old_policy=db_l7policy)
            old_request_ops = db_l7policy.request_header_operations
            request_ops = l7policy_dict.get('request_header_operations',
                                            old_request_ops)
            changed_request_ops = (request_ops
                                   if request_ops != old_request_ops else None)
            response_ops = l7policy_dict.get('response_header_operations')
            updated_targets = l7policy_dict.get('targets')
            binary_scope_expanded = enabled and (
                reopening or position < db_l7policy.position or
                hostname != db_l7policy.https_listener_hostname)
            binary_ops = validate.grpc_binary_metadata_lists(request_ops)
            new_binary_ops = changed_request_ops and any(
                op not in (old_request_ops or [])
                for op in binary_ops)
            binary_forwarding_expanded = binary_ops and enabled and (
                binary_scope_expanded or routing_changed_or_disabled or
                adds_mirrors or (action == weighted_action and
                                 _expands_weighted_forwarding(
                                     old_targets, targets)))
            requires_binary_metadata = (
                new_binary_ops or binary_forwarding_expanded or
                any(_expanded_target_header_operations(
                    old_targets, targets, binary_scope_expanded,
                    field='request_header_operations',
                    select=validate.grpc_binary_metadata_lists)))
            target_response_field = 'response_header_operations'
            expanded_target_response = list(_expanded_target_header_operations(
                old_targets, targets, binary_scope_expanded,
                field=target_response_field))
            if expanded_target_response:
                driver_utils.require_weighted_target_response_headers(
                    driver, listener.protocol)
            if ((requires_binary_metadata or changed_request_ops or
                 response_ops or updated_targets or
                 expanded_target_response) and
                    policy_repo.has_enabled_l7rule(
                        lock_session, constants.L7RULE_TYPE_GRPC_CONTENT_TYPE,
                        policy_id=id)):
                if requires_binary_metadata:
                    driver_utils.require_grpc_binary_request_metadata(
                        driver, listener.protocol)
                if any(_expanded_target_header_operations(
                        old_targets, targets, binary_scope_expanded,
                        field=target_response_field,
                        select=validate.grpc_binary_metadata_lists)):
                    driver_utils.require_grpc_binary_response_metadata(
                        driver, listener.protocol)
                for operations in expanded_target_response:
                    validate.validate_grpc_target_response_headers(operations)
                # An existing occurrence can retain a legacy literal list.
                # A duplicate in the new array consumes a separate occurrence.
                retained = list(old_targets or [])
                added = []
                for target in updated_targets or []:
                    if target in retained:
                        retained.remove(target)
                    else:
                        added.append(target)
                validate.validate_grpc_metadata_fields(
                    changed_request_ops, response_ops, added)

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
                'http_request_policy' in l7policy_dict or
                'external_auth' in l7policy_dict)
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
        if l7policy_id and remainder and remainder[0] == 'conditional_removal':
            return L7PolicyRemovalController(l7policy_id), remainder[1:]
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
