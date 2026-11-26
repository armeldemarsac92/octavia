# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import copy
from typing import List
from typing import Optional

from oslo_config import cfg
from oslo_log import log as logging
from stevedore import driver as stevedore_driver
from taskflow import engines
from taskflow import retry
from taskflow import task
from taskflow.types import failure
import tenacity

from octavia.amphorae.backends.agent import agent_jinja_cfg
from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.api.drivers import driver_factory
from octavia.api.drivers import utils as driver_utils
from octavia.common import constants
from octavia.common import data_models as octavia_data_models
from octavia.common import exceptions
from octavia.common import l7policy_activation
from octavia.common import utils
from octavia.common import validate
from octavia.controller.worker import task_utils as task_utilities
from octavia.db import api as db_apis
from octavia.db import repositories as repo
from octavia.network import data_models

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _retry_render(operation, *args):
    config = CONF.haproxy_amphora
    wait_for_render = tenacity.Retrying(
        retry=tenacity.retry_if_exception_type(
            driver_except.ListenerRenderLockBusy),
        stop=tenacity.stop_after_attempt(config.connection_max_retries),
        wait=tenacity.wait_fixed(config.connection_retry_interval),
        reraise=True)
    return wait_for_render(operation, *args)


def _serialize_render(operation, loadbalancer_id, *args):
    """Hold the per-LB lock from the fresh graph read through publication."""
    def publish():
        with db_apis.listener_render_lock(loadbalancer_id) as acquired:
            if not acquired:
                raise driver_except.ListenerRenderLockBusy()
            return operation(loadbalancer_id, *args)

    if loadbalancer_id:
        return _retry_render(publish)


class BaseAmphoraTask(task.Task):
    """Base task to load drivers common to the tasks."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.amphora_driver = stevedore_driver.DriverManager(
            namespace='octavia.amphora.drivers',
            name=CONF.controller_worker.amphora_driver,
            invoke_on_load=True
        ).driver
        self.amphora_repo = repo.AmphoraRepository()
        self.listener_repo = repo.ListenerRepository()
        self.loadbalancer_repo = repo.LoadBalancerRepository()
        self.task_utils = task_utilities.TaskUtils()


class AmpRetry(retry.Times):

    def on_failure(self, history, *args, **kwargs):
        last_errors = history[-1][1]
        max_retry_attempt = CONF.haproxy_amphora.connection_max_retries
        for task_name, ex_info in last_errors.items():
            if len(history) <= max_retry_attempt:
                # When taskflow persistence is enabled and flow/task state is
                # saved in the backend. If flow(task) is restored(restart of
                # worker,etc) we are getting ex_info as None - we need to RETRY
                # task to check its real state.
                if ex_info is None or ex_info._exc_info is None:
                    return retry.RETRY
                excp = ex_info._exc_info[1]
                if isinstance(excp, driver_except.AmpConnectionRetry):
                    return retry.RETRY

        return retry.REVERT_ALL


def _has_managed_udp_listener(loadbalancer):
    return loadbalancer is not None and any(
        listener.protocol == constants.PROTOCOL_UDP and
        listener.default_pool is not None and
        listener.default_pool.udp_packet_drop is not None
        for listener in loadbalancer.listeners)


class AmpListenersUpdate(BaseAmphoraTask):
    """Task to update the listeners on one amphora."""

    def execute(self, loadbalancer, amphora, timeout_dict=None):
        lb_id = loadbalancer[constants.LOADBALANCER_ID]
        _serialize_render(self._update, lb_id, amphora, timeout_dict)

    def _update(self, loadbalancer_id, amphora, timeout_dict):
        # Stock failover may continue when an amphora fails to update.
        # A managed UDP listener must be installed before enabling VRRP.
        # TODO(johnsom) Optimize this to use the dicts and not need the
        #               DB lookups
        session = db_apis.get_session()
        with session.begin():
            if self.loadbalancer_repo.batch_owns_graph(
                    session, loadbalancer_id, tcp_only=True):
                return
            db_amp = self.amphora_repo.get(session, id=amphora[constants.ID])
            db_lb = self.loadbalancer_repo.get(session, id=loadbalancer_id)
        if db_lb is None:
            raise driver_except.ListenerProvisioningError()
        weighted = utils.has_tls_sni_passthrough_weighted_policies(
            db_lb, active=False)
        header_name_256 = validate.http_header_name_256_listeners(db_lb)
        finalizing = (
            db_lb.topology == constants.TOPOLOGY_SINGLE and
            (utils.active_http_retry_backoff_policies(db_lb) or weighted or
             utils.backend_tls_system_ca_pool_ids(db_lb) or header_name_256))
        strict = (finalizing or weighted or _has_managed_udp_listener(db_lb) or
                  header_name_256 or
                  utils.has_active_http_header_persistence(db_lb))
        if db_amp is None and strict:
            raise driver_except.ListenerProvisioningError()
        try:
            self.amphora_driver.update_amphora_listeners(
                db_lb, db_amp, timeout_dict,
                **({'finalizing_failover': True} if finalizing else {}))
        except Exception as e:
            LOG.error('Failed to update listeners on amphora %s. Skipping '
                      'this amphora as it is failing to update due to: %s',
                      amphora[constants.ID], str(e))
            if db_amp is not None:
                with session.begin():
                    self.amphora_repo.update(session, db_amp.id,
                                             status=constants.ERROR)
            if strict:
                raise


class AmphoraIndexListenerUpdate(BaseAmphoraTask):
    """Task to update the listeners on one amphora."""

    def execute(self, loadbalancer, amphora_index, amphorae,
                amphorae_status: dict, new_amphora_id: str, timeout_dict=()):
        lb_id = loadbalancer[constants.LOADBALANCER_ID]
        _serialize_render(self._update, lb_id, amphora_index, amphorae,
                          amphorae_status,
                          new_amphora_id, timeout_dict)

    def _update(self, loadbalancer_id, amphora_index, amphorae,
                amphorae_status, new_amphora_id, timeout_dict):
        session = db_apis.get_session()
        with session.begin():
            if self.loadbalancer_repo.batch_owns_graph(
                    session, loadbalancer_id, tcp_only=True):
                return
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer_id)
        managed_udp = _has_managed_udp_listener(db_lb)
        strict = (
            managed_udp or validate.http_header_name_256_listeners(db_lb) or
            utils.active_http_retry_backoff_policies(db_lb) or
            utils.backend_tls_system_ca_pool_ids(db_lb) or
            utils.has_active_http_header_persistence(db_lb) or
            utils.has_tls_sni_passthrough_weighted_policies(
                db_lb, active=False))
        if managed_udp and any(
                status.get(constants.UNREACHABLE)
                for status in amphorae_status.values()):
            raise driver_except.ListenerProvisioningError()
        try:
            if self.amphora_driver.update_failover_listeners(
                    db_lb, amphora_index, amphorae_status,
                    timeout_dict) is True:
                return
        except driver_except.CoordinatedListenerUpdateError as error:
            for amphora_id, cause in error.amphora_errors.items():
                self._handle_update_failure(amphora_id, new_amphora_id, cause)
            if strict:
                raise
            return

        # Note, we don't want this to cause a revert as it may be used
        # in a failover flow with both amps failing. Skip it and let
        # health manager fix it.

        amphora_id = amphorae[amphora_index].get(constants.ID)
        amphora_status = amphorae_status.get(amphora_id, {})
        if amphora_status.get(constants.UNREACHABLE):
            if strict:
                raise driver_except.ListenerProvisioningError()
            LOG.warning("Skipping listener update because amphora %s "
                        "is not reachable.", amphora_id)
            return

        try:
            # TODO(johnsom) Optimize this to use the dicts and not need the
            #               DB lookups
            with session.begin():
                db_amp = self.amphora_repo.get(
                    session,
                    id=amphorae[amphora_index][constants.ID])
            if strict and db_amp is None:
                raise driver_except.ListenerProvisioningError()
            self.amphora_driver.update_amphora_listeners(
                db_lb, db_amp, timeout_dict)
        except Exception as error:
            self._handle_update_failure(amphora_id, new_amphora_id, error)
            if strict:
                raise

    def _handle_update_failure(self, amphora_id, new_amphora_id, error):
        LOG.error('Failed to update listeners on amphora %s. Skipping '
                  'this amphora as it is failing to update due to: %s',
                  amphora_id, str(error))
        # Health manager handles a surviving peer. Only mark the replacement.
        if amphora_id == new_amphora_id:
            session = db_apis.get_session()
            with session.begin():
                self.amphora_repo.update(session, amphora_id,
                                         status=constants.ERROR)


_HEADER_RULE_MATCH_FIELDS = ('type', 'compare_type', 'key', 'value', 'invert')


def _http_header_name_changes(loadbalancer, original, updates):
    """Return rollback attributes for fresh dependent admission."""
    changes = [
        (rule, {'enabled': False})
        for listener in loadbalancer.listeners
        for policy in listener.l7policies
        for rule in policy.l7rules
        if (rule.provisioning_status == constants.PENDING_CREATE and
            validate.is_http_header_name_256(rule.type, rule.key))]
    if not original or not updates:
        return changes

    old_enabled = original.get(constants.ADMIN_STATE_UP)
    new_enabled = updates.get('enabled', updates.get(constants.ADMIN_STATE_UP))
    rule_id = original.get(constants.L7RULE_ID)
    policy_id = original.get(constants.L7POLICY_ID)
    listener_id = original.get(constants.LISTENER_ID)
    reopen = old_enabled is False and new_enabled is True
    for listener in loadbalancer.listeners:
        if listener_id and listener.id != listener_id:
            continue
        for policy in listener.l7policies:
            if policy_id and policy.id != policy_id:
                continue
            for rule in policy.l7rules:
                if rule_id:
                    if (rule.id != rule_id or rule.provisioning_status !=
                            constants.PENDING_UPDATE):
                        continue
                    updated = {field: original.get(field)
                               for field in _HEADER_RULE_MATCH_FIELDS
                               if (field in updates and
                                   updates[field] == getattr(rule, field) and
                                   updates[field] != original.get(field))}
                    old_dependency = validate.is_http_header_name_256(
                        original.get('type'), original.get('key'))
                    new_dependency = validate.is_http_header_name_256(
                        rule.type, rule.key)
                    active_policy = (old_enabled and policy.enabled and
                                     listener.enabled and
                                     loadbalancer.enabled)
                    retiring_dependency = False
                    if active_policy and new_enabled is False:
                        remaining = [
                            sibling for sibling in policy.l7rules
                            if (sibling.id != rule.id and sibling.enabled and
                                sibling.provisioning_status not in (
                                    constants.PENDING_DELETE,
                                    constants.DELETED))]
                        retiring_dependency = bool(remaining) and (
                            old_dependency or any(
                                validate.is_http_header_name_256(
                                    sibling.type, sibling.key)
                                for sibling in remaining))
                    active_mutation = (
                        old_dependency and active_policy and rule.enabled)
                    match_changed = updated and (
                        new_dependency or active_mutation)
                    if (retiring_dependency or match_changed or
                            (reopen and new_dependency)):
                        if 'enabled' in updates and old_enabled is not None:
                            updated['enabled'] = old_enabled
                        changes.append((rule, updated))
                elif (reopen and rule.enabled and
                      rule.provisioning_status not in (
                          constants.PENDING_DELETE, constants.DELETED) and
                      validate.is_http_header_name_256(rule.type, rule.key)):
                    if policy_id:
                        resource = policy
                    elif listener_id:
                        resource = listener
                    else:
                        resource = loadbalancer
                    changes.append((resource, {'enabled': False}))
    return changes


def _withdraws_http_listener_state(loadbalancer, original, updates):
    """Identify closures that can be published on a degraded pair."""
    enabled = updates.get('enabled', updates.get(constants.ADMIN_STATE_UP))
    shrinking = enabled is False
    rule_id = original.get(constants.L7RULE_ID)
    policy_id = original.get(constants.L7POLICY_ID)
    if shrinking and not rule_id:
        return True
    for listener in loadbalancer.listeners:
        for policy in listener.l7policies:
            if policy.provisioning_status == constants.PENDING_DELETE:
                return True
            policy_closed = not (listener.enabled and policy.enabled)
            if policy_closed and (
                    (policy_id and policy.id == policy_id) or
                    (rule_id and any(rule.id == rule_id
                                     for rule in policy.l7rules))):
                return True
            retired = any(
                rule.provisioning_status == constants.PENDING_DELETE or
                (shrinking and rule.id == rule_id)
                for rule in policy.l7rules)
            if retired and (policy_closed or not any(
                    rule.enabled and rule.provisioning_status not in (
                        constants.PENDING_DELETE, constants.DELETED)
                    for rule in policy.l7rules)):
                return True
    return False


class ListenersUpdate(BaseAmphoraTask):
    """Task to update amphora with all specified listeners' configurations."""

    def execute(self, loadbalancer_id, original=None, updates=None):
        """Execute updates per listener for an amphora."""
        if original is None:
            _serialize_render(self._update, loadbalancer_id)
        else:
            _serialize_render(self._update, loadbalancer_id, None,
                              original, updates)

    @staticmethod
    def _scope_for_udp_pool(loadbalancer, pool_id):
        if pool_id is not None:
            pool = next((pool for pool in loadbalancer.pools
                         if pool.id == pool_id), None)
            if pool and pool.protocol == constants.PROTOCOL_UDP:
                return pool.listeners
        return None

    def _restore_header_name_changes(self, session, changes):
        repositories = {
            octavia_data_models.L7Rule: repo.L7RuleRepository,
            octavia_data_models.L7Policy: repo.L7PolicyRepository,
            octavia_data_models.Listener: repo.ListenerRepository,
            octavia_data_models.LoadBalancer: repo.LoadBalancerRepository,
        }
        for resource, attributes in changes:
            repositories[type(resource)]().update(
                session, resource.id, **attributes)

    def _update(self, loadbalancer_id, pool_id=None, original=None,
                updates=None):
        session = db_apis.get_session()
        unsupported = None
        changes = []
        withdrawal = False
        weighted_update = self._is_tcp_default_targets_update(updates)
        target_id = (original or {}).get(constants.LISTENER_ID)
        revision = (updates or {}).get('tcp_default_targets_revision')
        with session.begin():
            if self.loadbalancer_repo.batch_owns_graph(
                    session, loadbalancer_id):
                return
            loadbalancer = self.loadbalancer_repo.get(session,
                                                      id=loadbalancer_id)
            if loadbalancer:
                if revision and utils.pending_tcp_default_target_revisions(
                        loadbalancer).get(target_id) != revision:
                    return
                changes = _http_header_name_changes(
                    loadbalancer, original, updates)
                if changes:
                    driver = driver_factory.get_driver(loadbalancer.provider)
                    try:
                        driver_utils.require_http_header_name_256(driver)
                    except exceptions.ProviderUnsupportedOptionError as error:
                        unsupported = error
                        self._restore_header_name_changes(session, changes)
                if (not changes and
                        validate.http_header_name_256_listeners(loadbalancer)):
                    withdrawal = _withdraws_http_listener_state(
                        loadbalancer, original or {}, updates or {})
        if unsupported:
            raise unsupported
        if loadbalancer:
            scoped = self._scope_for_udp_pool(loadbalancer, pool_id)
            if scoped is not None:
                update_udp = getattr(
                    self.amphora_driver, 'update_udp_pool_listeners', None)
                if callable(update_udp):
                    update_udp(loadbalancer, [item.id for item in scoped])
                    return
            try:
                self.amphora_driver.update(
                    loadbalancer,
                    **({'http_header_name_withdrawal': True}
                       if withdrawal else {}),
                    **({'require_http_header_name_256': True}
                       if changes else {}),
                    **({'tcp_default_targets_update': True}
                       if weighted_update else {}))
            except driver_except.HttpHeaderName256Unsupported:
                # The capability preflight failed before any publication.
                if changes:
                    with session.begin():
                        self._restore_header_name_changes(session, changes)
                raise
        else:
            LOG.error('Load balancer %s for listeners update not found. '
                      'Skipping update.', loadbalancer_id)

    @staticmethod
    def _is_tcp_default_targets_update(updates):
        return bool({'tcp_default_targets', 'tcp_default_targets_revision'}
                    .intersection(updates or {}))

    def revert(self, loadbalancer_id, original=None, updates=None,
               *args, **kwargs):
        """Handle failed listeners updates."""
        target = (original or {}).get(constants.LISTENER_ID)
        if target and self._is_tcp_default_targets_update(updates):
            revision = updates.get('tcp_default_targets_revision')
            self._mark_tcp_default_targets_error(
                loadbalancer_id, target, revision)
            return
        self._mark_listeners_error(loadbalancer_id)

    def _mark_tcp_default_targets_error(self, lb_id, target, revision):
        session = db_apis.get_session()
        with session.begin():
            lb = self.loadbalancer_repo.get_for_update(session, lb_id)
            if lb is None:
                return
            listener_repository = repo.ListenerRepository()
            listener = listener_repository.get_orm(
                session, id=target, load_balancer_id=lb_id,
                project_id=lb.project_id)
            if (listener is None or
                    listener.provisioning_status in (
                        constants.PENDING_DELETE, constants.DELETED) or
                    (revision and
                     listener.tcp_default_targets_revision != revision)):
                return
            if (listener.tcp_default_targets_status ==
                    constants.PENDING_UPDATE):
                listener.tcp_default_targets_status = constants.ERROR
            listener_repository.update(
                session, target, provisioning_status=constants.ERROR)

    def _mark_listeners_error(self, loadbalancer_id, pool_id=None):
        LOG.warning("Reverting listeners updates.")
        session = db_apis.get_session()
        with session.begin():
            loadbalancer = self.loadbalancer_repo.get(session,
                                                      id=loadbalancer_id)
        scoped = self._scope_for_udp_pool(loadbalancer, pool_id)
        for listener in (loadbalancer.listeners if scoped is None else scoped):
            self.task_utils.mark_listener_prov_status_error(
                listener.id)


class PoolDeleteListenersUpdate(ListenersUpdate):
    """Render only the listeners affected by deleting a UDP pool."""

    def execute(self, loadbalancer_id, pool_id):
        _serialize_render(self._update, loadbalancer_id, pool_id)

    def revert(self, loadbalancer_id, pool_id, *args, **kwargs):
        self._mark_listeners_error(loadbalancer_id, pool_id)


class _ManagedPoolOperation(BaseAmphoraTask):
    """Fence stale and duplicate deliveries against the committed operation."""

    action = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pool_repo = repo.PoolRepository()

    def execute(self, loadbalancer_id, pool_id, batch_id):
        _serialize_render(self._apply, loadbalancer_id, pool_id, batch_id)

    def _owned(self, session, lb_id, pool_id, batch_id):
        # The API casts while holding this row. A worker arriving early
        # waits for commit and an API rollback leaves no matching batch.
        lb = self.loadbalancer_repo.get_for_update(session, lb_id)
        if (lb is None or lb.provisioning_status != constants.PENDING_UPDATE or
                not self.loadbalancer_repo.tcp_batch_pending(lb)):
            return None, None
        operation = lb.tcp_member_batch
        if (operation['id'] != batch_id or operation['pool_id'] != pool_id or
                operation.get('action') != self.action or
                operation.get('protocol', constants.PROTOCOL_TCP) !=
                self.protocol):
            return None, None
        pool = self.pool_repo.get_orm(session, id=pool_id,
                                      load_balancer_id=lb_id,
                                      show_deleted=False)
        if pool is None or pool.tcp_member_batch_id != batch_id:
            return None, None
        return lb, pool

    @staticmethod
    def _finish_status(lb, *, applied):
        listener_ids = set(lb.tcp_member_batch['listener_ids'])
        for listener in lb.listeners:
            if (listener.id in listener_ids and
                    listener.provisioning_status == constants.PENDING_UPDATE):
                listener.provisioning_status = (constants.ACTIVE if applied
                                                else constants.ERROR)
        lb.tcp_member_batch = {
            **lb.tcp_member_batch,
            'phase': (constants.TCP_MEMBER_BATCH_APPLIED if applied
                      else constants.TCP_MEMBER_BATCH_FAILED),
        }
        lb.provisioning_status = constants.ACTIVE


class _ApplyManagedMemberBatch(_ManagedPoolOperation):
    """Apply one committed member graph and drop or rejection fraction."""

    def __init__(self, network_flow, **kwargs):
        super().__init__(**kwargs)
        self.network_flow = network_flow
        self.member_repo = repo.MemberRepository()
        self.az_repo = repo.AvailabilityZoneRepository()

    def _apply(self, lb_id, pool_id, batch_id):
        with db_apis.session().begin() as session:
            lb, pool = self._owned(session, lb_id, pool_id, batch_id)
            if pool is None:
                return
            if pool.provisioning_status != constants.PENDING_UPDATE:
                raise driver_except.ListenerProvisioningError()
            az = (self.az_repo.get_availability_zone_metadata_dict(
                session, lb.availability_zone)
                if lb.availability_zone else {})
            graph = lb.to_data_model()
            listener_ids = lb.tcp_member_batch['listener_ids']

        try:
            engines.run(self.network_flow, store={
                constants.LOADBALANCER_ID: lb_id,
                constants.LOADBALANCER: {
                    constants.LOADBALANCER_ID: lb_id,
                    constants.VIP_SUBNET_ID: graph.vip.subnet_id,
                    constants.VIP_NETWORK_ID: graph.vip.network_id,
                },
                constants.AVAILABILITY_ZONE: az,
            })
            receipt = self._render(graph, listener_ids)
            self._finish(lb_id, pool_id, batch_id, applied=True,
                         receipt=receipt)
        except Exception:
            self._finish(lb_id, pool_id, batch_id, applied=False)
            raise

    def _confirm_render(self, lb, receipt):
        """Verify worker-specific activation evidence under the LB lock."""

    def _finish(self, lb_id, pool_id, batch_id, *, applied, receipt=None):
        with db_apis.session().begin() as session:
            lb, pool = self._owned(session, lb_id, pool_id, batch_id)
            if pool is None:
                return
            if (applied and
                    pool.provisioning_status == constants.PENDING_UPDATE):
                self._confirm_render(lb, receipt)
                pool.provisioning_status = constants.ACTIVE
                pool.tcp_member_batch_id = None
                for member in self.member_repo.get_batch_for_update(
                        session, pool_id):
                    if member.provisioning_status == constants.PENDING_DELETE:
                        session.delete(member)
                    elif member.provisioning_status in (
                            constants.PENDING_CREATE,
                            constants.PENDING_UPDATE):
                        member.provisioning_status = constants.ACTIVE
            else:
                # Keep both desired values for a replacement after a failed
                # or partial reload. Never acknowledge the pool as ACTIVE.
                pool.provisioning_status = constants.ERROR
                pool.tcp_member_batch_id = constants.TCP_MEMBER_BATCH_FAILED
            self._finish_status(
                lb, applied=pool.provisioning_status == constants.ACTIVE)


class ApplyTCPMemberBatch(_ApplyManagedMemberBatch):
    """Apply the TCP member graph and connection rejection fraction."""

    protocol = constants.PROTOCOL_TCP

    def _render(self, graph, listener_ids):
        self.amphora_driver.update(graph, tcp_member_batch=True)


def _confirm_udp_peers(loadbalancer, receipt):
    current = tuple(sorted(
        (amp.id, amp.role) for amp in loadbalancer.amphorae
        if amp.status == constants.AMPHORA_ALLOCATED))
    if not receipt or receipt != current:
        raise driver_except.ListenerProvisioningError()


class ApplyUDPMemberBatch(_ApplyManagedMemberBatch):
    """Apply one committed UDP member graph and its drop fraction."""

    protocol = constants.PROTOCOL_UDP

    def _render(self, graph, listener_ids):
        listener_id, = listener_ids
        return self.amphora_driver.apply_udp_member_batch(graph, listener_id)

    def _confirm_render(self, lb, receipt):
        _confirm_udp_peers(lb, receipt)


class DeleteManagedUDPPool(_ManagedPoolOperation):
    """Retire the scoped listener before releasing the managed pool."""

    protocol = constants.PROTOCOL_UDP
    action = constants.UDP_POOL_DELETE_ACTION

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.repos = repo.Repositories()

    def _apply(self, lb_id, pool_id, batch_id):
        with db_apis.session().begin() as session:
            lb, pool = self._owned(session, lb_id, pool_id, batch_id)
            if pool is None:
                return
            if pool.provisioning_status != constants.PENDING_DELETE:
                raise driver_except.ListenerProvisioningError()
            graph = lb.to_data_model()
            listener_ids = lb.tcp_member_batch['listener_ids']
        try:
            receipt = self.amphora_driver.update_udp_pool_listeners(
                graph, listener_ids)
            self._finish(lb_id, pool_id, batch_id, applied=True,
                         receipt=receipt)
        except Exception:
            self._finish(lb_id, pool_id, batch_id, applied=False)
            raise

    def _finish(self, lb_id, pool_id, batch_id, *, applied, receipt=None):
        with db_apis.session().begin() as session:
            lb, pool = self._owned(session, lb_id, pool_id, batch_id)
            if pool is None:
                return
            if applied:
                if lb.tcp_member_batch['listener_ids']:
                    _confirm_udp_peers(lb, receipt)
                health_monitors, members = self.pool_repo.get_children_count(
                    session, pool.id)
                for resource, count in (
                        (octavia_data_models.Pool, 1),
                        (octavia_data_models.HealthMonitor, health_monitors),
                        (octavia_data_models.Member, members)):
                    if count:
                        self.repos.decrement_quota(
                            session, resource, pool.project_id, quantity=count)
                session.delete(pool)
            else:
                pool.provisioning_status = constants.ERROR
                pool.tcp_member_batch_id = constants.TCP_MEMBER_BATCH_FAILED
            self._finish_status(lb, applied=applied)


class ApplyL7PolicyWithInitialRules(BaseAmphoraTask):
    """Serialize render and completion against duplicate create deliveries."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.l7policy_repo = repo.L7PolicyRepository()
        self.l7rule_repo = repo.L7RuleRepository()

    def execute(self, l7policy):
        _serialize_render(self._apply, l7policy[constants.LOADBALANCER_ID],
                          l7policy)

    def _apply(self, lb_id, l7policy):
        policy_id = l7policy[constants.L7POLICY_ID]
        expected_ids = {rule[constants.L7RULE_ID]
                        for rule in l7policy['rules']}
        update_error = None
        # Wait for the API transaction, which holds the load balancer row
        # when it dispatches the RPC. Release it before the Amphora call so
        # API mutations can observe the existing PENDING_UPDATE state.
        with db_apis.session().begin() as session:
            if (not self.loadbalancer_repo.lock(session, lb_id) or
                    self.loadbalancer_repo.batch_owns_graph(
                        session, lb_id, tcp_only=True)):
                return

        # Serialize duplicate deliveries through status publication. A
        # duplicate cannot render stale state or clear a later LB status.
        with db_apis.session().begin() as session:
            try:
                policy = self.l7policy_repo.get_for_update(session, policy_id)
            except exceptions.NotFound:
                return
            if policy.provisioning_status != constants.PENDING_CREATE:
                return

            rules = policy.l7rules
            try:
                rule_ids = {rule.id for rule in rules}
                if policy.enabled or rule_ids != expected_ids:
                    raise exceptions.InvalidL7PolicyArgs(msg=(
                        'The disabled policy and its complete set of rules '
                        'are required for initial provisioning.'))
                loadbalancer = self.loadbalancer_repo.get(session, id=lb_id)
                if any(validate.is_http_header_name_256(rule.type, rule.key)
                       for rule in rules):
                    driver_utils.require_http_header_name_256(
                        driver_factory.get_driver(loadbalancer.provider))
                self.amphora_driver.update(loadbalancer)
            except Exception as e:
                update_error = e

            succeeded = update_error is None
            status = constants.ACTIVE if succeeded else constants.ERROR
            for rule in rules:
                if rule.provisioning_status == constants.PENDING_CREATE:
                    operating_status = (
                        constants.ONLINE if succeeded and rule.enabled
                        else constants.OFFLINE)
                    self.l7rule_repo.update(
                        session, rule.id, provisioning_status=status,
                        operating_status=operating_status)
            policy.provisioning_status = status
            self.listener_repo.prov_status_active_if_not_error(
                session, policy.listener_id)
            self.loadbalancer_repo.update(
                session, lb_id, provisioning_status=constants.ACTIVE)

        if update_error is not None:
            raise update_error


class ApplyL7PolicyActivation(BaseAmphoraTask):
    """Recover and finish a durable group activation."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.repositories = repo.Repositories()

    def _owned(self, session, delivery):
        lb = self.loadbalancer_repo.get_for_update(
            session, delivery['loadbalancer_id'])
        operation = lb.l7policy_activation if lb else None
        if (not operation or operation['id'] != delivery['id'] or
                operation['phase'] not in l7policy_activation.PENDING):
            return None
        listener = self.listener_repo.get_for_update(
            session, operation['listener_id'], show_deleted=False)
        return lb, listener, operation

    def _matches(self, session, lb, listener, request):
        if (lb.provisioning_status != constants.PENDING_UPDATE or
                listener.provisioning_status != constants.PENDING_UPDATE or
                listener.load_balancer_id != lb.id or
                listener.project_id != lb.project_id):
            return False
        try:
            graph, policies = l7policy_activation.snapshot(
                session, self.repositories, lb, listener, pending=True,
                additional_pools=l7policy_activation.transition_pools(
                    request))
        except exceptions.L7PolicyActivationConflict:
            return False
        expected = request['policies']
        transition = request.get('grpc_auth_transition')
        driver = None
        if transition:
            driver = driver_factory.get_driver(lb.provider)
            if not l7policy_activation.grpc_auth_transition_available(
                    driver, listener):
                return False
            try:
                for change in transition.values():
                    if change['origin'] is not None:
                        driver_utils.require_l7policy_external_auth(
                            driver, listener.protocol, change['external_auth'])
            except (exceptions.ProviderUnsupportedOptionError,
                    exceptions.ValidationException):
                return False
        selected = [p for p in policies if p.id in expected]
        # A transition to the fixed 500 preserves the existing predicates.
        # Only activation or restoration of an origin requires enrollment.
        activating_rules = [
            rule for policy in selected
            if not transition or transition[policy.id]['origin'] is not None
            for rule in policy.l7rules if rule.enabled]
        long_hostname = any(validate.is_long_http_hostname_regex(
            rule.type, rule.compare_type, rule.value)
            for rule in activating_rules)
        literal_path = any(
            rule.type == constants.L7RULE_TYPE_HTTP_PATH_LITERAL
            for rule in activating_rules)
        header_name_256 = any(validate.is_http_header_name_256(
            rule.type, rule.key) for rule in activating_rules)
        if long_hostname or literal_path or header_name_256:
            driver = driver or driver_factory.get_driver(lb.provider)
            if ((long_hostname and
                 not driver_utils.http_long_hostname_available(driver)) or
                (literal_path and
                 not driver_utils.http_literal_path_available(driver)) or
                (header_name_256 and
                 not driver_utils.http_header_name_256_available(driver))):
                return False
        if listener.protocol == constants.PROTOCOL_TCP:
            driver = driver_factory.get_driver(lb.provider)
            if not driver_utils.l7policy_batch_activation_available(
                    driver, listener):
                return False
            if any(rule.enabled and
                   rule.compare_type == constants.L7RULE_COMPARE_TYPE_ENDS_WITH
                   for policy in selected for rule in policy.l7rules):
                try:
                    driver_utils.require_tls_sni_suffix(driver)
                except exceptions.ProviderUnsupportedOptionError:
                    return False
        return (
            graph.graph_revision == request['graph_revision'] and
            [p.id for p in policies] == request['order'] and
            len(selected) == len(expected) and
            all(p.provisioning_status == constants.PENDING_UPDATE and
                p.enabled == bool(transition) and
                all(rule.provisioning_status == constants.ACTIVE
                    for rule in p.l7rules) and
                l7policy_activation.policy_revision(p) == expected[p.id]
                for p in selected))

    @staticmethod
    def _selected(lb, listener, operation):
        return [policy for policy in listener.l7policies
                if policy.id in operation['request']['policies'] and
                policy.project_id == lb.project_id]

    @staticmethod
    def _original_grpc_barriers(transition, policies, expected):
        return (len(policies) == len(transition) and
                all(policy.enabled and
                    policy.action ==
                    constants.L7POLICY_ACTION_FIXED_RESPONSE and
                    policy.fixed_response == {'status_code': 500} and
                    policy.external_auth is None and
                    l7policy_activation.policy_revision(policy) ==
                    expected[policy.id] for policy in policies))

    def _prepare(self, delivery, *, revert=False):
        with db_apis.session().begin() as session:
            owned = self._owned(session, delivery)
            if not owned:
                return None, False
            lb, listener, operation = owned
            request = operation['request']
            transition = request.get('grpc_auth_transition')
            withdraws = l7policy_activation.withdraws_grpc_auth(request)
            # A worker that crashes after sending a restoration can only
            # reassert the original 500s. A new write must prove intent again.
            restoration_expired = (
                transition and not withdraws and
                (operation['phase'] != 'pending' or
                 l7policy_activation.grpc_auth_recovery_ready(operation)))
            restoring = (revert or operation['phase'] == 'reverting' or
                         restoration_expired or
                         not self._matches(session, lb, listener, request))
            lb.l7policy_activation = {
                **operation, 'phase': 'reverting' if restoring else
                'rendering'}
            policies = self._selected(lb, listener, operation)
            if transition:
                candidate = lb.to_data_model()
                frontend = next(row for row in candidate.listeners
                                if row.id == listener.id)
                if restoring:
                    if withdraws or not self._original_grpc_barriers(
                            transition, policies, request['policies']):
                        frontend.enabled = False
                    return candidate, True
                pools = {pool.id: pool for pool in candidate.pools}
                linked_pool_ids = {pool.id for pool in frontend.pools}
                withdrawn_pool_ids = set()
                for policy in frontend.l7policies:
                    change = transition.get(policy.id)
                    if change is None:
                        continue
                    if policy.redirect_pool is not None:
                        withdrawn_pool_ids.add(policy.redirect_pool.id)
                        policy.redirect_pool.l7policies.remove(policy)
                    if policy.external_auth is not None:
                        withdrawn_pool_ids.add(policy.external_auth['pool_id'])
                    origin = change['origin']
                    pool = pools[origin] if origin else None
                    l7policy_activation.apply_transition(policy, change, pool)
                    if pool:
                        pool.l7policies.append(policy)
                        if pool.id not in linked_pool_ids:
                            frontend.pools.append(pool)
                            linked_pool_ids.add(pool.id)
                        authorizer = pools[change['external_auth']['pool_id']]
                        for destination in (pool, authorizer):
                            if all(row.id != frontend.id
                                   for row in destination.listeners):
                                destination.listeners.append(frontend)
                if withdrawn_pool_ids:
                    # Resolve both directions from the SQL graph's remaining
                    # references before staging any protected TLS pools.
                    remaining_pool_ids = {
                        pool.id for pool in listener._linked_pools(
                            withdrawn_policies=transition)}
                    frontend.pools = [pool for pool in frontend.pools
                                      if pool.id in remaining_pool_ids]
                    for pool in lb.pools:
                        if (pool.id in withdrawn_pool_ids and
                                all(row.id != frontend.id for row in
                                    pool._linked_listeners(
                                        withdrawn_policies=transition))):
                            candidate_pool = pools[pool.id]
                            candidate_pool.listeners = [
                                row for row in candidate_pool.listeners
                                if row.id != frontend.id]
                return candidate, False
            if restoring:
                for policy in policies:
                    policy.enabled = False
                return lb.to_data_model(), True
            # Render a candidate graph while keeping the persisted flags
            # disabled. A crash leaves the original operation replayable.
            with session.no_autoflush:
                for policy in policies:
                    policy.enabled = True
                try:
                    candidate = lb.to_data_model()
                finally:
                    for policy in policies:
                        policy.enabled = False
            return candidate, False

    def _finish(self, delivery, *, applied, healthy, recovered_pools=None):
        with db_apis.session().begin() as session:
            owned = self._owned(session, delivery)
            if not owned:
                return True
            lb, listener, operation = owned
            if applied and not self._matches(session, lb, listener,
                                             operation['request']):
                return False
            if recovered_pools:
                self.repositories.pool.set_backend_tls_pool_statuses(
                    session, closed=(), recovered=recovered_pools)
            request = operation['request']
            transition = request.get('grpc_auth_transition')
            selected = self._selected(lb, listener, operation)
            barrier_confirmed = False
            if transition and not applied and healthy:
                barrier_confirmed = self._original_grpc_barriers(
                    transition, selected, request['policies'])
                if not barrier_confirmed:
                    listener.enabled = False
            pools = {pool.id: pool for pool in lb.pools} if transition else {}
            for policy in selected:
                if transition:
                    if applied:
                        change = transition[policy.id]
                        policy_repo = self.repositories.l7policy
                        policy_repo._replace_external_auth_pool_ref(
                            session, policy.id, listener, policy.project_id,
                            change['external_auth'])
                        l7policy_activation.apply_transition(
                            policy, change, pools.get(change['origin']))
                else:
                    policy.enabled = applied
                healthy_policy = applied or barrier_confirmed
                policy.provisioning_status = (constants.ACTIVE
                                              if healthy_policy
                                              else constants.ERROR)
                policy.operating_status = (constants.ONLINE if healthy_policy
                                           else constants.OFFLINE)
            status = constants.ACTIVE if healthy else constants.ERROR
            lb.provisioning_status = status
            listener.provisioning_status = (
                constants.ERROR if listener.frontend_fallback_owns_error
                is True else status)
            if applied:
                phase = 'applied'
            else:
                # Keep the recovery authority when Amphora did not confirm
                # the disabled graph. A redelivery can finish compensation.
                phase = 'failed' if healthy else 'reverting'
            result = {**operation, 'phase': phase}
            if applied:
                session.flush()
                graph, _policies = l7policy_activation.snapshot(
                    session, self.repositories, lb, listener,
                    additional_pools=l7policy_activation.transition_pools(
                        request))
                result['applied_revision'] = graph.graph_revision
            lb.l7policy_activation = result
            return True

    def _restore(self, delivery, graph):
        try:
            recovered = self.amphora_driver.update(
                graph, l7policy_activation=True, l7policy_restoration=True)
        except Exception:
            self._finish(delivery, applied=False, healthy=False)
            raise
        self._finish(delivery, applied=False, healthy=True,
                     recovered_pools=recovered)

    def execute(self, l7policy_activation):
        _retry_render(self._execute_locked, l7policy_activation)

    def _execute_locked(self, delivery):
        with db_apis.listener_render_lock(delivery['loadbalancer_id']) as lock:
            if not lock:
                raise driver_except.ListenerRenderLockBusy()
            graph, restoring = self._prepare(delivery)
            if graph is None:
                return
            if restoring:
                self._restore(delivery, graph)
                return
            try:
                recovered = self.amphora_driver.update(
                    graph, l7policy_activation=True)
            except Exception:
                graph, _restoring = self._prepare(delivery, revert=True)
                if graph is not None:
                    self._restore(delivery, graph)
                raise
            if not self._finish(delivery, applied=True, healthy=True,
                                recovered_pools=recovered):
                graph, _restoring = self._prepare(delivery, revert=True)
                if graph is not None:
                    self._restore(delivery, graph)


class ListenersStart(BaseAmphoraTask):
    """Task to start all listeners on the vip."""

    def execute(self, loadbalancer, amphora=None):
        """Execute listener start routines for listeners on an amphora."""
        _serialize_render(self._start, loadbalancer[constants.LOADBALANCER_ID],
                          amphora)

    def _start(self, loadbalancer_id, amphora):
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer_id)
        if db_lb.listeners:
            if amphora is not None:
                with session.begin():
                    db_amp = self.amphora_repo.get(session,
                                                   id=amphora[constants.ID])
            else:
                db_amp = amphora
            self.amphora_driver.start(db_lb, db_amp)
            LOG.debug("Started the listeners on the vip")

    def revert(self, loadbalancer, *args, **kwargs):
        """Handle failed listeners starts."""

        LOG.warning("Reverting listeners starts.")
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer[constants.LOADBALANCER_ID])
        for listener in db_lb.listeners:
            self.task_utils.mark_listener_prov_status_error(listener.id)


class AmphoraIndexListenersReload(BaseAmphoraTask):
    """Task to reload all listeners on an amphora."""

    def execute(self, loadbalancer, amphora_index, amphorae,
                amphorae_status: dict, new_amphora_id: str, timeout_dict=None):
        """Execute listener reload routines for listeners on an amphora."""
        if amphorae is None:
            return
        lb_id = loadbalancer[constants.LOADBALANCER_ID]
        _serialize_render(self._reload, lb_id, amphora_index, amphorae,
                          amphorae_status,
                          new_amphora_id, timeout_dict)

    def _reload(self, loadbalancer_id, amphora_index, amphorae,
                amphorae_status, new_amphora_id, timeout_dict):
        amphora_id = amphorae[amphora_index].get(constants.ID)
        amphora_status = amphorae_status.get(amphora_id, {})
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(session, id=loadbalancer_id)
        strict = (
            validate.http_header_name_256_listeners(db_lb) or
            utils.active_http_retry_backoff_policies(db_lb) or
            utils.has_tls_sni_passthrough_weighted_policies(
                db_lb, active=False))
        if amphora_status.get(constants.UNREACHABLE):
            if strict:
                raise driver_except.ListenerProvisioningError()
            LOG.warning("Skipping listener reload because amphora %s "
                        "is not reachable.", amphora_id)
            return

        # TODO(johnsom) Optimize this to use the dicts and not need the
        #               DB lookups
        with session.begin():
            db_amp = self.amphora_repo.get(
                session, id=amphorae[amphora_index][constants.ID])
        if strict and db_amp is None:
            raise driver_except.ListenerProvisioningError()
        if db_lb.listeners:
            try:
                self.amphora_driver.reload(db_lb, db_amp, timeout_dict)
            except Exception as e:
                LOG.warning('Failed to reload listeners on amphora %s. '
                            'Skipping this amphora as it is failing to '
                            'reload due to: %s', amphora_id, str(e))
                # Update only the status of the newly created amphora during
                # the failover
                if amphora_id == new_amphora_id:
                    with session.begin():
                        self.amphora_repo.update(session, amphora_id,
                                                 status=constants.ERROR)
                if strict or _has_managed_udp_listener(db_lb):
                    raise


class ListenerDelete(BaseAmphoraTask):
    """Task to delete the listener on the vip."""

    def execute(self, listener):
        """Execute listener delete routines for an amphora."""
        _serialize_render(self._delete, listener[constants.LOADBALANCER_ID],
                          listener[constants.LISTENER_ID])

    def _delete(self, loadbalancer_id, listener_id):
        session = db_apis.get_session()
        with session.begin():
            if self.loadbalancer_repo.batch_owns_graph(
                    session, loadbalancer_id, tcp_only=True):
                return
            db_listener = self.listener_repo.get(
                session, id=listener_id)
        if db_listener is None:
            return
        self.amphora_driver.delete(db_listener)
        LOG.debug("Deleted the listener on the vip")

    def revert(self, listener, *args, **kwargs):
        """Handle a failed listener delete."""

        LOG.warning("Reverting listener delete.")

        self.task_utils.mark_listener_prov_status_error(
            listener[constants.LISTENER_ID])


class AmphoraGetInfo(BaseAmphoraTask):
    """Task to get information on an amphora."""

    def execute(self, amphora):
        """Execute get_info routine for an amphora."""
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora[constants.ID])
        self.amphora_driver.get_info(db_amp)


class AmphoraGetDiagnostics(BaseAmphoraTask):
    """Task to get diagnostics on the amphora and the loadbalancers."""

    def execute(self, amphora):
        """Execute get_diagnostic routine for an amphora."""
        self.amphora_driver.get_diagnostics(amphora)


class AmphoraFinalize(BaseAmphoraTask):
    """Task to finalize the amphora before any listeners are configured."""

    def execute(self, amphora):
        """Execute finalize_amphora routine."""
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora.get(constants.ID))
        self.amphora_driver.finalize_amphora(db_amp)
        LOG.debug("Finalized the amphora.")

    def revert(self, result, amphora, *args, **kwargs):
        """Handle a failed amphora finalize."""
        if isinstance(result, failure.Failure):
            return
        LOG.warning("Reverting amphora finalize.")
        self.task_utils.mark_amphora_status_error(
            amphora.get(constants.ID))


class AmphoraPostNetworkPlug(BaseAmphoraTask):
    """Task to notify the amphora post network plug."""

    def execute(self, amphora, ports, amphora_network_config):
        """Execute post_network_plug routine."""
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora[constants.ID])

        for port in ports:
            net = data_models.Network(**port.pop(constants.NETWORK))
            ips = port.pop(constants.FIXED_IPS)
            fixed_ips = []
            for ip in ips:
                subnet_arg = ip.pop(constants.SUBNET)
                host_routes = subnet_arg.get('host_routes')
                if host_routes:
                    subnet_arg['host_routes'] = [
                        data_models.HostRoute(**hr)
                        for hr in host_routes
                    ]
                fixed_ips.append(data_models.FixedIP(
                    subnet=data_models.Subnet(**subnet_arg), **ip))
            self.amphora_driver.post_network_plug(
                db_amp,
                data_models.Port(network=net, fixed_ips=fixed_ips, **port),
                amphora_network_config)

            LOG.debug("post_network_plug called on compute instance "
                      "%(compute_id)s for port %(port_id)s",
                      {"compute_id": amphora[constants.COMPUTE_ID],
                       "port_id": port[constants.ID]})

    def revert(self, result, amphora, *args, **kwargs):
        """Handle a failed post network plug."""
        if isinstance(result, failure.Failure):
            return
        LOG.warning("Reverting post network plug.")
        self.task_utils.mark_amphora_status_error(amphora.get(constants.ID))


class AmphoraePostNetworkPlug(BaseAmphoraTask):
    """Task to notify the amphorae post network plug."""

    def execute(self, loadbalancer, updated_ports, amphorae_network_config):
        """Execute post_network_plug routine."""
        amp_post_plug = AmphoraPostNetworkPlug()
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer[constants.LOADBALANCER_ID])
        for amphora in db_lb.amphorae:
            if amphora.id in updated_ports:
                amp_post_plug.execute(amphora.to_dict(),
                                      updated_ports[amphora.id],
                                      amphorae_network_config[amphora.id])

    def revert(self, result, loadbalancer, updated_ports, *args, **kwargs):
        """Handle a failed post network plug."""
        if isinstance(result, failure.Failure):
            return
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer[constants.LOADBALANCER_ID])
        LOG.warning("Reverting post network plug.")
        for amphora in filter(
            lambda amp: amp.status == constants.AMPHORA_ALLOCATED,
                db_lb.amphorae):

            self.task_utils.mark_amphora_status_error(amphora.id)


class AmphoraPostVIPPlug(BaseAmphoraTask):
    """Task to notify the amphora post VIP plug."""

    def execute(self, amphora, loadbalancer, amphorae_network_config):
        """Execute post_vip_routine."""
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora.get(constants.ID))
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer[constants.LOADBALANCER_ID])
        vrrp_port = data_models.Port(
            **amphorae_network_config[
                amphora.get(constants.ID)][constants.VRRP_PORT])
        # Required for noop-case
        vip_arg = copy.deepcopy(
            amphorae_network_config[
                amphora.get(constants.ID)][constants.VIP_SUBNET])
        if vip_arg:
            host_routes = vip_arg.get('host_routes')
            if host_routes:
                vip_arg['host_routes'] = [
                    data_models.HostRoute(**hr)
                    for hr in host_routes
                ]
            vip_subnet = data_models.Subnet(**vip_arg)
        else:
            vip_subnet = data_models.Subnet()

        additional_vip_data = []
        for add_vip in amphorae_network_config[
                amphora[constants.ID]]['additional_vip_data']:

            subnet_arg = copy.deepcopy(add_vip['subnet'])
            subnet_arg['host_routes'] = [
                data_models.HostRoute(**hr)
                for hr in subnet_arg['host_routes']]
            subnet = data_models.Subnet(**subnet_arg)

            additional_vip_data.append(
                data_models.AdditionalVipData(
                    ip_address=add_vip['ip_address'],
                    subnet=subnet))

        self.amphora_driver.post_vip_plug(
            db_amp, db_lb, amphorae_network_config, vrrp_port,
            vip_subnet, additional_vip_data=additional_vip_data)
        LOG.debug("Notified amphora of vip plug")

    def revert(self, result, amphora, loadbalancer, *args, **kwargs):
        """Handle a failed amphora vip plug notification."""
        if isinstance(result, failure.Failure):
            return
        LOG.warning("Reverting post vip plug.")
        self.task_utils.mark_amphora_status_error(amphora.get(constants.ID))


class AmphoraePostVIPPlug(BaseAmphoraTask):
    """Task to notify the amphorae post VIP plug."""

    def execute(self, loadbalancer, amphorae_network_config):
        """Execute post_vip_plug across the amphorae."""
        amp_post_vip_plug = AmphoraPostVIPPlug()
        session = db_apis.get_session()
        with session.begin():
            db_lb = self.loadbalancer_repo.get(
                session, id=loadbalancer[constants.LOADBALANCER_ID])
        for amphora in db_lb.amphorae:
            amp_post_vip_plug.execute(amphora.to_dict(),
                                      loadbalancer,
                                      amphorae_network_config)


class AmphoraCertUpload(BaseAmphoraTask):
    """Upload a certificate to the amphora."""

    def execute(self, amphora, server_pem):
        """Execute cert_update_amphora routine."""
        LOG.debug("Upload cert in amphora REST driver")
        fer = utils.get_server_certs_key_passphrases_fernet()
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora.get(constants.ID))
        self.amphora_driver.upload_cert_amp(
            db_amp, fer.decrypt(server_pem.encode('utf-8')))


# TODO(johnsom) REMOVE ME!
class AmphoraUpdateVRRPInterface(BaseAmphoraTask):
    """Task to get and update the VRRP interface device name from amphora."""

    def execute(self, amphora, timeout_dict=None):
        try:
            # TODO(johnsom) Optimize this to use the dicts and not need the
            #               DB lookups
            session = db_apis.get_session()
            with session.begin():
                db_amp = self.amphora_repo.get(session,
                                               id=amphora[constants.ID])
            interface = self.amphora_driver.get_interface_from_ip(
                db_amp, db_amp.vrrp_ip, timeout_dict=timeout_dict)
        except Exception as e:
            # This can occur when an active/standby LB has no listener
            LOG.error('Failed to get amphora VRRP interface on amphora '
                      '%s. Skipping this amphora as it is failing due to: '
                      '%s', amphora.get(constants.ID), str(e))
            with session.begin():
                self.amphora_repo.update(session,
                                         amphora.get(constants.ID),
                                         status=constants.ERROR)
            return None

        with session.begin():
            self.amphora_repo.update(session, amphora[constants.ID],
                                     vrrp_interface=interface)
        return interface


class AmphoraIndexUpdateVRRPInterface(BaseAmphoraTask):
    """Task to get and update the VRRP interface device name from amphora."""

    def execute(self, amphora_index, amphorae, amphorae_status: dict,
                new_amphora_id: str, timeout_dict=None):
        amphora_id = amphorae[amphora_index][constants.ID]
        amphora_status = amphorae_status.get(amphora_id, {})
        if amphora_status.get(constants.UNREACHABLE):
            LOG.warning("Skipping VRRP interface update because amphora %s "
                        "is not reachable.", amphora_id)
            return None

        try:
            # TODO(johnsom) Optimize this to use the dicts and not need the
            #               DB lookups
            session = db_apis.get_session()
            with session.begin():
                db_amp = self.amphora_repo.get(session,
                                               id=amphora_id)
            interface = self.amphora_driver.get_interface_from_ip(
                db_amp, db_amp.vrrp_ip, timeout_dict=timeout_dict)
        except Exception as e:
            # This can occur when an active/standby LB has no listener
            LOG.error('Failed to get amphora VRRP interface on amphora '
                      '%s. Skipping this amphora as it is failing due to: '
                      '%s', amphora_id, str(e))
            # Update only the status of the newly created amphora during the
            # failover
            if amphora_id == new_amphora_id:
                with session.begin():
                    self.amphora_repo.update(session, amphora_id,
                                             status=constants.ERROR)
            return None

        with session.begin():
            self.amphora_repo.update(session, amphora_id,
                                     vrrp_interface=interface)
        return interface


class AmphoraVRRPUpdate(BaseAmphoraTask):
    """Task to update the VRRP configuration of an amphora."""

    def execute(self, loadbalancer_id, amphorae_network_config, amphora,
                amp_vrrp_int, timeout_dict=None):
        """Execute update_vrrp_conf."""
        # Note, we don't want this to cause a revert as it may be used
        # in a failover flow with both amps failing. Skip it and let
        # health manager fix it.
        amphora_id = amphora[constants.ID]
        try:
            # TODO(johnsom) Optimize this to use the dicts and not need the
            #               DB lookups
            session = db_apis.get_session()
            with session.begin():
                db_amp = self.amphora_repo.get(session,
                                               id=amphora_id)
                loadbalancer = self.loadbalancer_repo.get(session,
                                                          id=loadbalancer_id)
            db_amp.vrrp_interface = amp_vrrp_int
            self.amphora_driver.update_vrrp_conf(
                loadbalancer, amphorae_network_config, db_amp, timeout_dict)
        except Exception as e:
            LOG.error('Failed to update VRRP configuration amphora %s. '
                      'Skipping this amphora as it is failing to update due '
                      'to: %s', amphora_id, str(e))
            with session.begin():
                self.amphora_repo.update(session, amphora_id,
                                         status=constants.ERROR)

        LOG.debug("Uploaded VRRP configuration of amphora %s.", amphora_id)


class AmphoraIndexVRRPUpdate(BaseAmphoraTask):
    """Task to update the VRRP configuration of an amphora."""

    def execute(self, loadbalancer_id, amphorae_network_config, amphora_index,
                amphorae, amphorae_status: dict, amp_vrrp_int: Optional[str],
                new_amphora_id: str, timeout_dict=None):
        """Execute update_vrrp_conf."""
        # Note, we don't want this to cause a revert as it may be used
        # in a failover flow with both amps failing. Skip it and let
        # health manager fix it.
        amphora_id = amphorae[amphora_index][constants.ID]
        amphora_status = amphorae_status.get(amphora_id, {})
        if amphora_status.get(constants.UNREACHABLE):
            LOG.warning("Skipping VRRP configuration because amphora %s "
                        "is not reachable.", amphora_id)
            return

        try:
            # TODO(johnsom) Optimize this to use the dicts and not need the
            #               DB lookups
            session = db_apis.get_session()
            with session.begin():
                db_amp = self.amphora_repo.get(session,
                                               id=amphora_id)
                loadbalancer = self.loadbalancer_repo.get(session,
                                                          id=loadbalancer_id)

            # If the amphora is in ERROR status, stop its VRRP service to
            # prevent split-brain (LP#2121370). During failover, the old
            # ERROR amphora may still be running VRRP as MASTER while the
            # new replacement also becomes MASTER.
            if db_amp.status == constants.ERROR:
                LOG.warning(
                    "Amphora %s is in ERROR status, stopping VRRP "
                    "service to prevent split-brain.", amphora_id)
                try:
                    self.amphora_driver.stop_vrrp_service_on_amphora(
                        db_amp, timeout_dict)
                except Exception:
                    LOG.debug("Could not stop VRRP on ERROR amphora %s "
                              "(may be unreachable)", amphora_id)
                return

            db_amp.vrrp_interface = amp_vrrp_int
            self.amphora_driver.update_vrrp_conf(
                loadbalancer, amphorae_network_config, db_amp, timeout_dict)
        except Exception as e:
            LOG.error('Failed to update VRRP configuration amphora %s. '
                      'Skipping this amphora as it is failing to update due '
                      'to: %s', amphora_id, str(e))
            # Update only the status of the newly created amphora during the
            # failover
            if amphora_id == new_amphora_id:
                with session.begin():
                    self.amphora_repo.update(session, amphora_id,
                                             status=constants.ERROR)
            return
        LOG.debug("Uploaded VRRP configuration of amphora %s.", amphora_id)


class AmphoraVRRPStart(BaseAmphoraTask):
    """Task to start keepalived on an amphora.

    This will reload keepalived if it is already running.
    """

    def execute(self, amphora, timeout_dict=None):
        # TODO(johnsom) Optimize this to use the dicts and not need the
        #               DB lookups
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(
                session, id=amphora[constants.ID])
        self.amphora_driver.start_vrrp_service(db_amp, timeout_dict)
        LOG.debug("Started VRRP on amphora %s.", amphora[constants.ID])


class AmphoraIndexVRRPStart(BaseAmphoraTask):
    """Task to start keepalived on an amphora.

    This will reload keepalived if it is already running.
    """

    def execute(self, amphora_index, amphorae, amphorae_status: dict,
                new_amphora_id: str, timeout_dict=None):
        # TODO(johnsom) Optimize this to use the dicts and not need the
        #               DB lookups
        amphora_id = amphorae[amphora_index][constants.ID]
        amphora_status = amphorae_status.get(amphora_id, {})
        if amphora_status.get(constants.UNREACHABLE):
            LOG.warning("Skipping VRRP start because amphora %s "
                        "is not reachable.", amphora_id)
            return

        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session, id=amphora_id)
        try:
            self.amphora_driver.start_vrrp_service(db_amp, timeout_dict)
        except Exception as e:
            LOG.error('Failed to start VRRP on amphora %s. '
                      'Skipping this amphora as it is failing to start due '
                      'to: %s', amphora_id, str(e))
            # Update only the status of the newly created amphora during the
            # failover
            if amphora_id == new_amphora_id:
                with session.begin():
                    self.amphora_repo.update(session, amphora_id,
                                             status=constants.ERROR)
            return
        LOG.debug("Started VRRP on amphora %s.",
                  amphorae[amphora_index][constants.ID])


class AmphoraComputeConnectivityWait(BaseAmphoraTask):
    """Task to wait for the compute instance to be up."""

    def execute(self, amphora, raise_retry_exception=False):
        """Execute get_info routine for an amphora until it responds."""
        try:
            session = db_apis.get_session()
            with session.begin():
                db_amphora = self.amphora_repo.get(
                    session, id=amphora.get(constants.ID))
            amp_info = self.amphora_driver.get_info(
                db_amphora, raise_retry_exception=raise_retry_exception)
            LOG.debug('Successfuly connected to amphora %s: %s',
                      amphora.get(constants.ID), amp_info)
        except driver_except.TimeOutException:
            LOG.error("Amphora compute instance failed to become reachable. "
                      "This either means the compute driver failed to fully "
                      "boot the instance inside the timeout interval or the "
                      "instance is not reachable via the lb-mgmt-net.")
            with session.begin():
                self.amphora_repo.update(session,
                                         amphora.get(constants.ID),
                                         status=constants.ERROR)
            raise


class AmphoraConfigUpdate(BaseAmphoraTask):
    """Task to push a new amphora agent configuration to the amphora."""

    def execute(self, amphora, flavor):
        # Extract any flavor based settings
        if flavor:
            topology = flavor.get(constants.LOADBALANCER_TOPOLOGY,
                                  CONF.controller_worker.loadbalancer_topology)
        else:
            topology = CONF.controller_worker.loadbalancer_topology

        # Build the amphora agent config
        agent_cfg_tmpl = agent_jinja_cfg.AgentJinjaTemplater()
        agent_config = agent_cfg_tmpl.build_agent_config(
            amphora.get(constants.ID), topology)
        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session,
                                           id=amphora[constants.ID])
        # Push the new configuration to the amphora
        try:
            self.amphora_driver.update_amphora_agent_config(db_amp,
                                                            agent_config)
        except driver_except.AmpDriverNotImplementedError:
            LOG.error('Amphora {} does not support agent configuration '
                      'update. Please update the amphora image for this '
                      'amphora. Skipping.'.
                      format(amphora.get(constants.ID)))


class AmphoraeGetConnectivityStatus(BaseAmphoraTask):
    """Task that checks amphorae connectivity status.

    Check and return the connectivity status of both amphorae in ACTIVE STANDBY
    load balancers
    """

    def execute(self, amphorae: List[dict], new_amphora_id: str,
                timeout_dict=None):
        amphorae_status = {}

        for amphora in amphorae:
            amphora_id = amphora[constants.ID]
            amphorae_status[amphora_id] = {}

            session = db_apis.get_session()
            with session.begin():
                db_amp = self.amphora_repo.get(session, id=amphora_id)

            try:
                # Verify if the amphora is reachable
                self.amphora_driver.check(db_amp, timeout_dict=timeout_dict)
            except Exception as e:
                LOG.exception("Cannot get status for amphora %s",
                              amphora_id)
                # In case it fails and the tested amphora is the newly created
                # amphora, it's not a normal error handling, re-raise the
                # exception
                if amphora_id == new_amphora_id:
                    raise e
                amphorae_status[amphora_id][constants.UNREACHABLE] = True
            else:
                amphorae_status[amphora_id][constants.UNREACHABLE] = False

        return amphorae_status


class SetAmphoraFirewallRules(BaseAmphoraTask):
    """Task to push updated firewall ruls to an amphora."""

    def execute(self, amphorae: List[dict], amphora_index: int,
                amphora_firewall_rules: List[dict], amphorae_status: dict,
                timeout_dict=None):

        if (amphora_firewall_rules and
                amphora_firewall_rules[0].get('non-sriov-vip', False)):
            # Not an SRIOV VIP, so skip setting firewall rules.
            # This is already logged in GetAmphoraFirewallRules.
            return

        amphora_id = amphorae[amphora_index][constants.ID]
        amphora_status = amphorae_status.get(amphora_id, {})
        if amphora_status.get(constants.UNREACHABLE):
            LOG.warning("Skipping firewall rules update because amphora %s "
                        "is not reachable.", amphora_id)
            return

        session = db_apis.get_session()
        with session.begin():
            db_amp = self.amphora_repo.get(session, id=amphora_id)

        self.amphora_driver.set_interface_rules(
            db_amp,
            amphorae[amphora_index][constants.VRRP_IP],
            amphora_firewall_rules, timeout_dict=timeout_dict)
