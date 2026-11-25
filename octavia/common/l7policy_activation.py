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

import hashlib
import json

from wsme.rest import json as wsme_json

from octavia.api.v2.types import health_monitor
from octavia.api.v2.types import l7policy
from octavia.api.v2.types import l7policy_activation as wire
from octavia.api.v2.types import listener as listener_types
from octavia.api.v2.types import load_balancer
from octavia.common import constants
from octavia.common import exceptions
from octavia.common import listener_request_filters
from octavia.common import validate


PENDING = ('pending', 'rendering', 'reverting')


# The enabled flag is part of the precondition. An applied operation
# keeps a receipt for the exact original precondition.
ACTIVATION_POLICY_FIELDS = (
    'id', 'name', 'description', 'project_id', 'listener_id', 'position',
    'enabled', 'action', 'redirect_pool_id', 'redirect_url', 'redirect_prefix',
    'redirect_http_code', 'fixed_response', 'redirect_request',
    'request_url_rewrite', 'request_cors', 'targets',
    'request_header_operations', 'response_header_operations',
    'https_listener_hostname')
ACTIVATION_RULE_FIELDS = (
    'id', 'project_id', 'type', 'compare_type', 'key', 'value', 'invert',
    'enabled')


def policy_revision(policy):
    def values(resource, fields):
        return {**{field: getattr(resource, field) for field in fields},
                'tags': sorted(resource.tags)}

    data = values(policy, ACTIVATION_POLICY_FIELDS)
    request_policy = getattr(policy, 'http_request_policy', None)
    if request_policy is not None:
        data['http_request_policy'] = request_policy
    request_mirrors = getattr(policy, 'request_mirrors', None)
    if request_mirrors:
        data['request_mirrors'] = request_mirrors
    external_auth = getattr(policy, 'external_auth', None)
    if external_auth is not None:
        data['external_auth'] = external_auth
    data['rules'] = [values(rule, ACTIVATION_RULE_FIELDS) for rule in
                     sorted(policy.l7rules, key=lambda rule: rule.id)]
    return _digest(data)


def _digest(data):
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _configuration(value):
    if isinstance(value, dict):
        return {key: sorted(item or []) if key == 'tags' else
                _configuration(item) for key, item in value.items()
                if key not in ('created_at', 'updated_at', 'operating_status',
                               'backend_tls_system_ca_sha256')}
    if isinstance(value, list):
        if value and all(isinstance(item, dict) and set(item) == {'id'}
                         for item in value):
            value = sorted(value, key=lambda item: item['id'])
        return [_configuration(item) for item in value]
    return value


def snapshot(session, repositories, lb, listener, *, pending=False):
    repo = repositories.l7policy
    policies = repo.get_listener_policies_for_update(session, listener.id)
    repo.load_activation_references(session, policies)
    auth_pool_ids = listener_request_filters.pool_ids(
        listener.request_filter_sections)
    pool_ids = {listener.default_pool_id}
    snapshots = []
    for policy in policies:
        if (policy.project_id != lb.project_id or
                any(rule.project_id != lb.project_id
                    for rule in policy.l7rules)):
            raise exceptions.L7PolicyActivationConflict()
        if policy.external_auth is not None:
            try:
                auth = validate.http_external_auth(policy.external_auth)
            except exceptions.ValidationException as exc:
                raise exceptions.L7PolicyActivationConflict() from exc
            auth_pool_ids.add(auth['pool_id'])
        pool_ids.add(policy.redirect_pool_id)
        pool_ids.update(target.get('pool_id') for target in policy.targets)
        pool_ids.update(validate.request_mirror_pool_ids(
            policy.request_mirrors, policy.targets))
        snapshots.append(wire.L7PolicyActivationSnapshot(
            revision=policy_revision(policy),
            policy=l7policy.L7PolicyFullResponse.from_db_obj(policy)))
    pool_ids.update(auth_pool_ids)
    pool_ids.discard(None)
    pools = {pool.id: pool for pool in lb.pools}
    destinations = []
    for pool_id in sorted(pool_ids):
        pool = pools.get(pool_id)
        if (pool is None or pool.project_id != lb.project_id or
                pool.provisioning_status == constants.DELETED or
                (pool_id in auth_pool_ids and
                 (pool.load_balancer_id != lb.id or
                  pool.provisioning_status == constants.PENDING_DELETE or
                  not listener_request_filters.valid_pool(pool)))):
            raise exceptions.L7PolicyActivationConflict()
        members = sorted(
            (m for m in pool.members if m.provisioning_status !=
             constants.DELETED), key=lambda member: member.id)
        monitor = pool.health_monitor
        if (any(member.project_id != lb.project_id for member in members) or
                (monitor and monitor.project_id != lb.project_id)):
            raise exceptions.L7PolicyActivationConflict()
        pool_data = wire.ActivationPool.from_db_obj(pool)
        if monitor:
            pool_data.healthmonitor = (
                health_monitor.HealthMonitorResponse.from_db_obj(monitor))
        destinations.append(wire.ActivationDestination(
            pool=pool_data, members=[
                wire.ActivationMember.from_db_obj(member) for member in
                members]))
    result = wire.L7PolicyActivationResponse(
        loadbalancer=load_balancer.LoadBalancerResponse.from_db_obj(lb),
        listener=listener_types.ListenerResponse.from_db_obj(listener),
        pools=destinations, policies=snapshots)
    graph = wsme_json.tojson(wire.L7PolicyActivationResponse, result)
    graph['policies'] = [(policy.id, entry.revision)
                         for policy, entry in zip(policies, snapshots)]
    if pending:
        # These statuses change when the batch is accepted, even before a
        # worker consumes it. Other provisioning changes still conflict.
        for parent in ('loadbalancer', 'listener'):
            status = graph[parent]['provisioning_status']
            if status == constants.PENDING_UPDATE:
                graph[parent]['provisioning_status'] = constants.ACTIVE
    result.graph_revision = _digest(
        [lb.l7policy_graph_generation, _configuration(graph)])
    return result, policies
