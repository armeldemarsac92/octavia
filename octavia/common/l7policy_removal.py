# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import json

from wsme.rest import json as wsme_json

from octavia.api.v2.types import l7policy as wire
from octavia.common import constants
from octavia.common import exceptions


def lock_load_balancer(session, repos, lb_id):
    lb = repos.load_balancer.get_for_update(session, lb_id)
    if not lb or lb.provisioning_status == constants.DELETED:
        raise exceptions.NotFound(resource='Load Balancer', id=lb_id)
    return lb


def lock_policy(session, repos, lb, listener_id, policy_id, *, removing=False):
    """Read a policy and its children under the load balancer write lock."""
    if removing and (
            lb.provisioning_status != constants.ACTIVE or
            repos.load_balancer._batch_pending(lb) or
            repos.load_balancer.tcp_batch_pending(lb)):
        raise exceptions.L7PolicyRemovalConflict()
    listener = repos.listener.get_for_update(
        session, listener_id, show_deleted=False)
    if (listener.load_balancer_id != lb.id or
            listener.project_id != lb.project_id or
            (removing and listener.provisioning_status != constants.ACTIVE)):
        raise exceptions.L7PolicyRemovalConflict()
    policy = repos.l7policy.get_for_update(
        session, policy_id, show_deleted=False, load_targets_and_mirrors=False)
    if (policy.listener_id != listener.id or
            policy.project_id != lb.project_id or
            (removing and (policy.enabled or
                           policy.provisioning_status != constants.ACTIVE))):
        raise exceptions.L7PolicyRemovalConflict()
    repos.l7policy.load_activation_references(
        session, [policy], include_deleted_rules=True)
    if any(rule.project_id != policy.project_id or
           rule.l7policy_id != policy.id for rule in policy.l7rules):
        raise exceptions.L7PolicyRemovalConflict()
    return policy


def snapshot(lb, policy):
    response = wire.L7PolicyFullResponse.from_db_obj(policy)
    document = wsme_json.tojson(wire.L7PolicyFullResponse, response)
    for item in [document, *document['rules']]:
        item.pop('operating_status', None)
        item['tags'] = sorted(item.get('tags') or [])
    document['rules'].sort(key=lambda rule: rule['id'])
    # Include the database value when the protocol hides the setting on wire.
    document['tcp_tls_passthrough'] = policy.tcp_tls_passthrough
    canonical = json.dumps(
        [lb.id, lb.l7policy_graph_generation, document],
        sort_keys=True, separators=(',', ':'))
    return response, hashlib.sha256(canonical.encode()).hexdigest()


def validate_removal(lb, policy, expected_revision):
    ready_rule_statuses = (constants.ACTIVE, constants.DELETED)
    if (any(rule.provisioning_status not in ready_rule_statuses
            for rule in policy.l7rules) or
            snapshot(lb, policy)[1] != expected_revision):
        raise exceptions.L7PolicyRemovalConflict()
