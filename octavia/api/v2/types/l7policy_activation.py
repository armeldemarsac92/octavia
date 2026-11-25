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

from wsme.rest import json as wsme_json
from wsme import types as wtypes

from octavia.api.common import types
from octavia.api.v2.types import health_monitor
from octavia.api.v2.types import l7policy
from octavia.api.v2.types import listener
from octavia.api.v2.types import load_balancer
from octavia.api.v2.types import member
from octavia.api.v2.types import pool
from octavia.common import constants
from octavia.i18n import _


class L7PolicyActivationSnapshot(types.BaseType):
    revision = wtypes.wsattr(wtypes.text)
    policy = wtypes.wsattr(l7policy.L7PolicyFullResponse)


class ActivationMember(member.MemberResponse):
    pool_id = wtypes.wsattr(wtypes.UuidType())


class ActivationPool(pool.PoolResponse):
    healthmonitor = wtypes.wsattr(health_monitor.HealthMonitorResponse)


class ActivationDestination(types.BaseType):
    pool = wtypes.wsattr(ActivationPool)
    members = wtypes.wsattr([ActivationMember])


class L7PolicyActivationResponse(types.BaseType):
    graph_revision = wtypes.wsattr(wtypes.text)
    loadbalancer = wtypes.wsattr(load_balancer.LoadBalancerResponse)
    listener = wtypes.wsattr(listener.ListenerResponse)
    pools = wtypes.wsattr([ActivationDestination])
    policies = wtypes.wsattr([L7PolicyActivationSnapshot])


class L7PolicyActivationRootResponse(types.BaseType):
    l7policy_activation = wtypes.wsattr(L7PolicyActivationResponse)


Revision = wtypes.StringType(min_length=64, max_length=64,
                             pattern=r'^[a-f0-9]+$')


class L7PolicyActivationReference(types.BaseType):
    id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)
    revision = wtypes.wsattr(Revision, mandatory=True)


class RuleTagUpdate(types.BaseType):
    id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)
    tags = wtypes.wsattr([wtypes.StringType(max_length=255)], mandatory=True)


class GRPCAuthTransition(types.BaseType):
    id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)
    revision = wtypes.wsattr(Revision, mandatory=True)
    tags = wtypes.wsattr([wtypes.StringType(max_length=255)], mandatory=True)
    rules = wtypes.wsattr([RuleTagUpdate], mandatory=True)
    redirect_pool_id = wtypes.wsattr(wtypes.UuidType())
    external_auth = wtypes.wsattr(l7policy.ExternalAuth())


class L7PolicyActivationPOST(types.BaseType):
    expected_graph_revision = wtypes.wsattr(Revision, mandatory=True)
    expected_order = wtypes.wsattr([wtypes.UuidType()], mandatory=True)
    policies = wtypes.wsattr([L7PolicyActivationReference], mandatory=True)


class GRPCAuthTransitionPOST(types.BaseType):
    expected_graph_revision = wtypes.wsattr(Revision, mandatory=True)
    expected_order = wtypes.wsattr([wtypes.UuidType()], mandatory=True)
    policies = wtypes.wsattr([GRPCAuthTransition], mandatory=True)


class GRPCAuthTransitionRootPOST(types.BaseType):
    l7policy_grpc_auth_transition = wtypes.wsattr(
        GRPCAuthTransitionPOST, mandatory=True)


class GRPCAuthRecovery(types.BaseType):
    operation_id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)


class L7PolicyActivationRootPOST(types.BaseType):
    l7policy_activation = wtypes.wsattr(L7PolicyActivationPOST, mandatory=True)


@wsme_json.fromjson.when_object(L7PolicyActivationRootPOST)
def _l7policy_activation_post_from_json(datatype, value):
    if not isinstance(value, dict) or set(value) != {'l7policy_activation'}:
        raise ValueError(_('Supply an l7policy_activation object.'))
    activation = value['l7policy_activation']
    if (not isinstance(activation, dict) or
            set(activation) != {
                'expected_graph_revision', 'expected_order', 'policies'} or
            not isinstance(activation['expected_graph_revision'], str)):
        raise ValueError(_('Supply both the order and the activation group.'))
    order = activation['expected_order']
    if (not isinstance(order, list) or
            not all(isinstance(policy_id, str) for policy_id in order)):
        raise ValueError(_('Supply the complete expected order as UUIDs.'))
    policies = activation['policies']
    max_policies = constants.MAX_L7POLICY_BATCH_ACTIVATION
    if (not isinstance(policies, list) or
            not 2 <= len(policies) <= max_policies or
            any(not isinstance(item, dict) or
                set(item) != {'id', 'revision'} or
                not isinstance(item['id'], str) or
                not isinstance(item['revision'], str) for item in policies)):
        raise ValueError(_('Supply 2–64 L7 policy IDs and revisions.'))
    return wsme_json.fromjson.default(datatype, value)
