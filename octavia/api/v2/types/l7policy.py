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
from octavia.api.v2.types import l7rule as l7rule_types
from octavia.api.v2.types import pool as pool_types
from octavia.common import constants
from octavia.i18n import _


class BaseL7PolicyType(types.BaseType):
    _type_to_db_map = {'admin_state_up': 'enabled'}
    _child_map = {}

    def to_dict(self, render_unsets=False):
        data = super().to_dict(render_unsets=render_unsets)
        for field in ('request_header_operations',
                      'response_header_operations', 'redirect_request',
                      'request_url_rewrite', 'request_cors',
                      'http_request_policy'):
            if getattr(self, field) is wtypes.Unset:
                data.pop(field, None)
        return data


class L7PolicyResponse(BaseL7PolicyType):
    """Defines which attributes are to be shown on any response."""
    id = wtypes.wsattr(wtypes.UuidType())
    name = wtypes.wsattr(wtypes.StringType())
    description = wtypes.wsattr(wtypes.StringType())
    provisioning_status = wtypes.wsattr(wtypes.StringType())
    operating_status = wtypes.wsattr(wtypes.StringType())
    admin_state_up = wtypes.wsattr(bool)
    project_id = wtypes.wsattr(wtypes.StringType())
    action = wtypes.wsattr(wtypes.StringType())
    listener_id = wtypes.wsattr(wtypes.UuidType())
    redirect_pool_id = wtypes.wsattr(wtypes.UuidType())
    redirect_url = wtypes.wsattr(wtypes.StringType())
    fixed_response = wtypes.wsattr(types.FixedHTTPResponse)
    redirect_request = wtypes.wsattr(types.HTTPRequestRedirect())
    request_url_rewrite = wtypes.wsattr(types.HTTPRequestURLRewrite())
    request_cors = wtypes.wsattr(types.HTTPRequestCORS())
    http_request_policy = wtypes.wsattr(types.HTTPRequestPolicy())
    targets = wtypes.wsattr(types.WeightedL7PolicyTargets())
    request_header_operations = wtypes.wsattr(types.RequestHeaderOperations())
    response_header_operations = wtypes.wsattr(
        types.ResponseHeaderOperations())
    https_listener_hostname = wtypes.wsattr(wtypes.StringType(max_length=253))
    tcp_tls_passthrough = wtypes.wsattr(bool)
    redirect_prefix = wtypes.wsattr(wtypes.StringType())
    position = wtypes.wsattr(wtypes.IntegerType())
    rules = wtypes.wsattr([types.IdOnlyType])
    created_at = wtypes.wsattr(wtypes.datetime.datetime)
    updated_at = wtypes.wsattr(wtypes.datetime.datetime)
    tags = wtypes.wsattr(wtypes.ArrayType(wtypes.StringType()))
    redirect_http_code = wtypes.wsattr(wtypes.IntegerType())

    @classmethod
    def from_db_obj(cls, db_obj):
        result = super().from_db_obj(db_obj)
        if db_obj.fixed_response is not None:
            result.fixed_response = types.FixedHTTPResponse(
                **db_obj.fixed_response)
        else:
            result.fixed_response = wtypes.Unset
        if db_obj.https_listener_hostname is None:
            result.https_listener_hostname = wtypes.Unset
        listener = getattr(db_obj, 'listener', None)
        passthrough = getattr(db_obj, 'tcp_tls_passthrough', None)
        if (getattr(listener, 'tcp_tls_mixed_mode', None) is not True or
                not isinstance(passthrough, bool)):
            result.tcp_tls_passthrough = wtypes.Unset
        for field in ('request_header_operations',
                      'response_header_operations', 'redirect_request',
                      'request_url_rewrite', 'request_cors',
                      'http_request_policy'):
            if getattr(db_obj, field) is None:
                setattr(result, field, wtypes.Unset)
        if not db_obj.targets:
            result.targets = wtypes.Unset

        if cls._full_response():
            result.rules = [
                l7rule_types.L7RuleFullResponse.from_db_obj(l7rule)
                for l7rule in db_obj.l7rules
            ]
        else:
            result.rules = [
                types.IdOnlyType.from_db_obj(l7rule)
                for l7rule in db_obj.l7rules
            ]

        return result


class L7PolicyFullResponse(L7PolicyResponse):
    @classmethod
    def _full_response(cls):
        return True

    rules = wtypes.wsattr([l7rule_types.L7RuleFullResponse])


class L7PolicyRootResponse(types.BaseType):
    l7policy = wtypes.wsattr(L7PolicyResponse)


class L7PoliciesRootResponse(types.BaseType):
    l7policies = wtypes.wsattr([L7PolicyResponse])
    l7policies_links = wtypes.wsattr([types.PageType])


class L7PolicyPOST(BaseL7PolicyType):
    """Defines mandatory and optional attributes of a POST request."""
    name = wtypes.wsattr(wtypes.StringType(max_length=255))
    description = wtypes.wsattr(wtypes.StringType(max_length=255))
    admin_state_up = wtypes.wsattr(bool, default=True)
    # TODO(johnsom) Remove after deprecation (R series)
    project_id = wtypes.wsattr(wtypes.StringType(max_length=36))
    action = wtypes.wsattr(
        wtypes.Enum(str, *constants.SUPPORTED_L7POLICY_ACTIONS),
        mandatory=True)
    redirect_pool_id = wtypes.wsattr(wtypes.UuidType())
    redirect_url = wtypes.wsattr(types.URLType())
    fixed_response = wtypes.wsattr(types.FixedHTTPResponse)
    redirect_request = wtypes.wsattr(types.HTTPRequestRedirect())
    request_url_rewrite = wtypes.wsattr(types.HTTPRequestURLRewrite())
    request_cors = wtypes.wsattr(types.HTTPRequestCORS())
    http_request_policy = wtypes.wsattr(types.HTTPRequestPolicy())
    targets = wtypes.wsattr(types.WeightedL7PolicyTargets())
    request_header_operations = wtypes.wsattr(types.RequestHeaderOperations())
    response_header_operations = wtypes.wsattr(
        types.ResponseHeaderOperations())
    https_listener_hostname = wtypes.wsattr(wtypes.StringType(max_length=253))
    tcp_tls_passthrough = wtypes.wsattr(bool, default=False)
    redirect_prefix = wtypes.wsattr(types.URLType())
    position = wtypes.wsattr(wtypes.IntegerType(
        minimum=constants.MIN_POLICY_POSITION,
        maximum=constants.MAX_POLICY_POSITION),
        default=constants.MAX_POLICY_POSITION)
    listener_id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)
    rules = wtypes.wsattr([l7rule_types.L7RuleSingleCreate])
    tags = wtypes.wsattr(wtypes.ArrayType(wtypes.StringType(max_length=255)))
    redirect_http_code = wtypes.wsattr(
        wtypes.Enum(int, *constants.SUPPORTED_L7POLICY_REDIRECT_HTTP_CODES))


class L7PolicyRootPOST(types.BaseType):
    l7policy = wtypes.wsattr(L7PolicyPOST)


@wsme_json.fromjson.when_object(L7PolicyRootPOST)
def _l7policy_post_from_json(datatype, value):
    # Validate shape and booleans before the generic decoder coerces values.
    policy = value.get('l7policy') if isinstance(value, dict) else None
    if not isinstance(policy, dict):
        raise ValueError(_('The request must contain an l7policy object.'))
    rules = policy.get('rules')
    if rules is not None and not isinstance(rules, list):
        raise ValueError(_('Initial rules must be an array.'))
    if rules:
        if ('admin_state_up' in policy and
                not isinstance(policy['admin_state_up'], bool)):
            raise ValueError(_('Policy admin_state_up must be a boolean.'))
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError(_('Each initial rule must be an object.'))
            for field in ('admin_state_up', 'invert'):
                if field in rule and not isinstance(rule[field], bool):
                    raise ValueError(_(
                        'Initial rule %(field)s must be a boolean.')
                        % {'field': field})
    return wsme_json.fromjson.default(datatype, value)


class L7PolicyPUT(BaseL7PolicyType):
    """Defines attributes that are acceptable of a PUT request."""
    name = wtypes.wsattr(wtypes.StringType(max_length=255))
    description = wtypes.wsattr(wtypes.StringType(max_length=255))
    admin_state_up = wtypes.wsattr(bool)
    action = wtypes.wsattr(
        wtypes.Enum(str, *constants.SUPPORTED_L7POLICY_ACTIONS))
    redirect_pool_id = wtypes.wsattr(wtypes.UuidType())
    redirect_url = wtypes.wsattr(types.URLType())
    fixed_response = wtypes.wsattr(types.FixedHTTPResponse)
    redirect_request = wtypes.wsattr(types.HTTPRequestRedirect())
    request_url_rewrite = wtypes.wsattr(types.HTTPRequestURLRewrite())
    request_cors = wtypes.wsattr(types.HTTPRequestCORS())
    http_request_policy = wtypes.wsattr(types.HTTPRequestPolicy())
    targets = wtypes.wsattr(types.WeightedL7PolicyTargets())
    request_header_operations = wtypes.wsattr(types.RequestHeaderOperations())
    response_header_operations = wtypes.wsattr(
        types.ResponseHeaderOperations())
    https_listener_hostname = wtypes.wsattr(wtypes.StringType(max_length=253))
    tcp_tls_passthrough = wtypes.wsattr(bool)
    redirect_prefix = wtypes.wsattr(types.URLType())
    position = wtypes.wsattr(wtypes.IntegerType(
        minimum=constants.MIN_POLICY_POSITION,
        maximum=constants.MAX_POLICY_POSITION))
    tags = wtypes.wsattr(wtypes.ArrayType(wtypes.StringType(max_length=255)))
    redirect_http_code = wtypes.wsattr(
        wtypes.Enum(int, *constants.SUPPORTED_L7POLICY_REDIRECT_HTTP_CODES))


class L7PolicyRootPUT(types.BaseType):
    l7policy = wtypes.wsattr(L7PolicyPUT)


class L7PolicySingleCreate(BaseL7PolicyType):
    """Defines mandatory and optional attributes of a POST request."""
    name = wtypes.wsattr(wtypes.StringType(max_length=255))
    description = wtypes.wsattr(wtypes.StringType(max_length=255))
    admin_state_up = wtypes.wsattr(bool, default=True)
    action = wtypes.wsattr(
        wtypes.Enum(str, *constants.SUPPORTED_L7POLICY_ACTIONS),
        mandatory=True)
    redirect_pool = wtypes.wsattr(pool_types.PoolSingleCreate)
    redirect_url = wtypes.wsattr(types.URLType())
    fixed_response = wtypes.wsattr(types.FixedHTTPResponse)
    redirect_request = wtypes.wsattr(types.HTTPRequestRedirect())
    request_url_rewrite = wtypes.wsattr(types.HTTPRequestURLRewrite())
    request_cors = wtypes.wsattr(types.HTTPRequestCORS())
    http_request_policy = wtypes.wsattr(types.HTTPRequestPolicy())
    targets = wtypes.wsattr(types.WeightedL7PolicyTargets())
    request_header_operations = wtypes.wsattr(types.RequestHeaderOperations())
    response_header_operations = wtypes.wsattr(
        types.ResponseHeaderOperations())
    https_listener_hostname = wtypes.wsattr(wtypes.StringType(max_length=253))
    tcp_tls_passthrough = wtypes.wsattr(bool, default=False)
    redirect_prefix = wtypes.wsattr(types.URLType())
    position = wtypes.wsattr(wtypes.IntegerType(
        minimum=constants.MIN_POLICY_POSITION,
        maximum=constants.MAX_POLICY_POSITION),
        default=constants.MAX_POLICY_POSITION)
    rules = wtypes.wsattr([l7rule_types.L7RuleSingleCreate])
    tags = wtypes.wsattr(wtypes.ArrayType(wtypes.StringType(max_length=255)))
    redirect_http_code = wtypes.wsattr(
        wtypes.Enum(int, *constants.SUPPORTED_L7POLICY_REDIRECT_HTTP_CODES))
