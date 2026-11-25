#    Copyright 2014 Rackspace
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

import ipaddress

from octavia_lib.common import constants as lib_constants
from wsme import exc as wsme_exc
from wsme import types as wtypes

from octavia.common import constants
from octavia.common import exceptions
from octavia.common import validate
from octavia.i18n import _


class IPAddressType(wtypes.UserType):
    basetype = str
    name = 'ipaddress'

    @staticmethod
    def validate(value):
        """Validates whether value is an IPv4 or IPv6 address."""
        try:
            wtypes.IPv4AddressType.validate(value)
            return value
        except ValueError:
            try:
                wtypes.IPv6AddressType.validate(value)
                return value
            except ValueError as e:
                error = 'Value should be IPv4 or IPv6 format'
                raise ValueError(error) from e


class CidrType(wtypes.UserType):
    basetype = str
    name = 'cidr'

    @staticmethod
    def validate(value):
        """Validates whether value is an IPv4 or IPv6 CIDR."""
        try:
            return ipaddress.ip_network(value, strict=False).with_prefixlen
        except Exception as e:
            error = 'Value should be IPv4 or IPv6 CIDR format'
            raise ValueError(error) from e


class TCPConnectionRejection(wtypes.UserType):
    basetype = object
    name = 'tcp_connection_rejection'

    @staticmethod
    def validate(value):
        try:
            return validate.tcp_connection_rejection(value)
        except exceptions.ValidationException as error:
            raise ValueError(str(error)) from error


class UDPPacketDrop(wtypes.UserType):
    basetype = object
    name = 'udp_packet_drop'

    @staticmethod
    def validate(value):
        try:
            return validate.udp_packet_drop(value)
        except exceptions.ValidationException as error:
            raise ValueError(str(error)) from error


class AlpnProtocolType(wtypes.UserType):
    basetype = str
    name = 'alpn_protocol'

    @staticmethod
    def validate(value):
        """Validates whether value is a valid ALPN protocol ID."""
        if value in constants.SUPPORTED_ALPN_PROTOCOLS:
            return value
        error = 'Value should be a valid ALPN protocol ID'
        raise ValueError(error)


class URLType(wtypes.UserType):
    basetype = str
    name = 'url'

    def __init__(self, require_scheme=True):
        super().__init__()
        self.require_scheme = require_scheme

    def validate(self, value):
        try:
            validate.url(value, require_scheme=self.require_scheme)
        except exceptions.InvalidURL as e:
            error = 'Value must be a valid URL string'
            raise ValueError(error) from e
        return value


class URLPathType(wtypes.UserType):
    basetype = str
    name = 'url_path'

    @staticmethod
    def validate(value):
        try:
            validate.url_path(value)
        except exceptions.InvalidURLPath as e:
            error = 'Value must be a valid URL Path string'
            raise ValueError(error) from e
        return value


class BaseMeta(wtypes.BaseMeta):
    def __new__(mcs, name, bases, dct):
        def get_tenant_id(self):
            tenant_id = getattr(self, '_tenant_id', wtypes.Unset)
            # If tenant_id was explicitly set to Unset, return that
            if tenant_id is wtypes.Unset and self._unset_tenant:
                return tenant_id
            # Otherwise, assume we can return project_id
            return self.project_id

        def set_tenant_id(self, tenant_id):
            self._tenant_id = tenant_id

            if tenant_id is wtypes.Unset:
                # Record that tenant_id was explicitly Unset
                self._unset_tenant = True
            else:
                # Reset 'unset' state, and update project_id as well
                self._unset_tenant = False
                self.project_id = tenant_id

        if 'project_id' in dct and 'tenant_id' not in dct:
            dct['tenant_id'] = wtypes.wsproperty(
                wtypes.StringType(max_length=36),
                get_tenant_id, set_tenant_id)
            # This will let us know if tenant_id was explicitly set to Unset
            dct['_unset_tenant'] = False
        return super().__new__(mcs, name, bases, dct)


class BaseType(wtypes.Base, metaclass=BaseMeta):
    @classmethod
    def _full_response(cls):
        return False

    @classmethod
    def from_db_obj(cls, db_obj):
        """Map DB object to WSME attributes.

        The behaviour can be individually extended by implementing from_db_obj
        closer to the type.

        :param db_obj: the DB object to process
        """
        result = cls()

        def try_set_attr(result, attr_name, attr):
            # This is not as messy as it may seem. Trying to setattr and
            # discarding InvalidInput exceptions allows from_db_obj to stay as
            # generic as possible and effectively ignore attributes that need
            # a developer-defined processing path. This should only affect
            # development in the event that a new property is added to an API
            # response type but needs an explicit procesing path (for example
            # for attributes that are IdOnlyType normally but XFullResponse
            # when _full_response).
            try:
                setattr(result, attr_name, attr)
            except wsme_exc.InvalidInput:
                pass

        attr_names = [attr.name for attr in cls._wsme_attributes]
        for attr_name in attr_names:
            if hasattr(db_obj, attr_name):
                attr = getattr(db_obj, attr_name)

                if attr_name in ['name', 'description'] and attr is None:
                    setattr(result, attr_name, '')
                else:
                    try_set_attr(result, attr_name, attr)
            elif hasattr(cls, '_type_to_db_map'):
                if (attr_name not in cls._type_to_db_map or
                   '.' in cls._type_to_db_map[attr_name]):
                    continue

                attr = getattr(db_obj, cls._type_to_db_map[attr_name])
                try_set_attr(result, attr_name, attr)

        return result

    @classmethod
    def translate_dict_keys_to_db_obj(cls, wsme_dict):
        """Translate the keys from wsme class type, to db_obj."""
        if not hasattr(cls, '_type_to_db_map'):
            return wsme_dict
        res = {}
        for (k, v) in wsme_dict.items():
            if k in cls._type_to_db_map:
                k = cls._type_to_db_map[k]
                if '.' in k:
                    parent, child = k.split('.')
                    if parent not in res:
                        res[parent] = {}
                    res[parent][child] = v
                    continue
            res[k] = v
        return res

    @classmethod
    def translate_key_to_db_obj(cls, key):
        """Translate the keys from wsme class type, to db_obj."""
        if not hasattr(cls, '_type_to_db_map') or (
                key not in cls._type_to_db_map):
            return key
        return cls._type_to_db_map[key]

    def to_dict(self, render_unsets=False):
        """Converts Octavia WSME type to dictionary.

        :param render_unsets: If True, will convert items that are WSME Unset
                              types to None. If False, does not add the item
        """
        # Set project_id equal tenant_id if project_id is unset and tenant_id
        # is
        if hasattr(self, 'project_id') and hasattr(self, 'tenant_id'):
            # pylint: disable=access-member-before-definition
            if (isinstance(self.project_id, wtypes.UnsetType) and
                    not isinstance(self.tenant_id, wtypes.UnsetType)):
                self.project_id = self.tenant_id
        if hasattr(self, 'admin_state_up') and getattr(
                self, 'admin_state_up') is None:
            # This situation will be hit during request with
            # admin_state_up is null. If users specify this field to null,
            # then we treat it as False
            self.admin_state_up = bool(self.admin_state_up)
        wsme_dict = {}
        for attr in dir(self):
            if attr.startswith('_'):
                continue
            value = getattr(self, attr, None)
            # TODO(blogan): Investigate wsme types handling the duality of
            # tenant_id and project_id in a clean way.  One way could be
            # wsme.rest.json.fromjson and using the @fromjson.when_object
            # decorator.
            if attr == 'tenant_id':
                continue
            if value and callable(value):
                continue
            if value and isinstance(value, BaseType):
                value = value.to_dict(render_unsets=render_unsets)
            if value and isinstance(value, list):
                value = [val.to_dict(render_unsets=render_unsets)
                         if isinstance(val, BaseType) else val
                         for val in value]
            if isinstance(value, wtypes.UnsetType):
                if render_unsets:
                    value = None
                else:
                    continue
            wsme_dict[attr] = value
        return self.translate_dict_keys_to_db_obj(wsme_dict)


class FixedHTTPStatusCode(wtypes.UserType):
    # Preserve the JSON value's type so strings and floats cannot be coerced.
    basetype = object
    name = 'fixed_http_status_code'

    @staticmethod
    def validate(value):
        if (type(value) is not int or
                value not in lib_constants.SUPPORTED_FIXED_HTTP_STATUS_CODES):
            raise ValueError(_('Status code must be 404 or 500.'))
        return value


class FixedHTTPResponse(BaseType):
    status_code = wtypes.wsattr(FixedHTTPStatusCode(), mandatory=True)


class StrictBoolean(wtypes.UserType):
    # Preserve the JSON value before WSME can coerce it to a bool.
    basetype = object
    name = 'strict_boolean'

    @staticmethod
    def validate(value):
        if type(value) is not bool:
            raise ValueError(_('Expected a JSON boolean.'))
        return value


class StrictBooleanAttribute(wtypes.wsattr):
    def __init__(self):
        super().__init__(StrictBoolean())

    def __set__(self, instance, value):
        # WSME bypasses type validation for explicit JSON null.
        if value is None:
            raise wsme_exc.InvalidInput(
                self.name, value, _('Expected a JSON boolean.'))
        super().__set__(instance, value)


class HTTPRequestRedirect(wtypes.UserType):
    # Keep the original JSON types and reject unknown keys.
    basetype = object
    name = 'http_request_redirect'

    @staticmethod
    def validate(value):
        try:
            return validate.http_request_redirect(value)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class HTTPRequestURLRewrite(wtypes.UserType):
    basetype = object
    name = 'http_request_url_rewrite'

    @staticmethod
    def validate(value):
        try:
            return validate.http_request_url_rewrite(value)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class HTTPRequestPolicy(wtypes.UserType):
    basetype = object
    name = 'http_request_policy'

    @staticmethod
    def validate(value):
        try:
            return validate.http_request_policy(value)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class HTTPRequestMirrors(wtypes.UserType):
    basetype = object
    name = 'request_mirrors'

    @staticmethod
    def validate(value):
        try:
            return validate.http_request_mirrors(value)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class HTTPRequestCORS(wtypes.UserType):
    basetype = object
    name = 'request_cors'

    @staticmethod
    def validate(value):
        try:
            return validate.http_request_cors(value)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class WeightedL7PolicyTargets(wtypes.UserType):
    # Preserve the original JSON types for strict validation.
    basetype = object
    name = 'weighted_l7policy_targets'

    @staticmethod
    def validate(value):
        try:
            return validate.weighted_l7policy_targets(value)
        except (exceptions.InvalidL7PolicyArgs,
                exceptions.ValidationException) as e:
            raise ValueError(str(e)) from e


class RequestHeaderOperations(wtypes.UserType):
    # A tagged list with strict JSON types and a per-operation value field.
    basetype = object
    name = 'request_header_operations'

    @classmethod
    def validate(cls, value):
        try:
            return validate.header_operations(value, cls.name)
        except exceptions.InvalidL7PolicyArgs as e:
            raise ValueError(str(e)) from e


class ResponseHeaderOperations(RequestHeaderOperations):
    name = 'response_header_operations'


class IdOnlyType(BaseType):
    id = wtypes.wsattr(wtypes.UuidType(), mandatory=True)


class NameOnlyType(BaseType):
    name = wtypes.wsattr(wtypes.StringType(max_length=255), mandatory=True)


class PageType(BaseType):
    href = wtypes.StringType()
    rel = wtypes.StringType()
