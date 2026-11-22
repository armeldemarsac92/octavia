# Copyright 2016 Blue Box, an IBM Company
# All Rights Reserved.
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

"""
Several handy validation functions that go beyond simple type checking.
Defined here so these can also be used at deeper levels than the API.
"""


import ipaddress
import re
import typing
import uuid

from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from rfc3986 import uri_reference
from rfc3986 import validators
from wsme import types as wtypes

from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import utils
from octavia.i18n import _

if typing.TYPE_CHECKING:
    from octavia.common import context

CONF = cfg.CONF
_ListenerPUT = 'octavia.api.v2.types.listener.ListenerPUT'


# Reject control characters and spaces in URLs before passing to rfc3986.
# The rfc3986 library encodes these (e.g. \n -> %0A) before validating, so
# they pass structural validation, but Octavia stores the raw input which
# ends up in HAProxy config files — allowing config injection via newlines.
INVALID_URL_CHARS_RE = re.compile(r'[\x00-\x20\x7f-\x9f]')


def url(url, require_scheme=True):
    """Raises an error if the url doesn't look like a URL."""
    if INVALID_URL_CHARS_RE.search(url):
        raise exceptions.InvalidURL(url=url)

    validator = validators.Validator()
    if require_scheme:
        validator.allow_schemes('http', 'https')
        validator.require_presence_of('scheme', 'host')
        validator.check_validity_of('scheme', 'host', 'path')
    else:
        validator.check_validity_of('path')

    try:
        validator.validate(uri_reference(url))
    except Exception as e:
        raise exceptions.InvalidURL(url=url) from e
    return True


def url_path(url_path):
    """Raises an error if the url_path doesn't look like a URL Path."""
    validator = validators.Validator().check_validity_of('path')
    try:
        p_url = uri_reference(url_path)
        validator.validate(p_url)

        invalid_path = (
            re.search(r"\s", url_path) or
            p_url.scheme or p_url.userinfo or p_url.host or
            p_url.port or
            p_url.path is None or
            not p_url.path.startswith('/')
        )

        if invalid_path:
            raise exceptions.InvalidURLPath(url_path=url_path)
    except Exception as e:
        raise exceptions.InvalidURLPath(url_path=url_path) from e
    return True


def header_name(header, what=None):
    """Raises an error if header does not look like an HTML header name."""
    p = re.compile(constants.HTTP_HEADER_NAME_REGEX)
    if not p.match(header):
        raise exceptions.InvalidString(what=what)
    return True


def cookie_value_string(value, what=None):
    """Raises an error if the value string contains invalid characters."""
    p = re.compile(constants.HTTP_COOKIE_VALUE_REGEX)
    if not p.match(value):
        raise exceptions.InvalidString(what=what)
    return True


def header_value_string(value, what=None):
    """Raises an error if the value string contains invalid characters."""
    p = re.compile(constants.HTTP_HEADER_VALUE_REGEX)
    q = re.compile(constants.HTTP_QUOTED_HEADER_VALUE_REGEX)
    if not p.match(value) and not q.match(value):
        raise exceptions.InvalidString(what=what)
    return True


def regex(regex):
    """Raises an error if the string given is not a valid regex."""
    try:
        re.compile(regex)
    except Exception as e:
        raise exceptions.InvalidRegex(e=str(e))
    return True


DNS_LABEL_RE = re.compile(
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?')


def is_exact_sni_name(value):
    if not value or len(value) > 253 or not all(
            DNS_LABEL_RE.fullmatch(label) for label in value.split('.')):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def https_listener_hostname(value):
    if value == '*':
        return value
    if isinstance(value, str) and len(value) <= 253:
        name = value[2:] if value.startswith('*.') else value
        if is_exact_sni_name(name):
            return value.lower()
    raise exceptions.ValidationException(detail=_(
        'HTTPS listener hostnames must be exact DNS names, wildcard DNS '
        'suffixes beginning with "*.", or "*".'))


def https_virtual_hosts(values):
    if not isinstance(values, list) or not values:
        raise exceptions.ValidationException(detail=_(
            'https_virtual_hosts must contain at least one hostname.'))
    hosts = [https_listener_hostname(value) for value in values]
    if len(hosts) != len(set(hosts)):
        raise exceptions.ValidationException(detail=_(
            'https_virtual_hosts requires distinct hostnames.'))
    return sorted(hosts)


def validate_https_listener(protocol, certificate, sni_certificates,
                            default_pool, default_response):
    if protocol != constants.PROTOCOL_TERMINATED_HTTPS:
        raise exceptions.ValidationException(detail=_(
            'https_virtual_hosts requires a TERMINATED_HTTPS listener.'))
    if not certificate or sni_certificates:
        raise exceptions.ValidationException(detail=_(
            'https_virtual_hosts requires one default certificate and '
            'no SNI certificate references.'))
    if (default_pool or (default_response is not None and
                         fixed_http_status_code(default_response) != 404)):
        raise exceptions.ValidationException(detail=_(
            'https_virtual_hosts requires an HTTP 404 fallback.'))


def validate_https_policy_hostname(hosts, value):
    if hosts is None and value is None:
        return None
    if hosts is not None and value is not None:
        hostname = https_listener_hostname(value)
        if hostname in hosts:
            return hostname
    raise exceptions.ValidationException(detail=_(
        'A scoped HTTPS L7 policy must select one hostname configured on '
        'its listener. Other L7 policies cannot specify a listener hostname.'))


def is_tls_sni_rule(rule):
    if (rule.type != constants.L7RULE_TYPE_TLS_SNI or
            rule.key not in (None, wtypes.Unset) or rule.invert):
        return False
    if rule.compare_type == constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
        return is_exact_sni_name(rule.value)
    if rule.compare_type == constants.L7RULE_COMPARE_TYPE_ENDS_WITH:
        value = rule.value
        return (bool(value) and len(value) <= 253 and
                value.startswith('*.') and is_exact_sni_name(value[2:]))
    return False


def validate_tcp_redirect_pool_protocol(protocol, tls_enabled):
    if protocol != constants.PROTOCOL_TCP or tls_enabled:
        raise exceptions.ValidationException(detail=_(
            'TCP listener policies require a TCP pool with '
            'tls_enabled false.'))


# Note that we can evaluate this outside the context of any L7 Policy because
# L7 rules must be internally consistent.
def l7rule_data(l7rule, *, validate_request_value=False):
    """Raises an error if the l7rule given is invalid in some way."""
    if not l7rule.value:
        raise exceptions.InvalidL7Rule(msg=_('L7 rule type requires a value'))
    if l7rule.type == constants.L7RULE_TYPE_HTTP_QUERY_PARAM_EXACT:
        if l7rule.compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_QUERY_PARAM_EXACT requires EQUAL_TO.'))
        if not l7rule.key or not _HEADER_NAME_RE.fullmatch(l7rule.key):
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_QUERY_PARAM_EXACT requires an ASCII token name of '
                '1 to 256 characters.'))
        if len(l7rule.value) > constants.MAX_L7RULE_QUERY_PARAM_VALUE_LENGTH:
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_QUERY_PARAM_EXACT values are limited to 1024 '
                'characters.'))
        try:
            l7rule.value.encode('utf-8')
        except UnicodeEncodeError as e:
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_QUERY_PARAM_EXACT requires a valid UTF-8 value.')) from e
        return True

    if l7rule.key and len(l7rule.key) > constants.MAX_L7RULE_KEY_LENGTH:
        raise exceptions.InvalidL7Rule(msg=_(
            'L7 rule keys are limited to 255 characters.'))
    # Preserve the original WSME pattern, which allows one final LF. Apply
    # it to request values so previously stored rules can still be edited.
    if (validate_request_value and
            ('\r' in l7rule.value or '\n' in l7rule.value.removesuffix('\n'))):
        raise exceptions.InvalidL7Rule(msg=_(
            'Line breaks are unsupported in values for this L7 rule type.'))
    if l7rule.type == constants.L7RULE_TYPE_HTTP_HEADER_EXACT:
        if l7rule.compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_HEADER_EXACT requires EQUAL_TO.'))
        if not l7rule.key or not _HEADER_NAME_RE.fullmatch(l7rule.key):
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_HEADER_EXACT requires a valid HTTP header name.'))
        if (len(l7rule.value) > constants.MAX_L7RULE_HEADER_VALUE_LENGTH or
                l7rule.value != l7rule.value.strip(' \t') or
                _HEADER_VALUE_CONTROL_RE.search(l7rule.value)):
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_HEADER_EXACT requires valid HTTP field content '
                'without surrounding whitespace.'))
        return True

    if len(l7rule.value) > constants.MAX_LEGACY_L7RULE_VALUE_LENGTH:
        raise exceptions.InvalidL7Rule(msg=_(
            'L7 rule values are limited to 255 characters for this type.'))

    if l7rule.type == constants.L7RULE_TYPE_TLS_SNI:
        if not is_tls_sni_rule(l7rule):
            raise exceptions.InvalidL7Rule(msg=_(
                'TLS_SNI requires EQUAL_TO with an exact DNS hostname or '
                'ENDS_WITH with a DNS wildcard like *.example.test. '
                'Keys and inversion are unsupported.'))

    elif l7rule.type == constants.L7RULE_TYPE_HTTP_METHOD:
        if (l7rule.compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO or
                l7rule.value not in constants.L7RULE_HTTP_METHODS or
                l7rule.key not in (None, wtypes.Unset) or l7rule.invert):
            raise exceptions.InvalidL7Rule(msg=_(
                'HTTP_METHOD requires EQUAL_TO with a supported uppercase '
                'HTTP method. Keys and inversion are unsupported.'))

    elif l7rule.type == constants.L7RULE_TYPE_GRPC_CONTENT_TYPE:
        if (l7rule.compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO or
                l7rule.value != constants.GRPC_CONTENT_TYPE or
                l7rule.key not in (None, wtypes.Unset) or l7rule.invert):
            raise exceptions.InvalidL7Rule(msg=_(
                'GRPC_CONTENT_TYPE requires EQUAL_TO with application/grpc. '
                'Keys and inversion are unsupported.'))

    elif l7rule.type == constants.L7RULE_TYPE_HEADER:
        if not l7rule.key:
            raise exceptions.InvalidL7Rule(msg='L7 rule type requires a key')
        header_name(l7rule.key, what='key')
        if l7rule.compare_type == constants.L7RULE_COMPARE_TYPE_REGEX:
            regex(l7rule.value)
        elif l7rule.compare_type in (
                constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                constants.L7RULE_COMPARE_TYPE_CONTAINS,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO):
            header_value_string(l7rule.value, what='header value')
        else:
            raise exceptions.InvalidL7Rule(msg='invalid comparison type '
                                           'for rule type')

    elif l7rule.type == constants.L7RULE_TYPE_COOKIE:
        if not l7rule.key:
            raise exceptions.InvalidL7Rule(msg='L7 rule type requires a key')
        header_name(l7rule.key, what='key')
        if l7rule.compare_type == constants.L7RULE_COMPARE_TYPE_REGEX:
            regex(l7rule.value)
        elif l7rule.compare_type in (
                constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                constants.L7RULE_COMPARE_TYPE_CONTAINS,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO):
            cookie_value_string(l7rule.value, what='cookie value')
        else:
            raise exceptions.InvalidL7Rule(msg='invalid comparison type '
                                           'for rule type')

    elif l7rule.type in (constants.L7RULE_TYPE_HOST_NAME,
                         constants.L7RULE_TYPE_PATH):
        if l7rule.compare_type in (
                constants.L7RULE_COMPARE_TYPE_STARTS_WITH,
                constants.L7RULE_COMPARE_TYPE_ENDS_WITH,
                constants.L7RULE_COMPARE_TYPE_CONTAINS,
                constants.L7RULE_COMPARE_TYPE_EQUAL_TO):
            header_value_string(l7rule.value, what='comparison value')
        elif l7rule.compare_type == constants.L7RULE_COMPARE_TYPE_REGEX:
            regex(l7rule.value)
        else:
            raise exceptions.InvalidL7Rule(msg='invalid comparison type '
                                           'for rule type')

    elif l7rule.type == constants.L7RULE_TYPE_FILE_TYPE:
        if l7rule.compare_type == constants.L7RULE_COMPARE_TYPE_REGEX:
            regex(l7rule.value)
        elif l7rule.compare_type == constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
            header_value_string(l7rule.value, what='comparison value')
        else:
            raise exceptions.InvalidL7Rule(msg='invalid comparison type '
                                           'for rule type')

    elif l7rule.type in [constants.L7RULE_TYPE_SSL_CONN_HAS_CERT,
                         constants.L7RULE_TYPE_SSL_VERIFY_RESULT,
                         constants.L7RULE_TYPE_SSL_DN_FIELD]:
        validate_l7rule_ssl_types(l7rule)

    else:
        raise exceptions.InvalidL7Rule(msg='invalid rule type')
    return True


def validate_l7rule_ssl_types(l7rule):
    if not l7rule.type or l7rule.type not in [
       constants.L7RULE_TYPE_SSL_CONN_HAS_CERT,
       constants.L7RULE_TYPE_SSL_VERIFY_RESULT,
       constants.L7RULE_TYPE_SSL_DN_FIELD]:
        return

    rule_type = None if l7rule.type == wtypes.Unset else l7rule.type
    req_key = None if l7rule.key == wtypes.Unset else l7rule.key
    req_value = None if l7rule.value == wtypes.Unset else l7rule.value
    compare_type = (None if l7rule.compare_type == wtypes.Unset else
                    l7rule.compare_type)
    msg = None
    if rule_type == constants.L7RULE_TYPE_SSL_CONN_HAS_CERT:
        # key and value are not allowed
        if req_key:
            # log error or raise
            msg = f'L7rule type {rule_type} does not use the "key" field.'
        elif req_value.lower() != 'true':
            msg = f'L7rule value {req_value} is not a boolean True string.'
        elif compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
            msg = 'L7rule type {} only supports the {} compare type.'.format(
                rule_type, constants.L7RULE_COMPARE_TYPE_EQUAL_TO)

    if rule_type == constants.L7RULE_TYPE_SSL_VERIFY_RESULT:
        if req_key:
            # log or raise req_key not used
            msg = f'L7rule type {rule_type} does not use the "key" field.'
        elif not req_value.isdigit() or int(req_value) < 0:
            # log or raise req_value must be int
            msg = f'L7rule type {rule_type} needs a int value, which is >= 0'
        elif compare_type != constants.L7RULE_COMPARE_TYPE_EQUAL_TO:
            msg = 'L7rule type {} only supports the {} compare type.'.format(
                rule_type, constants.L7RULE_COMPARE_TYPE_EQUAL_TO)

    if rule_type == constants.L7RULE_TYPE_SSL_DN_FIELD:
        dn_regex = re.compile(constants.DISTINGUISHED_NAME_FIELD_REGEX)
        if compare_type == constants.L7RULE_COMPARE_TYPE_REGEX:
            regex(l7rule.value)

        if not req_key or not req_value:
            # log or raise key and value must be specified.
            msg = (f'L7rule type {rule_type} needs to specify a '
                   f'key and a value.')
        # log or raise the key must be splited by '-'
        elif not dn_regex.match(req_key):
            msg = 'Invalid L7rule distinguished name field.'

    if msg:
        raise exceptions.InvalidL7Rule(msg=msg)


def fixed_http_status_code(response):
    if (not isinstance(response, dict) or
            response.keys() != {'status_code'} or
            type(response['status_code']) is not int or
            response['status_code'] not in
            lib_consts.SUPPORTED_FIXED_HTTP_STATUS_CODES):
        raise exceptions.ValidationException(
            detail='The HTTP response must specify status_code 404 or 500.')
    return response['status_code']


def validate_fixed_http_protocol(protocol):
    if protocol not in (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail='Local HTTP responses require an HTTP or '
                   'TERMINATED_HTTPS listener.')


def validate_default_http_response(protocol, response, default_pool):
    if response is not None:
        validate_fixed_http_protocol(protocol)
        fixed_http_status_code(response)
        if default_pool:
            raise exceptions.ValidationException(
                detail='default_http_response and a default pool are '
                       'mutually exclusive.')


def validate_weighted_l7policy_protocol(protocol):
    if protocol not in (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('Weighted targets require an HTTP or '
                     'TERMINATED_HTTPS listener.'))


def weighted_l7policy_targets(targets):
    if (not isinstance(targets, list) or
            not 1 <= len(targets) <= constants.MAX_L7POLICY_TARGETS):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('targets must contain between 1 and 16 entries.'))

    normalized = []
    for target in targets:
        if (not isinstance(target, dict) or
                target.keys() not in ({'weight', 'pool_id'},
                                      {'weight', 'fixed_response'})):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Each target requires weight and exactly one of '
                      'pool_id or fixed_response.'))

        weight = target['weight']
        if (type(weight) is not int or
                not 0 <= weight <= constants.MAX_L7POLICY_TARGET_WEIGHT):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Target weight must be an integer from 0 to 1000000.'))

        if 'pool_id' in target:
            try:
                pool_id = str(uuid.UUID(target['pool_id']))
            except (AttributeError, TypeError, ValueError) as e:
                raise exceptions.InvalidL7PolicyArgs(
                    msg=_('Target pool_id must be a UUID.')) from e
            normalized.append({'weight': weight, 'pool_id': pool_id})
        else:
            status = fixed_http_status_code(target['fixed_response'])
            normalized.append({'weight': weight,
                               'fixed_response': {'status_code': status}})

    if not any(target['weight'] for target in normalized):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('Total target weight must be positive.'))
    return normalized


_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_\x60|~0-9A-Za-z]{1,256}")
_HEADER_VALUE_CONTROL_RE = re.compile(r'[\x00-\x08\x0a-\x1f\x7f\ud800-\udfff]')


# Connection management and framing are controlled by HAProxy.
_RESPONSE_TRANSPORT_HEADERS = frozenset({
    'connection', 'content-length', 'keep-alive', 'proxy-connection', 'te',
    'trailer', 'transfer-encoding', 'upgrade',
})


def header_operations(operations, field):
    if not isinstance(operations, list) or len(operations) > 48:
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('%s must be an array of up to 48 entries.') % field)

    names = set()
    normalized = []
    for item in operations:
        operation = item.get('operation') if isinstance(item, dict) else None
        if (operation not in ('SET', 'ADD', 'REMOVE') or
                item.keys() != ({'operation', 'name'} if operation == 'REMOVE'
                                else {'operation', 'name', 'value'})):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Each header operation requires SET, ADD or REMOVE, '
                      'a name, and a value for SET and ADD only.'))
        name = item['name']
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Invalid header name.'))
        name = name.lower()
        if (field == 'response_header_operations' and
                name in _RESPONSE_TRANSPORT_HEADERS):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Response framing and connection headers are managed '
                      'by the listener.'))
        if name in names:
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Header operation names must be unique '
                      'regardless of case.'))
        names.add(name)
        result = {'operation': operation, 'name': name}
        if operation != 'REMOVE':
            value = item['value']
            if (not isinstance(value, str) or len(value) > 4096 or
                    _HEADER_VALUE_CONTROL_RE.search(value)):
                raise exceptions.InvalidL7PolicyArgs(
                    msg=_('Invalid header value.'))
            result['value'] = value
        normalized.append(result)
    return normalized


def validate_header_protocol(protocol):
    if protocol not in (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('Header operations require an HTTP or '
                     'TERMINATED_HTTPS listener.'))


HTTP_URL_PATH_RE = re.compile(
    r"/(?:[a-zA-Z0-9/._~!$&'()*+,;=:@-]|%[a-fA-F0-9]{2})*")
_HTTP_URL_MODIFIER_FIELDS = {'hostname', 'replace_full_path', 'replace_prefix'}


def http_request_redirect(redirect):
    if (not isinstance(redirect, dict) or
            redirect.keys() - (_HTTP_URL_MODIFIER_FIELDS | {'scheme', 'port'})):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('Invalid redirect_request fields.'))
    if redirect.get('scheme') not in ('http', 'https'):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('redirect_request.scheme must be http or https.'))
    port = redirect.get('port')
    if type(port) is not int or not 1 <= port <= constants.MAX_PORT_NUMBER:
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('redirect_request.port must be an integer from 1 to 65535.'))
    _validate_http_url_modifiers(redirect, 'redirect_request')
    return redirect


def http_request_url_rewrite(rewrite):
    if (not isinstance(rewrite, dict) or not rewrite or
            rewrite.keys() - _HTTP_URL_MODIFIER_FIELDS):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('request_url_rewrite requires hostname or a path '
                  'replacement.'))
    _validate_http_url_modifiers(rewrite, 'request_url_rewrite')
    return rewrite


def _validate_http_url_modifiers(modifiers, field):
    if 'hostname' in modifiers:
        hostname = modifiers['hostname']
        if not isinstance(hostname, str) or not is_exact_sni_name(hostname):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('%s.hostname must be a DNS name.') % field)
    if 'replace_prefix' in modifiers:
        if 'replace_full_path' in modifiers:
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('Specify only one redirect path replacement.')
                if field == 'redirect_request' else
                _('Specify only one rewrite path replacement.'))
        prefix = modifiers['replace_prefix']
        if not isinstance(prefix, dict) or prefix.keys() != {
                'match', 'replacement'}:
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('replace_prefix requires match and replacement.'))
        match = prefix['match']
        if (not isinstance(match, str) or len(match) > 1024 or
                not HTTP_URL_PATH_RE.fullmatch(match) or
                any(part in match for part in ('//', '/./', '/../')) or
                '%2f' in match.lower() or match.endswith(('/.', '/..'))):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('replace_prefix.match must be a valid absolute '
                      'PathPrefix of at most 1024 characters.'))
        _validate_http_url_replacement(prefix['replacement'], field)
    if 'replace_full_path' in modifiers:
        _validate_http_url_replacement(modifiers['replace_full_path'], field)


def _validate_http_url_replacement(path, field):
    if (not isinstance(path, str) or len(path) > 1024 or
            any(0xD800 <= ord(char) <= 0xDFFF for char in path)):
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('Redirect replacements must be UTF-8 text of at most '
                  '1024 characters.') if field == 'redirect_request' else
            _('Rewrite replacements must be UTF-8 text of at most '
              '1024 characters.'))


def validate_http_request_redirect_protocol(protocol):
    if protocol not in (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('HTTP request redirects require an HTTP or '
                     'TERMINATED_HTTPS listener.'))


def validate_http_request_url_rewrite_protocol(protocol):
    if protocol not in (constants.PROTOCOL_HTTP,
                        constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('HTTP request URL rewrites require an HTTP or '
                     'TERMINATED_HTTPS listener.'))


def validate_listener_pool_protocol(listener_protocol, pool_protocol):
    if pool_protocol not in constants.VALID_LISTENER_POOL_PROTOCOL_MAP[
            listener_protocol]:
        raise exceptions.ValidationException(detail=_(
            "The pool protocol '%(pool_protocol)s' is invalid while the "
            "listener protocol is '%(listener_protocol)s'.") % {
                'pool_protocol': pool_protocol,
                'listener_protocol': listener_protocol})


def sanitize_l7policy_api_args(l7policy, create=False, old_policy=None):
    """Validate and make consistent L7Policy API arguments.

    This method is mainly meant to sanitize L7 Policy create and update
    API dictionaries, so that we strip 'None' values that don't apply for
    our particular update. This method does *not* verify that any
    redirect_pool_id exists in the database, but will raise an
    error if a redirect_url doesn't look like a URL.

    :param l7policy: The L7 Policy dictionary we are sanitizing / validating
    """
    fixed_action = constants.L7POLICY_ACTION_FIXED_RESPONSE
    weighted_action = constants.L7POLICY_ACTION_WEIGHTED_TARGETS
    request_redirect_action = constants.L7POLICY_ACTION_REDIRECT_REQUEST
    old_action = old_policy.action if old_policy is not None else None
    action = l7policy.get('action')
    redirect_targets = (
        'redirect_pool_id', 'redirect_pool', 'redirect_url', 'redirect_prefix')
    has_redirect_target = any(l7policy.get(target)
                              for target in redirect_targets)
    # Legacy partial updates can select a redirect action by target alone.
    if ('action' not in l7policy and not has_redirect_target and
            old_action in (fixed_action, weighted_action,
                           request_redirect_action)):
        action = old_action

    if action == request_redirect_action:
        if any(l7policy.get(target) is not None
               for target in redirect_targets):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('REDIRECT_REQUEST cannot use legacy redirect targets.'))
        if 'redirect_request' in l7policy or old_action != action:
            l7policy['redirect_request'] = http_request_redirect(
                l7policy.get('redirect_request'))
        if old_action != action or 'redirect_http_code' in l7policy:
            code = l7policy.get('redirect_http_code')
            if code is None:
                l7policy['redirect_http_code'] = 302
            elif (type(code) is not int or code not in
                  constants.SUPPORTED_L7POLICY_REDIRECT_HTTP_CODES):
                raise exceptions.InvalidL7PolicyArgs(
                    msg=_('Invalid redirect_http_code.'))
    elif l7policy.get('redirect_request') is not None:
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('redirect_request requires the REDIRECT_REQUEST action.'))
    elif old_action == request_redirect_action:
        l7policy['redirect_request'] = None
    else:
        l7policy.pop('redirect_request', None)

    if action == weighted_action:
        if any(l7policy.get(field) is not None for field in (
                *redirect_targets, 'redirect_http_code', 'fixed_response')):
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('WEIGHTED_TARGETS is incompatible with redirect '
                      'fields and fixed_response.'))
        if 'targets' in l7policy or old_action != weighted_action:
            l7policy['targets'] = weighted_l7policy_targets(
                l7policy.get('targets'))
    elif l7policy.get('targets') is not None:
        raise exceptions.InvalidL7PolicyArgs(
            msg=_('targets requires the WEIGHTED_TARGETS action.'))
    elif old_action == weighted_action:
        l7policy['targets'] = None
    else:
        l7policy.pop('targets', None)

    if action == fixed_action:
        response = l7policy.get(
            'fixed_response',
            old_policy.fixed_response if old_policy is not None else None)
        fixed_http_status_code(response)
        if any(l7policy.get(target) is not None
               for target in (*redirect_targets, 'redirect_http_code')):
            raise exceptions.InvalidL7PolicyArgs(
                msg='FIXED_RESPONSE is incompatible with redirect targets '
                    'and redirect_http_code.')
    elif l7policy.get('fixed_response') is not None:
        raise exceptions.InvalidL7PolicyArgs(
            msg='fixed_response requires the FIXED_RESPONSE action.')
    elif old_action == fixed_action:
        l7policy['fixed_response'] = None

    if 'action' in l7policy:
        if action in (fixed_action, weighted_action):
            l7policy.update(redirect_pool_id=None, redirect_url=None,
                            redirect_prefix=None, redirect_http_code=None)
            l7policy.pop('redirect_pool', None)
        elif action == constants.L7POLICY_ACTION_REJECT:
            l7policy.update({'redirect_url': None})
            l7policy.update({'redirect_pool_id': None})
            l7policy.pop('redirect_pool', None)
        elif l7policy['action'] == constants.L7POLICY_ACTION_REDIRECT_TO_URL:
            if not l7policy.get('redirect_url'):
                raise exceptions.InvalidL7PolicyArgs(
                    msg='redirect_url must not be None')
            l7policy.update({'redirect_pool_id': None})
            l7policy.pop('redirect_pool', None)
        elif l7policy['action'] == constants.L7POLICY_ACTION_REDIRECT_TO_POOL:
            if (not l7policy.get('redirect_pool_id') and
                    not l7policy.get('redirect_pool')):
                raise exceptions.InvalidL7PolicyArgs(
                    msg='redirect_pool_id or redirect_pool must not be None')
            l7policy.update({'redirect_url': None})
        elif l7policy['action'] == constants.L7POLICY_ACTION_REDIRECT_PREFIX:
            if not l7policy.get('redirect_prefix'):
                raise exceptions.InvalidL7PolicyArgs(
                    msg='redirect_prefix must not be None')
        elif action == request_redirect_action:
            l7policy.update(redirect_pool_id=None, redirect_url=None,
                            redirect_prefix=None)
            l7policy.pop('redirect_pool', None)
        else:
            raise exceptions.InvalidL7PolicyAction(
                action=l7policy['action'])
    if ((l7policy.get('redirect_pool_id') or l7policy.get('redirect_pool')) and
            (l7policy.get('redirect_url') or l7policy.get('redirect_prefix'))):
        raise exceptions.InvalidL7PolicyArgs(
            msg='Cannot specify redirect_pool_id and redirect_url or '
                'redirect_prefix at the same time')
    if l7policy.get('redirect_pool_id'):
        l7policy.update({
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL})
        l7policy.update({'redirect_url': None})
        l7policy.pop('redirect_pool', None)
        l7policy.update({'redirect_prefix': None})
        l7policy.update({'redirect_http_code': None})
    if l7policy.get('redirect_pool'):
        l7policy.update({
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_POOL})
        l7policy.update({'redirect_url': None})
        l7policy.pop('redirect_pool_id', None)
        l7policy.update({'redirect_prefix': None})
        l7policy.update({'redirect_http_code': None})
    if l7policy.get('redirect_url'):
        url(l7policy['redirect_url'])
        l7policy.update({
            'action': constants.L7POLICY_ACTION_REDIRECT_TO_URL})
        l7policy.update({'redirect_pool_id': None})
        l7policy.update({'redirect_prefix': None})
        l7policy.pop('redirect_pool', None)
        if not l7policy.get('redirect_http_code'):
            l7policy.update({'redirect_http_code': 302})
    if l7policy.get('redirect_prefix'):
        url(l7policy['redirect_prefix'])
        l7policy.update({
            'action': constants.L7POLICY_ACTION_REDIRECT_PREFIX})
        l7policy.update({'redirect_pool_id': None})
        l7policy.update({'redirect_url': None})
        l7policy.pop('redirect_pool', None)
        if not l7policy.get('redirect_http_code'):
            l7policy.update({'redirect_http_code': 302})

    forwarding_actions = (constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
                          constants.L7POLICY_ACTION_WEIGHTED_TARGETS)
    rewrite = l7policy.get('request_url_rewrite',
                           getattr(old_policy, 'request_url_rewrite', None))
    if rewrite is not None:
        if l7policy.get('action', old_action) not in forwarding_actions:
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('request_url_rewrite requires REDIRECT_TO_POOL or '
                      'WEIGHTED_TARGETS.'))
        if 'request_url_rewrite' in l7policy:
            l7policy['request_url_rewrite'] = http_request_url_rewrite(rewrite)
    for field, actions in (
            ('request_header_operations', forwarding_actions),
            ('response_header_operations',
             (*forwarding_actions, constants.L7POLICY_ACTION_FIXED_RESPONSE))):
        if field in l7policy:
            l7policy[field] = header_operations(l7policy[field], field)
        operations = l7policy.get(field, getattr(old_policy, field, None))
        if operations and l7policy.get('action', old_action) not in actions:
            raise exceptions.InvalidL7PolicyArgs(
                msg=_('%s is unavailable for this policy action.') % field)

    # If we are creating, we need an action at this point
    if create and 'action' not in l7policy.keys():
        raise exceptions.InvalidL7PolicyAction(action='None')

    # See if we have anything left after that...
    if not l7policy.keys():
        raise exceptions.InvalidL7PolicyArgs(msg='Invalid update options')
    return l7policy


def port_exists(port_id, context=None):
    """Raises an exception when a port does not exist."""
    network_driver = utils.get_network_driver()
    try:
        port = network_driver.get_port(port_id, context=context)
    except Exception as e:
        raise exceptions.InvalidSubresource(resource='Port', id=port_id) from e
    return port


def check_port_in_use(port):
    """Raise an exception when a port is used."""
    if port.device_id:
        raise exceptions.ValidationException(detail=_(
            "Port %(port_id)s is already used by device %(device_id)s ") %
            {'port_id': port.id, 'device_id': port.device_id})
    return False


def subnet_exists(subnet_id, context=None):
    """Raises an exception when a subnet does not exist."""
    network_driver = utils.get_network_driver()
    try:
        subnet = network_driver.get_subnet(subnet_id, context=context)
    except Exception as e:
        raise exceptions.InvalidSubresource(
            resource='Subnet', id=subnet_id) from e
    return subnet


def qos_policy_exists(qos_policy_id, context=None):
    network_driver = utils.get_network_driver()
    qos_extension_enabled(network_driver)
    try:
        qos_policy = network_driver.get_qos_policy(qos_policy_id,
                                                   context=context)
    except Exception as e:
        raise exceptions.InvalidSubresource(
            resource='qos_policy', id=qos_policy_id) from e
    return qos_policy


def qos_extension_enabled(network_driver):
    if not network_driver.qos_enabled():
        raise exceptions.ValidationException(detail=_(
            "VIP QoS policy is not allowed in this deployment."))


def network_exists_optionally_contains_subnet(network_id, subnet_id=None,
                                              context=None):
    """Raises an exception when a network does not exist.

    If a subnet is provided, also validate the network contains that subnet.
    """
    network_driver = utils.get_network_driver()
    try:
        network = network_driver.get_network(network_id, context=context)
    except Exception as e:
        raise exceptions.InvalidSubresource(
            resource='Network', id=network_id) from e
    if subnet_id:
        if not network.subnets or subnet_id not in network.subnets:
            raise exceptions.InvalidSubresource(resource='Subnet',
                                                id=subnet_id)
    return network


def security_group_exists(sg_id: str,
                          context: 'context.RequestContext' = None):
    """Raises an exception when a security group does not exist."""
    network_driver = utils.get_network_driver()
    try:
        network_driver.get_security_group_by_id(sg_id,
                                                context=context)
    except Exception as e:
        raise exceptions.InvalidSubresource(
            resource='Security Group', id=sg_id) from e


def network_allowed_by_config(network_id, valid_networks=None):
    if CONF.networking.valid_vip_networks and not valid_networks:
        valid_networks = CONF.networking.valid_vip_networks
    if valid_networks:
        valid_networks = map(str.lower, valid_networks)
        if network_id.lower() not in valid_networks:
            raise exceptions.ValidationException(detail=_(
                'Supplied VIP network_id is not allowed by the configuration '
                'of this deployment.'))


def network_denylist_by_config(network_id):
    denylist = CONF.networking.denylist_vip_networks
    if isinstance(denylist, list) and len(denylist) > 0:
        denylist = map(str.lower, denylist)
        if network_id.lower() in denylist:
            raise exceptions.ValidationException(detail=_(
                'Supplied VIP network_id is not allowed by the configuration '
                'of this deployment.'))


def is_ip_member_of_cidr(address, cidr):
    if ipaddress.ip_address(address) in ipaddress.ip_network(cidr):
        return True
    return False


def check_session_persistence(SP_dict):
    try:
        if SP_dict['cookie_name']:
            if SP_dict['type'] != constants.SESSION_PERSISTENCE_APP_COOKIE:
                raise exceptions.ValidationException(detail=_(
                    'Field "cookie_name" can only be specified with session '
                    'persistence of type "APP_COOKIE".'))
            bad_cookie_name = re.compile(r'[\x00-\x20\x22\x28-\x29\x2c\x2f'
                                         r'\x3a-\x40\x5b-\x5d\x7b\x7d\x7f]+')
            valid_chars = re.compile(r'[\x00-\xff]+')
            if (bad_cookie_name.search(SP_dict['cookie_name']) or
                    not valid_chars.search(SP_dict['cookie_name'])):
                raise exceptions.ValidationException(detail=_(
                    'Supplied "cookie_name" is invalid.'))
        if (SP_dict['type'] == constants.SESSION_PERSISTENCE_APP_COOKIE and
                not SP_dict['cookie_name']):
            raise exceptions.ValidationException(detail=_(
                'Field "cookie_name" must be specified when using the '
                '"APP_COOKIE" session persistence type.'))
    except exceptions.ValidationException:
        raise
    except Exception as e:
        raise exceptions.ValidationException(detail=_(
            'Invalid session_persistence provided.')) from e


def ip_not_reserved(ip_address):
    ip_address = (
        ipaddress.ip_address(ip_address).exploded.upper())
    if ip_address in CONF.networking.reserved_ips:
        raise exceptions.InvalidOption(value=ip_address,
                                       option='member address')


VALID_CIPHER_RE = re.compile(r'^[A-Za-z0-9\-+!:@=_.]+\Z')


def check_cipher_string(cipherstring):
    """Validate that a cipher string contains only safe characters."""
    if not VALID_CIPHER_RE.match(cipherstring):
        raise exceptions.ValidationException(detail=_(
            'Invalid characters in cipher string. '
            'Only alphanumeric, -, +, !, :, @, =, _, and . '
            'are allowed.'))


def check_cipher_prohibit_list(cipherstring):
    check_cipher_string(cipherstring)
    ciphers = cipherstring.split(':')
    prohibit_list = CONF.api_settings.tls_cipher_prohibit_list.split(':')
    rejected = []
    for cipher in ciphers:
        if cipher in prohibit_list:
            rejected.append(cipher)
    return rejected


def check_default_ciphers_prohibit_list_conflict():
    listener_rejected = check_cipher_prohibit_list(
        CONF.api_settings.default_listener_ciphers)
    if listener_rejected:
        raise exceptions.ValidationException(
            detail=_('Default listener ciphers conflict with prohibit list. '
                     'Conflicting ciphers: ' + ', '.join(listener_rejected)))

    pool_rejected = check_cipher_prohibit_list(
        CONF.api_settings.default_pool_ciphers)
    if pool_rejected:
        raise exceptions.ValidationException(
            detail=_('Default pool ciphers conflict with prohibit list. '
                     'Conflicting ciphers: ' + ', '.join(pool_rejected)))


def check_tls_version_list(versions):
    if versions == []:
        raise exceptions.ValidationException(
            detail=_('Empty TLS version list. Either specify at least one TLS '
                     'version or remove this parameter to use the default.'))

    # Unset action
    if versions is None:
        return

    invalid_versions = [v for v in versions
                        if v not in constants.TLS_ALL_VERSIONS]
    if invalid_versions:
        raise exceptions.ValidationException(
            detail=_('Invalid TLS versions: ' + ', '.join(invalid_versions)))


def check_tls_version_min(versions, message=None):
    """Checks a TLS version string against the configured minimum."""

    if not CONF.api_settings.minimum_tls_version:
        return

    if not message:
        message = _("Requested TLS versions are less than the minimum: ")

    min_ver_index = constants.TLS_ALL_VERSIONS.index(
        CONF.api_settings.minimum_tls_version)

    rejected = []
    for ver in versions:
        if constants.TLS_ALL_VERSIONS.index(ver) < min_ver_index:
            rejected.append(ver)
    if rejected:
        raise exceptions.ValidationException(detail=(
            message + ', '.join(rejected) + " < " +
            CONF.api_settings.minimum_tls_version))


def check_default_tls_versions_min_conflict():
    if not CONF.api_settings.minimum_tls_version:
        return

    listener_message = _("Default listener TLS versions are less than the "
                         "minimum: ")
    pool_message = _("Default pool TLS versions are less than the minimum: ")

    check_tls_version_min(CONF.api_settings.default_listener_tls_versions,
                          message=listener_message)

    check_tls_version_min(CONF.api_settings.default_pool_tls_versions,
                          message=pool_message)


def check_alpn_protocols(protocols):
    if protocols == []:
        raise exceptions.ValidationException(
            detail=_('Empty ALPN protocol list. Either specify at least one '
                     'ALPN protocol or remove this parameter to use the '
                     'default.'))

    # Unset action
    if protocols is None:
        return

    invalid_protocols = [p for p in protocols
                         if p not in constants.SUPPORTED_ALPN_PROTOCOLS]
    if invalid_protocols:
        raise exceptions.ValidationException(
            detail=_('Invalid ALPN protocol: ' + ', '.join(invalid_protocols)))


def check_hsts_options(listener: dict):
    if ((listener.get('hsts_include_subdomains') or
         listener.get('hsts_preload')) and
            not isinstance(listener.get('hsts_max_age'), int)):
        raise exceptions.ValidationException(
            detail=_('HSTS configuration options hsts_include_subdomains and '
                     'hsts_preload only make sense if hsts_max_age is '
                     'set as well.'))

    if (isinstance(listener.get('hsts_max_age'), int) and
            listener['protocol'] != constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('The HSTS feature can only be used for listeners using '
                     'the TERMINATED_HTTPS protocol.'))


def check_hsts_options_put(listener: _ListenerPUT,
                           db_listener: data_models.Listener):
    hsts_disabled = all(obj.hsts_max_age in [None, wtypes.Unset] for obj
                        in (db_listener, listener))
    if ((listener.hsts_include_subdomains or listener.hsts_preload) and
            hsts_disabled):
        raise exceptions.ValidationException(
            detail=_('Cannot enable hsts_include_subdomains or hsts_preload '
                     'if hsts_max_age was not set as well.'))

    if (isinstance(listener.hsts_max_age, int) and
            db_listener.protocol != constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(
            detail=_('The HSTS feature can only be used for listeners using '
                     'the TERMINATED_HTTPS protocol.'))
