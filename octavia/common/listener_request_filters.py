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

"""Ordered HTTP authorization filters applied before listener routing."""

import re
import uuid

from octavia.common import constants
from octavia.common import exceptions
from octavia.common import validate
from octavia.i18n import _


PATH_RE = re.compile(r"/(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*")
HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")


def normalize(sections):
    if not isinstance(sections, list):
        raise exceptions.ValidationException(detail=_(
            'request_filter_sections must be an array.'))
    result = []
    hostnames = set()
    for section in sections:
        if (not isinstance(section, dict) or 'hostname' not in section or
                section.keys() - {'hostname', 'reject', 'requests'}):
            raise exceptions.ValidationException(detail=_(
                'A listener request filter section requires a hostname.'))
        hostname = validate.https_listener_hostname(section['hostname'])
        if hostname in hostnames:
            raise exceptions.ValidationException(detail=_(
                'Listener request filter hostnames must be distinct.'))
        hostnames.add(hostname)

        reject = section.get('reject', False)
        requests = section.get('requests', [])
        if (type(reject) is not bool or not isinstance(requests, list) or
                len(requests) > 16 or (reject and requests)):
            raise exceptions.ValidationException(detail=_(
                'A listener section can reject locally or contain up to '
                '16 ordered request filters.'))
        normalized = {'hostname': hostname}
        if reject:
            normalized['reject'] = True
        if requests:
            normalized['requests'] = [_normalize_external_auth(request)
                                      for request in requests]
        result.append(normalized)
    return result


def _normalize_external_auth(request):
    if (not isinstance(request, dict) or
            request.keys() != {'type', 'http'} or
            request['type'] != 'ExternalAuth' or
            not isinstance(request['http'], dict)):
        raise exceptions.ValidationException(detail=_(
            'Only HTTP ExternalAuth listener request filters are supported.'))
    auth = request['http']
    if auth.keys() - {'pool_id', 'path_prefix', 'allowed_request_headers',
                      'allowed_response_headers'}:
        raise exceptions.ValidationException(detail=_(
            'Invalid HTTP ExternalAuth options.'))
    pool_id = auth.get('pool_id')
    try:
        if not isinstance(pool_id, str) or str(uuid.UUID(pool_id)) != pool_id:
            raise ValueError()
    except ValueError as exc:
        raise exceptions.ValidationException(detail=_(
            'HTTP ExternalAuth requires a pool UUID.')) from exc
    result = {'pool_id': pool_id}
    path = auth.get('path_prefix', '')
    if not isinstance(path, str) or (
            path and (len(path) > 1024 or not PATH_RE.fullmatch(path))):
        raise exceptions.ValidationException(detail=_(
            'Invalid HTTP ExternalAuth path prefix.'))
    if path:
        result['path_prefix'] = path
    for field in ('allowed_request_headers', 'allowed_response_headers'):
        headers = auth.get(field, [])
        if (not isinstance(headers, list) or len(headers) > 64 or
                any(not isinstance(name, str) or
                    not HEADER_NAME_RE.fullmatch(name) for name in headers)):
            raise exceptions.ValidationException(detail=_(
                'Invalid HTTP ExternalAuth header list.'))
        if headers:
            result[field] = sorted({name.lower() for name in headers})
    return {'type': 'ExternalAuth', 'http': result}


def pool_ids(sections):
    return {request['http']['pool_id'] for section in sections or ()
            for request in section.get('requests', ())}


def validate_listener(protocol, sections):
    if sections and protocol not in (constants.PROTOCOL_HTTP,
                                     constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(detail=_(
            'Listener request filters require an HTTP or TERMINATED_HTTPS '
            'listener.'))


def valid_pool(pool):
    return (pool.protocol == constants.PROTOCOL_HTTP and
            not pool.tls_enabled and not pool.backend_h2c and
            constants.GATEWAY_LISTENER_AUTH_POOL_TAG in (pool.tags or []))
