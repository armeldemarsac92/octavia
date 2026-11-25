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

from octavia.common import constants
from octavia.common import exceptions
from octavia.common import validate
from octavia.i18n import _


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
    return {'type': 'ExternalAuth',
            'http': validate.http_external_auth(request['http'])}


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
