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
            request.keys() not in ({'type', 'http'}, {'type', 'grpc'}) or
            request['type'] != 'ExternalAuth' or
            not isinstance(request.get('http', request.get('grpc')), dict)):
        raise exceptions.ValidationException(detail=_(
            'A listener ExternalAuth filter requires exactly one of http '
            'or grpc.'))
    if 'http' in request:
        return {'type': 'ExternalAuth',
                'http': validate.http_external_auth(request['http'])}
    grpc = request['grpc']
    if 'protocol' in grpc:
        raise exceptions.ValidationException(detail=_(
            'Listener gRPC ExternalAuth selects its protocol via grpc.'))
    grpc = validate.l7policy_external_auth({**grpc, 'protocol': 'GRPC'})
    del grpc['protocol']
    return {'type': 'ExternalAuth', 'grpc': grpc}


def authorizer(request):
    if 'grpc' in request:
        return {**request['grpc'], 'protocol': 'GRPC'}
    return request['http']


def authorizers(sections):
    return (authorizer(request) for section in sections or ()
            for request in section.get('requests', ()))


def pool_protocols(sections):
    result = {}
    for auth in authorizers(sections):
        result.setdefault(auth['pool_id'], set()).add(
            auth.get('protocol', constants.PROTOCOL_HTTP))
    return result


def pool_ids(sections):
    return set(pool_protocols(sections))


def transport_capabilities(auth, pool):
    required = set()
    if validate.is_grpc_external_auth(auth):
        required.add(constants.GATEWAY_CAPABILITY_LISTENER_GRPC_EXTERNAL_AUTH)
        required.add(constants.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN
                     if pool.tls_enabled else
                     constants.GATEWAY_CAPABILITY_BACKEND_H2C)
    elif not pool.tls_enabled:
        return required
    else:
        required.add(
            constants.GATEWAY_CAPABILITY_LISTENER_HTTP_EXTERNAL_AUTH_TLS)
    if pool.tls_enabled:
        required.add(constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME)
        if pool.backend_tls_system_ca:
            required.add(constants.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA)
        if pool.backend_tls_subject_alt_names:
            required.add(
                constants.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES)
    return required


def is_withdrawal(current, sections):
    """Match retained sections in order, allowing removal or local denial."""
    if not current or sections is None or sections == current:
        return False
    previous = iter(current)
    for section in sections:
        old = next((old for old in previous
                    if old['hostname'] == section['hostname']), None)
        if old is None or (old != section and not section.get('reject')):
            return False
    return True


def validate_listener(protocol, sections):
    if sections and protocol not in (constants.PROTOCOL_HTTP,
                                     constants.PROTOCOL_TERMINATED_HTTPS):
        raise exceptions.ValidationException(detail=_(
            'Listener request filters require an HTTP or TERMINATED_HTTPS '
            'listener.'))


def is_http_tls_authorizer(pool):
    return constants.GATEWAY_HTTP_AUTH_TLS_POOL_TAG in (
        getattr(pool, 'tags', None) or ())


def require_non_http_tls_authorizer(tags):
    if constants.GATEWAY_HTTP_AUTH_TLS_POOL_TAG in (tags or ()):
        raise exceptions.ValidationException(detail=_(
            'An HTTP TLS authorizer pool is reserved for ExternalAuth '
            'authorization.'))


def valid_pool(pool, protocol=constants.PROTOCOL_HTTP, *, tags=None,
               changes=None):
    """Check the authorizer role and transport, including a pending edit."""
    if pool.protocol != constants.PROTOCOL_HTTP:
        return False
    tags = set((pool.tags or ()) if tags is None else tags)
    changes = changes or {}

    def field(name):
        return changes[name] if name in changes else getattr(pool, name, None)

    grpc_tag = constants.GATEWAY_GRPC_AUTH_POOL_TAG
    http_tag = constants.GATEWAY_LISTENER_AUTH_POOL_TAG
    tls_enabled = field('tls_enabled')
    backend_h2c = field('backend_h2c')
    tls_tag = constants.GATEWAY_HTTP_AUTH_TLS_POOL_TAG
    collector_tag = constants.GATEWAY_OTLP_COLLECTOR_POOL_TAG
    if tls_tag in tags:
        if (protocol != constants.PROTOCOL_HTTP or
                tags.intersection({http_tag, grpc_tag, collector_tag})):
            return False
        ca_ref = bool(field('ca_tls_certificate_id'))
        system_ca = bool(field('backend_tls_system_ca'))
        alpn = field('alpn_protocols')
        return (tls_enabled is True and not backend_h2c and
                not field('backend_tls_require_h2') and
                validate.is_exact_sni_name(field('backend_tls_hostname')) and
                ca_ref != system_ca and
                (not system_ca or not field('crl_container_id')) and
                (not alpn or 'http/1.1' in alpn))
    if protocol == constants.PROTOCOL_HTTP:
        return (not tls_enabled and not backend_h2c and
                http_tag in tags and grpc_tag not in tags)
    if (protocol != 'GRPC' or grpc_tag not in tags or
            tags.intersection({http_tag,
                               constants.GATEWAY_OTLP_COLLECTOR_POOL_TAG})):
        return False
    require_h2 = field('backend_tls_require_h2')
    if backend_h2c:
        return not tls_enabled and not require_h2
    ca_ref = bool(field('ca_tls_certificate_id'))
    system_ca = bool(field('backend_tls_system_ca'))
    alpn = field('alpn_protocols')
    return (tls_enabled and require_h2 and
            validate.is_exact_sni_name(field('backend_tls_hostname')) and
            ca_ref != system_ca and (not alpn or 'h2' in alpn))
