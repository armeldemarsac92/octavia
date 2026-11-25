# Copyright 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2015 Rackspace
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
import contextlib
import functools
import hashlib
import json
import os
import ssl
import time
from typing import Optional
import uuid
import warnings

from cryptography import x509
from oslo_context import context as oslo_context
from oslo_log import log as logging
import requests
from stevedore import driver as stevedore_driver

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.amphorae.drivers import driver_base
from octavia.amphorae.drivers.haproxy import exceptions as exc
from octavia.amphorae.drivers.keepalived import vrrp_rest_driver
from octavia.common.config import cfg
from octavia.common import constants as consts
from octavia.common import exceptions
import octavia.common.jinja.haproxy.combined_listeners.jinja_cfg as jinja_combo
from octavia.common.jinja.lvs import jinja_cfg as jinja_udp_cfg
from octavia.common.tls_utils import cert_parser
from octavia.common import utils
from octavia.common import validate
from octavia.db import api as db_api
from octavia.db import models as db_models
from octavia.db import repositories as repo


LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class HaproxyAmphoraLoadBalancerDriver(
    driver_base.AmphoraLoadBalancerDriver,
        vrrp_rest_driver.KeepalivedAmphoraDriverMixin):

    def __init__(self):
        super().__init__()
        self.clients = {
            'base': AmphoraAPIClientBase(),
            '1.0': AmphoraAPIClient1_0(),
        }
        self.cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=CONF.certificates.cert_manager,
            invoke_on_load=True,
        ).driver

        self.jinja_combo = jinja_combo.JinjaTemplater(
            base_amp_path=CONF.haproxy_amphora.base_path,
            base_crt_dir=CONF.haproxy_amphora.base_cert_dir,
            haproxy_template=CONF.haproxy_amphora.haproxy_template,
            connection_logging=CONF.haproxy_amphora.connection_logging)
        self.lvs_jinja = jinja_udp_cfg.LvsJinjaTemplater()

    def _get_haproxy_versions(self, amphora, timeout_dict=None):
        """Get major and minor version number from haproxy

        Example: ['1', '6']

        :returns version_list: A list with the major and minor numbers
        """
        self._populate_amphora_api_version(
            amphora, timeout_dict=timeout_dict)
        amp_info = self.clients[amphora.api_version].get_info(
            amphora, timeout_dict=timeout_dict)
        haproxy_version_string = amp_info['haproxy_version']

        return haproxy_version_string.split('.')[:2]

    def _populate_amphora_api_version(self, amphora, timeout_dict=None,
                                      raise_retry_exception=False):
        """Populate the amphora object with the api_version

        This will query the amphora for version discovery and populate
        the api_version string attribute on the amphora object.

        :returns: None
        """
        if not getattr(amphora, 'api_version', None):
            try:
                amphora.api_version = self.clients['base'].get_api_version(
                    amphora, timeout_dict=timeout_dict,
                    raise_retry_exception=raise_retry_exception)['api_version']
            except exc.NotFound:
                # Amphora is too old for version discovery, default to 0.5
                amphora.api_version = '0.5'
        LOG.debug('Amphora %s has API version %s',
                  amphora.id, amphora.api_version)
        api_version = list(map(int, amphora.api_version.split('.')))

        if api_version[0] == 0 and api_version[1] <= 5:  # 0.5 or earlier
            raise driver_except.AmpVersionUnsupported(
                version=amphora.api_version)

        return api_version

    def check(self, amphora: db_models.Amphora,
              timeout_dict: Optional[dict] = None):
        """Check connectivity to the amphora."""
        self._populate_amphora_api_version(amphora, timeout_dict)

    def update_amphora_listeners(self, loadbalancer, amphora,
                                 timeout_dict=None, *,
                                 finalizing_failover=False):
        """Update the amphora with a new configuration.

        :param loadbalancer: The load balancer to update
        :type loadbalancer: object
        :param amphora: The amphora to update
        :type amphora: object
        :param timeout_dict: Dictionary of timeout values for calls to the
                             amphora. May contain: req_conn_timeout,
                             req_read_timeout, conn_max_retries,
                             conn_retry_interval
        :returns: None

        Updates the configuration of the listeners on a single amphora.
        """
        if amphora is None or amphora.status == consts.DELETED:
            if finalizing_failover:
                raise driver_except.ListenerProvisioningError()
            return

        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        with (
            self._otlp_render_results(loadbalancer) as tracing_options,
            self._observe_http_persistence(
                loadbalancer, target_id=amphora.id) as persistence_options,
            self._system_ca_render_results(
                loadbalancer, failover=finalizing_failover) as system_options
        ):
            if (opted_in or fallback or withdrawn or
                    utils.active_http_retry_backoff_policies(loadbalancer) or
                    utils.has_tls_sni_passthrough_weighted_policies(
                        loadbalancer, active=False) or
                    self._http_persistence_capabilities(loadbalancer)):
                peers = {amp.id: amp for amp in loadbalancer.amphorae
                         if amp.status != consts.DELETED}
                peers[amphora.id] = amphora
                targets = list(peers.values()) if system_options else [amphora]
                self._update_protected_tls_listeners(
                    loadbalancer, targets, peers.values(), protected,
                    fallback, withdrawn, timeout_dict=timeout_dict,
                    **({'require_http_retry_backoff': True,
                        'require_weighted_passthrough_topology': True}
                       if finalizing_failover else {}),
                    **tracing_options, **persistence_options,
                    **system_options)
            else:
                self._update_amphora_listeners(
                    loadbalancer, amphora, timeout_dict=timeout_dict,
                    **tracing_options, **persistence_options)

    @staticmethod
    def _otlp_render_targets(loadbalancer):
        targets = {}
        for listener in loadbalancer.listeners:
            if listener.provisioning_status in (
                    consts.PENDING_DELETE, consts.DELETED):
                continue
            tracing = getattr(listener, 'otlp_tracing', None)
            withdrawing = (
                tracing is None and
                getattr(listener, 'otlp_tracing_status', None) in (
                    consts.PENDING_UPDATE, consts.ERROR))
            if withdrawing or (loadbalancer.enabled and listener.enabled and
                               isinstance(tracing, dict)):
                targets[listener.id] = (
                    tracing, getattr(listener, 'otlp_tracing_revision', None))
        return targets

    @staticmethod
    def _haproxy_publication_acked(response, *, otlp_publication=None,
                                   config_publication=None):
        header = (consts.HAPROXY_CONFIG_PUBLICATION_HEADER
                  if config_publication else
                  consts.HAPROXY_OTLP_PUBLICATION_HEADER)
        publication = config_publication or otlp_publication
        return (publication is not None and
                getattr(response, 'status_code', None) == 202 and
                response.headers.get(header) == publication)

    @contextlib.contextmanager
    def _observe_http_persistence(self, loadbalancer, *, target_id=None):
        policies = {}
        header_policies = {}
        for pool in utils.active_listener_pools(loadbalancer):
            persistence = pool.session_persistence
            if (persistence is not None and persistence.type ==
                    consts.SESSION_PERSISTENCE_HTTP_HEADER):
                header_policies[pool.id] = (
                    persistence.header_name,
                    persistence.header_absolute_timeout_ms)
                continue
            timeout = getattr(persistence, 'cookie_absolute_timeout_ms', None)
            if type(timeout) is int or self._has_custom_cookie_path(pool):
                policies[pool.id] = (
                    persistence.cookie_name, timeout,
                    persistence.cookie_scope,
                    getattr(persistence, 'cookie_permanent', False) is True,
                    getattr(persistence, 'cookie_path', None))
        if not policies and not header_policies:
            yield {}
            return

        votes = {}
        completed = False
        try:
            yield {'http_persistence_observed': votes}
            completed = True
        finally:
            self._publish_http_persistence_results(
                loadbalancer, policies, header_policies, votes, completed,
                target_id)

    def _publish_http_persistence_results(
            self, loadbalancer, policies, header_policies, votes, completed,
            target_id):
        # An acknowledged degradation is observable even if a subsequent
        # peer fails. Recovery requires every member of the allocated topology.
        expected = set()
        if completed:
            try:
                expected = {amp.id for amp in
                            self._allocated_amphorae(loadbalancer)}
            except driver_except.ListenerProvisioningError:
                pass
        allocated = {amp.id for amp in loadbalancer.amphorae
                     if amp.status == consts.AMPHORA_ALLOCATED}
        all_policies = policies.keys() | header_policies.keys()
        failed = {pool_id for pool_id in all_policies
                  if any(votes.get(amp_id, {}).get(pool_id) == consts.ERROR
                         for amp_id in allocated)}
        recovered = {
            pool_id for pool_id in all_policies - failed
            if expected and all(votes.get(amp_id, {}).get(pool_id) ==
                                consts.ACTIVE for amp_id in expected)}
        # A full render needs a vote from every peer for these policies.
        # A single-peer maintenance render preflights the entire topology
        # but can only confirm its own reload and cannot recover both peers.
        requested = {target_id} if target_id else expected
        coordinated = header_policies.keys() | {
            pool_id for pool_id, policy in policies.items()
            if policy[-1] not in (None, consts.HTTP_COOKIE_DEFAULT_PATH)}
        failed.update(
            pool_id for pool_id in coordinated
            if (not completed or not requested or
                any(votes.get(amp_id, {}).get(pool_id) != consts.ACTIVE
                    for amp_id in requested)))
        recovered -= failed
        if failed or recovered:
            with db_api.session().begin() as session:
                pool_repo = repo.PoolRepository()
                if (failed | recovered) & policies.keys():
                    pool_repo.set_http_cookie_pool_statuses(
                        session, policies, failed=failed & policies.keys(),
                        recovered=recovered & policies.keys())
                if (failed | recovered) & header_policies.keys():
                    pool_repo.set_http_header_pool_statuses(
                        session, header_policies,
                        failed=failed & header_policies.keys(),
                        recovered=recovered & header_policies.keys())

    @contextlib.contextmanager
    def _otlp_render_results(self, loadbalancer):
        listeners = self._otlp_render_targets(loadbalancer)
        if not listeners:
            yield {}
            return
        results = {}
        expected = {amp.id: amp.role for amp in loadbalancer.amphorae
                    if amp.status != consts.DELETED}
        roles = {
            consts.TOPOLOGY_SINGLE: {consts.ROLE_STANDALONE},
            consts.TOPOLOGY_ACTIVE_STANDBY: {
                consts.ROLE_MASTER, consts.ROLE_BACKUP},
        }.get(loadbalancer.topology)
        valid_peers = (roles and len(expected) == len(roles) and
                       set(expected.values()) == roles)
        try:
            yield {'otlp_observed': results}
        finally:
            statuses = {}
            for listener_id, (tracing, revision) in listeners.items():
                applied = valid_peers and all(
                    results.get(amp, {}).get(listener_id) == consts.ACTIVE
                    for amp in expected)
                statuses[listener_id] = (
                    tracing, revision,
                    consts.ACTIVE if applied else consts.ERROR)
            listener_repo = repo.ListenerRepository()
            with db_api.session().begin() as session:
                listener_repo.set_otlp_tracing_statuses(
                    session, statuses, topology=(
                        loadbalancer.id, loadbalancer.topology, expected,
                        loadbalancer.enabled))

    @contextlib.contextmanager
    def _system_ca_render_results(self, loadbalancer, *, failover=False):
        pools = utils.backend_tls_system_ca_pool_ids(loadbalancer)
        if not pools:
            yield {}
            return

        expected = {amp.id: amp.role for amp in loadbalancer.amphorae
                    if amp.status != consts.DELETED}
        topology = (loadbalancer.id, loadbalancer.topology, expected)
        results = {}
        completed = False
        if failover:
            with db_api.session().begin() as session:
                repo.PoolRepository().set_backend_tls_system_ca_digests(
                    session, topology, dict.fromkeys(pools))
        try:
            yield {'system_ca_observed': results}
            completed = True
        finally:
            digests = dict.fromkeys(pools)
            try:
                peers = self._allocated_amphorae(loadbalancer)
            except driver_except.ListenerProvisioningError:
                peers = []
            if completed and peers and set(expected) == {
                    amp.id for amp in peers}:
                profile = validate.backend_tls_system_ca_profile(
                    loadbalancer.provider)
                if profile:
                    digest = profile[1]
                    for pool_id in pools:
                        if all(results.get(amp.id, {}).get(pool_id) == digest
                               for amp in peers):
                            digests[pool_id] = digest
            with db_api.session().begin() as session:
                repo.PoolRepository().set_backend_tls_system_ca_digests(
                    session, topology, digests)

    def _update_amphora_listeners(
            self, loadbalancer, amphora, timeout_dict=None, *,
            amp_details=None, backend_tls_certs=None,
            frontend_tls_certs=None, closed_frontend=(),
            l7policy_activation=False, otlp_observed=None,
            tcp_batch_configs=None, http_persistence_observed=None,
            http_retry_backoff_observed=None, required_backoff_policies=(),
            verify_publication=False, weighted_passthrough_degraded=False,
            system_ca_observed=None, read_http_header_key=None,
            tcp_only=False):
        if not loadbalancer.listeners:
            LOG.debug('No listeners found to update.')
            return set()

        # Check which HAProxy version is on the amp
        haproxy_versions = self._get_haproxy_versions(
            amphora, timeout_dict=timeout_dict)
        # Check if version is supported
        self._populate_amphora_api_version(amphora)

        has_tcp = False
        otlp_tls_certs = {}
        tracing_targets = self._otlp_render_targets(loadbalancer)
        tracing_results = {}
        system_ca_pools = utils.backend_tls_system_ca_pool_ids(loadbalancer)
        tracing_system_pools = {}
        certs = dict(backend_tls_certs or {})
        frontend_tls_certs = frontend_tls_certs or {}
        listeners_to_update = []
        for listener in loadbalancer.listeners:
            LOG.debug("%s updating listener %s on amphora %s",
                      self.__class__.__name__, listener.id, amphora.id)
            if listener.protocol in consts.LVS_PROTOCOLS:
                if (l7policy_activation or tcp_only or
                        tcp_batch_configs is not None):
                    continue
                self._update_udp_amphora(
                    listener, amphora, timeout_dict=timeout_dict)
            else:
                has_tcp = True
                obj_id = loadbalancer.id
                client_auth_fallback = getattr(
                    listener, 'client_authentication_insecure_fallback',
                    None) is True
                if client_auth_fallback and (
                        listener.id in closed_frontend or
                        listener.provisioning_status in
                        (consts.PENDING_DELETE, consts.DELETED) or
                        not (listener.enabled and loadbalancer.enabled)):
                    continue
                tcp_tls_termination = getattr(listener, 'tcp_tls_termination',
                                              False) is True
                if (tcp_tls_termination and
                        not (listener.enabled and loadbalancer.enabled)):
                    # A disabled endpoint must close even if its certificate
                    # has been withdrawn from the certificate manager.
                    listeners_to_update.append(listener)
                    continue

                if listener.id in tracing_targets:
                    tracing, _ = tracing_targets[listener.id]
                    tracing_status = consts.ACTIVE
                    if tracing is not None:
                        if amp_details is None:
                            client = self.clients[amphora.api_version]
                            amp_details = client.get_details(
                                amphora, timeout_dict=timeout_dict) or {}
                        can_trace = jinja_combo.otlp_tracing_supported(
                            loadbalancer, tracing, amp_details)
                        if can_trace:
                            pool_id = tracing['collector_pool_id']
                            system_ca = pool_id in system_ca_pools
                            if system_ca:
                                # Protected pools share the material staged
                                # for all Amphora peers, including mTLS.
                                material = (backend_tls_certs or {}).get(
                                    pool_id, {})
                                otlp_tls_certs[pool_id] = (
                                    material if material.get(
                                        'system_ca_sha256') else
                                    {'closed': True})
                                tracing_system_pools[listener.id] = pool_id
                            elif pool_id not in otlp_tls_certs:
                                otlp_tls_certs[pool_id] = (
                                    self._process_otlp_collector_certs(
                                        listener, loadbalancer, amphora,
                                        pool_id))
                            can_trace = not otlp_tls_certs[pool_id].get(
                                'closed')
                            if (tcp_batch_configs is not None and
                                    not can_trace and not system_ca):
                                raise driver_except.ListenerProvisioningError()
                        if not can_trace:
                            tracing_status = consts.ERROR
                    tracing_results[listener.id] = tracing_status
                try:
                    if client_auth_fallback:
                        certs.update(frontend_tls_certs[listener.id])
                    else:
                        certs.update(self._process_listener_tls_certs(
                            listener, amphora, obj_id))

                    certs.update(self._process_listener_pool_certs(
                        listener, amphora, obj_id))

                    listeners_to_update.append(listener)
                except Exception as e:
                    if (l7policy_activation or required_backoff_policies or
                            tcp_batch_configs is not None or
                            verify_publication):
                        raise
                    LOG.exception('Unable to update listener %s due to '
                                  '"%s". Skipping this listener.',
                                  listener.id, str(e))
                    listener_repo = repo.ListenerRepository()
                    with db_api.session().begin() as session:
                        listener_repo.update(session, listener.id,
                                             provisioning_status=consts.ERROR,
                                             operating_status=consts.ERROR)

        if has_tcp:
            if listeners_to_update:
                # Generate HaProxy configuration from listener object
                if amp_details is None:
                    client = self.clients[amphora.api_version]
                    amp_details = client.get_details(amphora)
                tracing_options = {}
                if otlp_tls_certs:
                    tracing_options['otlp_tls_certs'] = otlp_tls_certs
                otlp_system_ca_applied = set()
                if tracing_system_pools:
                    tracing_options['otlp_system_ca_applied'] = (
                        otlp_system_ca_applied)
                headers_requested = {
                    listener_id for listener_id, (profile, _) in
                    tracing_targets.items() if profile and profile.get(
                        'headers')
                }
                otlp_headers_applied = set()
                if headers_requested:
                    tracing_options['otlp_headers_applied'] = (
                        otlp_headers_applied)
                configured = {listener.id for listener in listeners_to_update}
                tracing_results = {
                    listener_id: tracing_results[listener_id]
                    for listener_id in configured & tracing_results.keys()}
                system_ca_results = (
                    {} if system_ca_observed is not None else None)
                system_ca_capability = (
                    consts.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA)
                publication_options = {}
                if (system_ca_results is not None and
                        (amp_details or {}).get(system_ca_capability) is True):
                    publication_options['config_publication'] = (
                        uuid.uuid4().hex)
                elif (tracing_results or verify_publication or
                      system_ca_results is not None):
                    publication_options['otlp_publication'] = uuid.uuid4().hex
                system_ca_options = (
                    {'system_ca_results': system_ca_results}
                    if system_ca_results is not None else {})
                persistence_results = {}
                persistence_options = (
                    {'http_persistence_results': persistence_results}
                    if http_persistence_observed is not None else {})
                backoff_results = {}
                backoff_options = (
                    {'http_retry_backoff_results': backoff_results}
                    if http_retry_backoff_observed is not None else {})
                config = self.jinja_combo.build_config(
                    host_amphora=amphora, listeners=listeners_to_update,
                    tls_certs=certs,
                    haproxy_versions=haproxy_versions,
                    amp_details=amp_details, **tracing_options,
                    **persistence_options, **publication_options,
                    **backoff_options, **system_ca_options,
                    **({'read_http_header_key': read_http_header_key}
                       if read_http_header_key is not None else {}),
                    **({'weighted_passthrough_degraded': True}
                       if weighted_passthrough_degraded else {}))
                for listener_id in (tracing_results.keys() &
                                    headers_requested - otlp_headers_applied):
                    tracing_results[listener_id] = consts.ERROR
                for listener_id, pool_id in tracing_system_pools.items():
                    if listener_id not in configured:
                        continue
                    if listener_id not in otlp_system_ca_applied:
                        tracing_results[listener_id] = consts.ERROR
                    elif system_ca_results is not None:
                        system_ca_results[pool_id] = (
                            otlp_tls_certs[pool_id]['system_ca_sha256'])
                if system_ca_results is not None:
                    self._record_staged_otlp_system_ca(
                        loadbalancer, listeners_to_update, tracing_targets,
                        backend_tls_certs or {}, amp_details,
                        system_ca_results)
                if any(backoff_results.get(policy_id) == consts.ERROR
                       for policy_id in required_backoff_policies):
                    http_retry_backoff_observed[amphora.id] = backoff_results
                    raise driver_except.HttpRetryBackoffUnsupported()
                if tcp_batch_configs is not None:
                    tcp_batch_configs.append((
                        amphora, config, persistence_results, tracing_results,
                        publication_options, backoff_results,
                        system_ca_results))
                    return configured
                self.clients[amphora.api_version].upload_config(
                    amphora, loadbalancer.id, config,
                    timeout_dict=timeout_dict)
                response = self.clients[amphora.api_version].reload_listener(
                    amphora, loadbalancer.id, timeout_dict=timeout_dict,
                    **publication_options)
                acknowledged = self._haproxy_publication_acked(
                    response, **publication_options)
                if not acknowledged and (
                        system_ca_results is not None or verify_publication):
                    raise driver_except.ListenerProvisioningError()
                if http_persistence_observed is not None:
                    http_persistence_observed[amphora.id] = persistence_results
                if http_retry_backoff_observed is not None:
                    http_retry_backoff_observed[amphora.id] = backoff_results
                if otlp_observed is not None and acknowledged:
                    otlp_observed[amphora.id] = tracing_results
                if system_ca_observed is not None and acknowledged:
                    system_ca_observed[amphora.id] = system_ca_results
            elif tcp_batch_configs is None:
                # If we aren't updating any listeners, make sure there are
                # no listeners hanging around. For example if this update
                # was called from a listener delete.
                self.clients[amphora.api_version].delete_listener(
                    amphora, loadbalancer.id)

        return {listener.id for listener in listeners_to_update}

    @staticmethod
    def _has_udp_guard(listener):
        return (listener.protocol == consts.PROTOCOL_UDP and
                getattr(listener.default_pool, 'udp_packet_drop', None)
                is not None)

    def _udp_guard_config(self, listener):
        if not self._has_udp_guard(listener):
            return None
        pool = listener.default_pool
        fraction = pool.udp_packet_drop
        retiring = pool.provisioning_status in jinja_udp_cfg.REMOVED

        lb = listener.load_balancer
        if (lb.additional_vips or utils.ip_version(lb.vip.ip_address) != 4 or
                pool.protocol != consts.PROTOCOL_UDP or
                pool.lb_algorithm != consts.LB_ALGORITHM_ROUND_ROBIN or
                pool.health_monitor or pool.session_persistence):
            raise driver_except.ListenerProvisioningError()

        listener_active = (not retiring and lb.enabled and listener.enabled and
                           listener.provisioning_status not in
                           jinja_udp_cfg.REMOVED)
        destinations = []
        if listener_active and pool.enabled:
            for member in pool.members:
                if (member.enabled and member.provisioning_status not in
                        jinja_udp_cfg.REMOVED):
                    destinations.append({
                        'address': member.ip_address,
                        'port': member.protocol_port,
                        'weight': member.weight,
                    })
        return {'vip': lb.vip.ip_address, 'port': listener.protocol_port,
                'fraction': fraction, 'has_service': bool(destinations),
                'destinations': destinations, 'retiring': retiring}

    def _check_udp_guard(self, amphora, timeout_dict=None):
        try:
            self.clients[amphora.api_version].check_udp_guard(
                amphora, timeout_dict=timeout_dict)
        except exc.NotFound as error:
            raise driver_except.AmpDriverNotImplementedError() from error

    def _update_udp_amphora(self, listener, amphora, timeout_dict=None, *,
                            delete=False):
        guard = self._udp_guard_config(listener)
        client = self.clients[amphora.api_version]
        if delete:
            # Stage the closed VIP/port even when a prior DELETE already
            # removed the files. A fresh kernel proof is required on retry.
            guard.update(has_service=False, destinations=[], retiring=True)
            config = f'net_namespace {consts.AMPHORA_NAMESPACE}\n'
        else:
            config = self.lvs_jinja.build_config(listener=listener)
        if guard is None:
            client.upload_udp_config(amphora, listener.id, config,
                                     timeout_dict=timeout_dict)
            client.reload_listener(amphora, listener.id,
                                   timeout_dict=timeout_dict)
            return

        try:
            self._check_udp_guard(amphora, timeout_dict)
        except driver_except.AmpDriverNotImplementedError:
            if guard['retiring']:
                client.close_legacy_udp_listener(amphora, listener.id,
                                                 timeout_dict=timeout_dict)
                LOG.error('Amphora %(amphora)s no longer reports UDP '
                          'listener %(listener)s. Use a guard-capable image '
                          'to verify IPVS and nftables withdrawal.',
                          {'amphora': amphora.id, 'listener': listener.id})
            # A downgraded agent can hide residual IPVS/nftables state.
            raise
        client.stage_udp_guard(amphora, listener.id, config, guard,
                               timeout_dict=timeout_dict)
        if delete:
            client.delete_guarded_udp_listener(amphora, listener.id)
        else:
            client.activate_udp_guard(amphora, listener.id,
                                      timeout_dict=timeout_dict)

    @staticmethod
    def _allocated_amphorae(loadbalancer):
        amphorae = [amp for amp in loadbalancer.amphorae
                    if amp.status == consts.AMPHORA_ALLOCATED]
        if (not utils.amphora_roles_match_topology(
                loadbalancer.topology, [amp.role for amp in amphorae]) or
                len({amp.id for amp in amphorae}) != len(amphorae)):
            raise driver_except.ListenerProvisioningError()
        return amphorae

    def apply_udp_member_batch(self, loadbalancer, listener_id):
        listener = next((listener for listener in loadbalancer.listeners
                         if listener.id == listener_id), None)
        if listener is None:
            raise driver_except.ListenerProvisioningError()
        guard = self._udp_guard_config(listener)
        if guard is None or guard['retiring']:
            raise driver_except.ListenerProvisioningError()

        # Ordinary member updates need the complete allocated topology.
        # Replacement Amphorae use the single-peer failover render method.
        amphorae = self._allocated_amphorae(loadbalancer)
        config = self.lvs_jinja.build_config(listener=listener)
        for amphora in amphorae:
            self._populate_amphora_api_version(amphora)
            self._check_udp_guard(amphora)
        for amphora in amphorae:
            self.clients[amphora.api_version].stage_udp_guard(
                amphora, listener.id, config, guard)
        for amphora in amphorae:
            self.clients[amphora.api_version].activate_udp_guard(
                amphora, listener.id)
        # The worker compares this receipt against the current LB roster.
        return tuple(sorted((amp.id, amp.role) for amp in amphorae))

    def update_udp_pool_listeners(self, loadbalancer, listener_ids):
        if not listener_ids:
            return ()
        listeners = {
            listener.id: listener for listener in loadbalancer.listeners
            if listener.protocol == consts.PROTOCOL_UDP
        }
        if not set(listener_ids) <= listeners.keys():
            raise driver_except.ListenerProvisioningError()
        return self._update_scoped_udp_listeners(
            loadbalancer, [listeners[listener_id] for listener_id in
                           listener_ids])

    def _update_scoped_udp_listeners(self, loadbalancer, listeners, *,
                                     delete=False):
        if any(self._has_udp_guard(listener) for listener in listeners):
            amphorae = self._allocated_amphorae(loadbalancer)
        else:
            amphorae = [amp for amp in loadbalancer.amphorae
                        if amp.status != consts.DELETED]
        errors = []
        for amphora in amphorae:
            try:
                self._populate_amphora_api_version(amphora)
                for listener in listeners:
                    self._update_udp_amphora(listener, amphora, delete=delete)
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]
        return tuple(sorted((amp.id, amp.role) for amp in amphorae
                            if amp.status == consts.AMPHORA_ALLOCATED))

    def update(self, loadbalancer, *, l7policy_activation=False,
               l7policy_restoration=False, tcp_member_batch=False):
        amphorae = [amphora for amphora in loadbalancer.amphorae
                    if amphora.status != consts.DELETED]
        if tcp_member_batch and not any(
                listener.protocol not in consts.LVS_PROTOCOLS
                for listener in loadbalancer.listeners):
            return
        backoff_policies = utils.active_http_retry_backoff_policies(
            loadbalancer)
        weighted_passthrough = utils.has_tls_sni_passthrough_weighted_policies(
            loadbalancer, active=False)
        if (not amphorae and
                (l7policy_activation or tcp_member_batch or backoff_policies or
                 weighted_passthrough)):
            raise driver_except.ListenerProvisioningError()
        tcp_batch_configs = [] if tcp_member_batch else None
        batch_options = (
            {'tcp_batch_configs': tcp_batch_configs}
            if tcp_member_batch else {})
        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        with (
            self._otlp_render_results(loadbalancer) as tracing_options,
            self._observe_http_persistence(
                loadbalancer) as persistence_options,
            self._system_ca_render_results(loadbalancer) as system_options
        ):
            if (amphorae and
                    (opted_in or fallback or withdrawn or
                     backoff_policies or weighted_passthrough or
                     self._http_persistence_capabilities(loadbalancer))):
                return self._update_protected_tls_listeners(
                    loadbalancer, amphorae, amphorae, protected, fallback,
                    withdrawn, l7policy_activation=l7policy_activation,
                    l7policy_restoration=l7policy_restoration,
                    **({'require_weighted_passthrough_topology': True}
                       if weighted_passthrough else {}),
                    **tracing_options, **batch_options, **persistence_options,
                    **system_options)
            for amphora in amphorae:
                self._update_amphora_listeners(
                    loadbalancer, amphora,
                    l7policy_activation=l7policy_activation,
                    **tracing_options, **batch_options, **persistence_options,
                    **system_options)
            if tcp_member_batch:
                self._reload_tcp_batch_configs(
                    loadbalancer, tcp_batch_configs, backoff_policies,
                    persistence_options.get('http_persistence_observed'),
                    tracing_options.get('otlp_observed'),
                    system_options.get('system_ca_observed'))

    def _reload_tcp_batch_configs(self, loadbalancer, configs,
                                  backoff_policies, persistence_votes,
                                  tracing_votes, system_ca_votes, *,
                                  closing=False, verify_publication=False):
        # Ordinarily every peer must validate the batch before a reload.
        # When closing protected pools, apply the withdrawal wherever
        # publication is possible and report every failed batch as failed.
        uploaded = []
        errors = []
        for entry in configs:
            amphora, config, *_ = entry
            try:
                self.clients[amphora.api_version].upload_config(
                    amphora, loadbalancer.id, config)
            except Exception as error:
                if not closing:
                    raise
                errors.append(error)
            else:
                uploaded.append(entry)
        backoff_votes = {}
        verify_publication = (verify_publication or
                              utils.has_tls_sni_passthrough_weighted_policies(
                                  loadbalancer))
        completed = False
        try:
            for (amphora, _, persistence_results, tracing_results,
                 publication_options, backoff_results,
                 system_ca_results) in uploaded:
                client = self.clients[amphora.api_version]
                try:
                    response = client.reload_listener(
                        amphora, loadbalancer.id, **publication_options)
                    acknowledged = self._haproxy_publication_acked(
                        response, **publication_options)
                    if not acknowledged and (
                            system_ca_results is not None or
                            verify_publication):
                        raise driver_except.ListenerProvisioningError()
                except Exception as error:
                    if not closing:
                        raise
                    errors.append(error)
                    continue
                if persistence_votes is not None:
                    persistence_votes[amphora.id] = persistence_results
                backoff_votes[amphora.id] = backoff_results
                if tracing_votes is not None and acknowledged:
                    tracing_votes[amphora.id] = tracing_results
                if system_ca_votes is not None and acknowledged:
                    system_ca_votes[amphora.id] = system_ca_results
            if errors:
                raise errors[0]
            completed = True
        finally:
            if backoff_policies:
                self._publish_http_retry_backoff_results(
                    loadbalancer, backoff_policies, backoff_votes,
                    completed=completed)

    def update_failover_listeners(self, loadbalancer, amphora_index,
                                  amphorae_status, timeout_dict=None):
        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        # A paired exporter needs confirmations from the same graph snapshot.
        tracing_pair = (
            loadbalancer.topology == consts.TOPOLOGY_ACTIVE_STANDBY and
            bool(self._otlp_render_targets(loadbalancer)))
        retry_backoff = bool(utils.active_http_retry_backoff_policies(
            loadbalancer))
        weighted_passthrough = utils.has_tls_sni_passthrough_weighted_policies(
            loadbalancer, active=False)
        coordinated = (opted_in or bool(fallback or withdrawn) or
                       tracing_pair or retry_backoff or weighted_passthrough or
                       self._http_persistence_capabilities(loadbalancer))
        if coordinated and amphora_index == 0:
            system_ca = bool(utils.backend_tls_system_ca_pool_ids(
                loadbalancer))
            peers = [amp for amp in loadbalancer.amphorae
                     if amp.status != consts.DELETED]
            unreachable = {
                amp.id for amp in peers
                if (amphorae_status.get(amp.id, {}).get(consts.UNREACHABLE) or
                    (amp.id not in amphorae_status and
                     (tracing_pair or retry_backoff or weighted_passthrough or
                      system_ca)))
            }
            with (
                self._otlp_render_results(loadbalancer) as tracing_options,
                self._observe_http_persistence(
                    loadbalancer) as persistence_options,
                self._system_ca_render_results(
                    loadbalancer, failover=True) as system_options
            ):
                self._update_protected_tls_listeners(
                    loadbalancer, [amp for amp in peers
                                   if amp.id not in unreachable],
                    peers, protected, fallback, withdrawn,
                    timeout_dict=timeout_dict,
                    unreachable=unreachable, coordinating_failover=True,
                    **({'require_http_retry_backoff': True}
                       if retry_backoff else {}),
                    **({'require_weighted_passthrough_topology': True}
                       if weighted_passthrough else {}),
                    **tracing_options, **persistence_options,
                    **system_options)
        return coordinated

    @staticmethod
    def _has_custom_cookie_path(pool):
        persistence = pool.session_persistence
        return (pool.protocol == consts.PROTOCOL_HTTP and
                persistence is not None and
                persistence.type == consts.SESSION_PERSISTENCE_HTTP_COOKIE and
                getattr(persistence, 'cookie_path', None) not in
                (None, consts.HTTP_COOKIE_DEFAULT_PATH))

    def _http_persistence_capabilities(self, loadbalancer):
        capabilities = set()
        header = consts.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        for pool in utils.active_listener_pools(loadbalancer):
            if self._has_custom_cookie_path(pool):
                capabilities.add(consts.GATEWAY_CAPABILITY_HTTP_COOKIE_PATH)
            if (pool.session_persistence and pool.session_persistence.type ==
                    consts.SESSION_PERSISTENCE_HTTP_HEADER):
                capabilities.add(header)
        return capabilities

    @staticmethod
    def _is_otlp_collector_listener(listener):
        return (listener.enabled and
                listener.protocol in (consts.PROTOCOL_HTTP,
                                      consts.PROTOCOL_TERMINATED_HTTPS) and
                listener.provisioning_status not in
                (consts.PENDING_DELETE, consts.DELETED))

    @staticmethod
    def _is_managed_otlp_collector_pool(pool):
        return (pool.protocol == consts.PROTOCOL_HTTP and
                consts.GATEWAY_OTLP_COLLECTOR_POOL_TAG in (pool.tags or ()))

    @classmethod
    def _backend_tls_pools(cls, loadbalancer):
        system_ca = bool(utils.backend_tls_system_ca_pool_ids(loadbalancer))
        opted_in = system_ca
        pools = {}
        collector_frontend = None
        collector_listeners = {}
        for listener in loadbalancer.listeners:
            if listener.protocol in consts.LVS_PROTOCOLS:
                continue
            for pool in listener.pools:
                if (not utils.is_protected_backend_tls_pool(pool) and
                        not utils.is_disabled_backend_tls_pool(pool)):
                    continue
                opted_in = True
                if (loadbalancer.enabled and listener.enabled and
                        pool.enabled and pool.provisioning_status not in
                        (consts.PENDING_DELETE, consts.DELETED)):
                    pools[pool.id] = (listener, pool)
            if system_ca and cls._is_otlp_collector_listener(listener):
                collector_frontend = collector_frontend or listener
                tracing = getattr(listener, 'otlp_tracing', None)
                if isinstance(tracing, dict):
                    collector_listeners[tracing.get(
                        'collector_pool_id')] = listener
        if collector_frontend is not None and loadbalancer.enabled:
            for pool in loadbalancer.pools:
                if (getattr(pool, 'backend_tls_system_ca', False) is True and
                        pool.enabled and pool.provisioning_status not in
                        (consts.PENDING_DELETE, consts.DELETED) and
                        (pool.id in collector_listeners or
                         cls._is_managed_otlp_collector_pool(pool))):
                    pools.setdefault(pool.id, (
                        collector_listeners.get(pool.id, collector_frontend),
                        pool))
        return opted_in, pools

    @classmethod
    def _record_staged_otlp_system_ca(
            cls, loadbalancer, listeners, tracing_targets, certs, amp_details,
            results):
        if (not loadbalancer.enabled or
                (amp_details or {}).get(
                    consts.GATEWAY_CAPABILITY_LISTENER_OTLP_TRACING)
                is not True or
                not any(cls._is_otlp_collector_listener(listener)
                        for listener in listeners)):
            return
        attached = {profile.get('collector_pool_id')
                    for profile, _ in tracing_targets.values()
                    if profile is not None}
        for pool in loadbalancer.pools:
            digest = certs.get(pool.id, {}).get('system_ca_sha256')
            if (not digest or pool.id in attached or
                    not cls._is_managed_otlp_collector_pool(pool)):
                continue
            try:
                validate.validate_otlp_collector_transport(
                    pool.protocol, pool.backend_h2c,
                    pool.backend_tls_require_h2, pool.tls_enabled,
                    pool.alpn_protocols)
            except exceptions.ValidationException:
                continue
            # The detached pool has no route to any member. Record the exact
            # bundle staged on this peer only after the HAProxy reload is
            # acknowledged by the caller.
            results[pool.id] = digest

    @staticmethod
    def _frontend_fallback_listeners(loadbalancer):
        fallback = []
        withdrawn = set()
        for listener in loadbalancer.listeners:
            if listener.provisioning_status in (
                    consts.PENDING_DELETE, consts.DELETED):
                continue
            ownership = getattr(listener, 'frontend_fallback_owns_error', None)
            if ownership is True or ownership is False:
                withdrawn.add(listener.id)
            if (loadbalancer.enabled and listener.enabled and
                    getattr(listener, 'client_authentication_insecure_fallback',
                            None) is True):
                fallback.append(listener)
        return fallback, withdrawn

    def _update_protected_tls_listeners(
            self, loadbalancer, amphorae, peers, protected, fallback,
            withdrawn, timeout_dict=None, unreachable=(),
            l7policy_activation=False,
            coordinating_failover=False, l7policy_restoration=False,
            otlp_observed=None, tcp_batch_configs=None,
            http_persistence_observed=None,
            require_http_retry_backoff=False,
            require_weighted_passthrough_topology=False,
            system_ca_observed=None):
        # Preflight the pair before staging material or reloading either peer.
        probe_targets = {
            amp.id: amp for amp in (peers if protected or fallback
                                    else amphorae)}
        persistence_capabilities = (
            self._http_persistence_capabilities(loadbalancer))
        header_capability = consts.GATEWAY_CAPABILITY_HTTP_HEADER_PERSISTENCE
        verify_header_publication = (
            header_capability in persistence_capabilities)
        if verify_header_publication and not amphorae:
            error = driver_except.ListenerProvisioningError()
            if coordinating_failover and unreachable:
                raise driver_except.CoordinatedListenerUpdateError(
                    dict.fromkeys(unreachable, error))
            raise error
        requested_amp_ids = {amp.id for amp in amphorae}
        closure_peers = {amp.id: amp for amp in amphorae}
        if verify_header_publication:
            closure_peers.update(
                (amp.id, amp) for amp in peers
                if amp.status == consts.AMPHORA_ALLOCATED and
                amp.id not in closure_peers and amp.id not in unreachable)
            probe_targets.update(closure_peers)
        backoff_policies = utils.active_http_retry_backoff_policies(
            loadbalancer)
        topology_peers = {}
        complete_topology = False
        weighted_present = utils.has_tls_sni_passthrough_weighted_policies(
            loadbalancer, active=False)
        if persistence_capabilities or backoff_policies or weighted_present:
            topology_peers = {amp.id: amp for amp in amphorae}
            try:
                topology_peers.update(
                    (amp.id, amp) for amp in
                    self._allocated_amphorae(loadbalancer))
                complete_topology = True
            except driver_except.ListenerProvisioningError:
                LOG.warning('Could not confirm the Amphora topology for '
                            'enabled policy features on load balancer %s.',
                            loadbalancer.id)
            probe_targets.update(topology_peers)
        details = {}
        probe_failures = set(unreachable)
        for amphora in probe_targets.values():
            if amphora.id in unreachable:
                details[amphora.id] = {}
                continue
            try:
                self._populate_amphora_api_version(amphora, timeout_dict)
                client = self.clients[amphora.api_version]
                detail = client.get_details(amphora, timeout_dict=timeout_dict)
                details[amphora.id] = (
                    dict(detail) if isinstance(detail, dict) else {})
            except (driver_except.AmphoraDriverError, exc.APIException,
                    requests.RequestException, ValueError):
                probe_failures.add(amphora.id)
                details[amphora.id] = {}

        read_http_header_key = None
        closing_header = False
        for capability in sorted(persistence_capabilities):
            unsupported = [amp_id for amp_id in topology_peers
                           if details[amp_id].get(capability) is not True]
            if unsupported:
                LOG.warning('Could not confirm %s support on amphorae %s for '
                            'load balancer %s.', capability, unsupported,
                            loadbalancer.id)
            supported = complete_topology and not unsupported
            if capability == header_capability:
                if supported:
                    # Use the same key snapshot for every render in the pair.
                    read_http_header_key = functools.cache(
                        jinja_combo._read_http_cookie_signing_key)
                    supported = read_http_header_key() is not None
                closing_header = not supported
            for detail in details.values():
                detail[capability] = supported
        if closing_header:
            amphorae = list(closure_peers.values())

        weighted_capability = (
            consts.GATEWAY_CAPABILITY_TLS_SNI_PASSTHROUGH_WEIGHTED_POOLS)
        weighted_errors = {}
        weighted_topology_missing = (
            weighted_present and require_weighted_passthrough_topology and
            not complete_topology)
        if weighted_present:
            weighted_errors = {
                amp_id: driver_except.ListenerProvisioningError()
                for amp_id in probe_targets
                if details[amp_id].get(weighted_capability) is not True}
        weighted_partial = bool(weighted_errors) or weighted_topology_missing
        if weighted_partial:
            LOG.warning('Could not qualify weighted TLS SNI passthrough for '
                        'load balancer %s. Publishing available withdrawals. '
                        'Unqualified Amphorae: %s.',
                        loadbalancer.id, sorted(weighted_errors))

        backoff_votes = {}
        required_backoff_policies = set()
        if backoff_policies:
            capability = consts.GATEWAY_CAPABILITY_HTTP_RETRY_BACKOFF
            base_policy = consts.GATEWAY_CAPABILITY_HTTP_REQUEST_POLICY
            unsupported = {
                amp_id for amp_id in topology_peers
                if (details[amp_id].get(capability) is not True or
                    details[amp_id].get(base_policy) is not True)}
            supported = complete_topology and not unsupported
            for detail in details.values():
                detail[capability] = supported
            if require_http_retry_backoff:
                required_backoff_policies = set(backoff_policies)
            elif l7policy_activation and not l7policy_restoration:
                required_backoff_policies = {
                    policy.id for policy in backoff_policies.values()
                    if policy.provisioning_status == consts.PENDING_UPDATE}
            if weighted_partial:
                # A weighted withdrawal still needs to reach the live peer.
                required_backoff_policies = set()
            elif require_http_retry_backoff and (
                    not supported or unreachable or not amphorae):
                self._publish_http_retry_backoff_results(
                    loadbalancer, backoff_policies, backoff_votes,
                    completed=False, failed=set(backoff_policies))
                error = driver_except.HttpRetryBackoffUnsupported()
                failed_peers = unsupported | set(unreachable)
                if coordinating_failover and failed_peers:
                    raise driver_except.CoordinatedListenerUpdateError(
                        dict.fromkeys(failed_peers, error))
                raise error

        frontend_certs, closed_frontend = self._stage_frontend_client_auth(
            loadbalancer.id, closure_peers.values(), peers, details, fallback)
        if (closed_frontend and not weighted_partial and
                (tcp_batch_configs is not None or
                 (l7policy_activation and not l7policy_restoration))):
            raise driver_except.ListenerProvisioningError()

        certs = {amp_id: {} for amp_id in closure_peers}
        closed = set()
        system_ca_pools = set()
        system_ca_material = None
        for pool_id, (listener, pool) in protected.items():
            required = [consts.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME]
            system_ca = getattr(pool, 'backend_tls_system_ca', False) is True
            if system_ca:
                system_ca_pools.add(pool_id)
                required.append(
                    consts.GATEWAY_CAPABILITY_BACKEND_TLS_SYSTEM_CA)
            if pool.protocol == consts.PROTOCOL_TCP:
                required.append(consts.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH)
            if getattr(pool, 'backend_tls_require_h2', False) is True:
                required.append(consts.GATEWAY_CAPABILITY_BACKEND_TLS_H2_ALPN)
            if getattr(pool, 'backend_tls_subject_alt_names', None):
                required.append(
                    consts.GATEWAY_CAPABILITY_BACKEND_TLS_SUBJECT_ALT_NAMES)
            unsupported = [
                amp_id for amp_id, detail in details.items()
                if any(detail.get(capability) is not True
                       for capability in required)]
            if unsupported:
                LOG.warning('Backend TLS pool %s will close because its '
                            'required capabilities could not be confirmed '
                            'on amphorae %s.', pool_id, unsupported)
            else:
                try:
                    if system_ca and system_ca_material is None:
                        # All system pools share the same regional image
                        # bundle. Fail any of them as a unit across the pair.
                        system_ca_material = {}
                        system_ca_material = self._stage_system_ca(
                            loadbalancer, peers, timeout_dict)
                    if system_ca and not system_ca_material:
                        raise driver_except.ListenerProvisioningError()
                    material = {
                        amphora.id: self._process_pool_certs(
                            listener, pool, amphora, loadbalancer.id,
                            **({'system_ca_material': system_ca_material}
                               if system_ca else {}))
                        for amphora in peers
                    }
                except Exception as error:
                    LOG.warning('Backend TLS pool %s will close because its '
                                'TLS configuration could not be prepared '
                                '(%s).', pool_id, type(error).__name__)
                else:
                    for amphora in closure_peers.values():
                        certs[amphora.id][pool_id] = material[amphora.id]
                    continue
            closed.add(pool_id)
            for amphora in closure_peers.values():
                certs[amphora.id][pool_id] = {'closed': True}

        if (tcp_batch_configs is not None and not weighted_partial and
                closed - system_ca_pools):
            raise driver_except.ListenerProvisioningError()

        reload_errors = dict(weighted_errors)
        if system_ca_observed is not None:
            reload_errors.update(dict.fromkeys(
                unreachable, driver_except.ListenerProvisioningError()))
        reloaded_listeners = []
        render_options = {}
        if otlp_observed is not None:
            render_options['otlp_observed'] = otlp_observed
        if http_persistence_observed is not None:
            render_options['http_persistence_observed'] = (
                http_persistence_observed)
        if read_http_header_key is not None:
            render_options['read_http_header_key'] = read_http_header_key
        if system_ca_observed is not None:
            render_options['system_ca_observed'] = system_ca_observed
        if backoff_policies:
            render_options.update(
                http_retry_backoff_observed=backoff_votes,
                required_backoff_policies=required_backoff_policies)
        staged_batch = tcp_batch_configs is not None and not weighted_partial
        batch_options = (
            {'tcp_batch_configs': tcp_batch_configs} if staged_batch else {})

        def publish(amphora, *, tcp_only=False, **options):
            verify_publication = (
                verify_header_publication or
                (weighted_present and details[amphora.id].get(
                    weighted_capability) is True))
            return self._update_amphora_listeners(
                loadbalancer, amphora, timeout_dict=timeout_dict,
                amp_details=details[amphora.id],
                backend_tls_certs=certs[amphora.id],
                frontend_tls_certs=frontend_certs[amphora.id],
                closed_frontend=closed_frontend,
                l7policy_activation=l7policy_activation,
                **({'verify_publication': True} if verify_publication
                   else {}),
                **({'tcp_only': True} if tcp_only or
                   amphora.id not in requested_amp_ids else {}),
                **({'weighted_passthrough_degraded': True}
                   if weighted_partial else {}),
                **render_options, **options)

        attempted = [amp for amp in amphorae if
                     not (weighted_partial and amp.id in probe_failures)]
        for amphora in attempted:
            try:
                reloaded_listeners.append(publish(amphora, **batch_options))
            except Exception as error:
                if (staged_batch and not system_ca_pools and
                        not verify_header_publication):
                    raise
                LOG.warning('Could not reload listeners on amphora %s (%s).',
                            amphora.id, type(error).__name__)
                reload_errors[amphora.id] = error

        batch_error = None
        closing_system_ca = bool(system_ca_pools and system_ca_pools <= closed)
        if staged_batch and not reload_errors:
            try:
                self._reload_tcp_batch_configs(
                    loadbalancer, tcp_batch_configs, backoff_policies,
                    http_persistence_observed, otlp_observed,
                    system_ca_observed,
                    closing=closing_system_ca or closing_header,
                    verify_publication=verify_header_publication)
            except Exception as error:
                if not system_ca_pools and not verify_header_publication:
                    raise
                batch_error = error

        render_failed = staged_batch and bool(reload_errors)
        close_system_ca = system_ca_pools and (
            not closing_system_ca or render_failed)
        close_header = verify_header_publication and (
            not closing_header or render_failed)
        if ((reload_errors or batch_error) and
                (close_system_ca or close_header)):
            # An upload or reload can leave an earlier peer on the new graph.
            # Publish a fresh closed generation independently on each peer.
            if close_system_ca:
                closed.update(system_ca_pools)
            if close_header:
                for detail in details.values():
                    detail[header_capability] = False
            for amphora in (closure_peers.values() if close_header
                            else attempted):
                if close_system_ca:
                    certs[amphora.id].update(
                        dict.fromkeys(system_ca_pools, {'closed': True}))
                try:
                    publish(amphora, tcp_only=bool(close_header))
                except Exception as error:
                    LOG.warning('Could not confirm protected pool '
                                'withdrawal on amphora %s (%s).', amphora.id,
                                type(error).__name__)
                    reload_errors.setdefault(amphora.id, error)

        if staged_batch:
            if closed:
                with db_api.session().begin() as session:
                    repo.PoolRepository().set_backend_tls_pool_statuses(
                        session, closed=closed, recovered=())
            if reload_errors:
                raise next(iter(reload_errors.values()))
            if batch_error is not None:
                raise batch_error
            if any(pool.id in closed and pool.tcp_member_batch_id not in (
                    None, consts.TCP_MEMBER_BATCH_FAILED)
                   for pool in loadbalancer.pools):
                raise driver_except.ListenerProvisioningError()
            return

        if backoff_policies:
            self._publish_http_retry_backoff_results(
                loadbalancer, backoff_policies, backoff_votes,
                completed=not (reload_errors or weighted_topology_missing),
                failed=(required_backoff_policies if reload_errors and
                        require_http_retry_backoff else ()))

        recovered = set()
        restored_frontend = set()
        if (not (reload_errors or weighted_topology_missing) and amphorae and
                len(amphorae) == len(peers)):
            recovered = {pool_id
                         for pool_id, (listener, pool) in protected.items()
                         if pool_id not in closed and
                         pool.provisioning_status == consts.ERROR and
                         all(listener.id in configured
                             for configured in reloaded_listeners)}
            paired = loadbalancer.topology == consts.TOPOLOGY_ACTIVE_STANDBY
            if withdrawn and (not paired or len(peers) >= 2):
                restored_frontend = withdrawn.intersection(
                    *reloaded_listeners)
                restored_frontend.update(
                    listener.id for listener in loadbalancer.listeners
                    if (listener.id in withdrawn and
                        not (listener.enabled and loadbalancer.enabled)))
        # The activation worker publishes recoveries after comparing the
        # original graph and in the same transaction as its policy changes.
        publish_recovered = set() if l7policy_activation else recovered
        if closed or publish_recovered:
            pool_repo = repo.PoolRepository()
            with db_api.session().begin() as session:
                pool_repo.set_backend_tls_pool_statuses(
                    session, closed=closed, recovered=publish_recovered)
        if not reloaded_listeners:
            closed_frontend = set()
        if closed_frontend or restored_frontend:
            listener_repo = repo.ListenerRepository()
            with db_api.session().begin() as session:
                listener_repo.set_frontend_fallback_statuses(
                    session, closed=closed_frontend, restored=restored_frontend)
        if reload_errors:
            if coordinating_failover:
                raise driver_except.CoordinatedListenerUpdateError(
                    reload_errors)
            raise next(iter(reload_errors.values()))
        if weighted_topology_missing:
            raise driver_except.ListenerProvisioningError()
        if l7policy_activation:
            return recovered

    def _stage_system_ca(self, loadbalancer, peers, timeout_dict):
        expected = self._allocated_amphorae(loadbalancer)
        profile = validate.backend_tls_system_ca_profile(loadbalancer.provider)
        if not profile or {amp.id for amp in expected} != {
                amp.id for amp in peers}:
            raise driver_except.ListenerProvisioningError()
        path, digest = profile
        for amphora in expected:
            client = self.clients[amphora.api_version]
            if client.stage_backend_tls_system_ca(
                    amphora, loadbalancer.id, path, digest,
                    timeout_dict=timeout_dict) != digest:
                raise driver_except.ListenerProvisioningError()
        return {
            'system_ca_sha256': digest,
            'ca_cert': os.path.join(
                CONF.haproxy_amphora.base_path, loadbalancer.id,
                consts.HAPROXY_SYSTEM_CA_DIRECTORY, f'{digest}.pem'),
        }

    def _publish_http_retry_backoff_results(
            self, loadbalancer, policies, votes, *, completed, failed=()):
        closed = set(failed)
        closed.update(policy_id for statuses in votes.values()
                      for policy_id, status in statuses.items()
                      if status == consts.ERROR)
        recovered = set()
        if completed:
            try:
                peers = self._allocated_amphorae(loadbalancer)
            except driver_except.ListenerProvisioningError:
                pass
            else:
                active = consts.ACTIVE
                recovered = {
                    policy_id for policy_id in policies.keys() - closed
                    if all(votes.get(amp.id, {}).get(policy_id) == active
                           for amp in peers)}
        if closed or recovered:
            with db_api.session().begin() as session:
                repo.L7PolicyRepository().set_http_retry_backoff_statuses(
                    session, policies, closed=closed, recovered=recovered)

    def _stage_frontend_client_auth(
            self, lb_id, amphorae, peers, details, listeners):
        certs = {amphora.id: {} for amphora in amphorae}
        closed = set()
        if not listeners:
            return certs, closed

        capability = (
            consts.GATEWAY_CAPABILITY_FRONTEND_CLIENT_AUTH_INSECURE_FALLBACK)
        unsupported = [amp_id for amp_id, detail in details.items()
                       if detail.get(capability) is not True]
        for listener in listeners:
            if unsupported:
                LOG.warning('Frontend client authentication fallback on '
                            'listener %s requires support on amphorae %s.',
                            listener.id, unsupported)
            else:
                try:
                    material = {
                        amphora.id: self._process_listener_tls_certs(
                            listener, amphora, lb_id, validate_client_ca=True)
                        for amphora in peers
                    }
                except Exception as error:
                    LOG.warning('Frontend client authentication fallback on '
                                'listener %s could not stage TLS material '
                                '(%s).', listener.id, type(error).__name__)
                else:
                    for amphora in amphorae:
                        certs[amphora.id][listener.id] = material[amphora.id]
                    continue
            closed.add(listener.id)
        return certs, closed

    def upload_cert_amp(self, amp, pem):
        LOG.debug("Amphora %s updating cert in REST driver "
                  "with amphora id %s,",
                  self.__class__.__name__, amp.id)
        self._populate_amphora_api_version(amp)
        self.clients[amp.api_version].update_cert_for_rotation(amp, pem)

    def _apply(self, func_name, loadbalancer, amphora=None, *args, **kwargs):
        if amphora is None:
            amphorae = loadbalancer.amphorae
        else:
            amphorae = [amphora]

        for amp in amphorae:
            if amp.status != consts.DELETED:
                self._populate_amphora_api_version(
                    amp, timeout_dict=args[0])
                has_tcp = False
                for listener in loadbalancer.listeners:
                    if listener.protocol in consts.LVS_PROTOCOLS:
                        getattr(self.clients[amp.api_version], func_name)(
                            amp, listener.id, *args)
                    else:
                        has_tcp = True
                if has_tcp:
                    getattr(self.clients[amp.api_version], func_name)(
                        amp, loadbalancer.id, *args)

    def reload(self, loadbalancer, amphora=None, timeout_dict=None):
        self._apply('reload_listener', loadbalancer, amphora, timeout_dict)

    def start(self, loadbalancer, amphora=None, timeout_dict=None):
        self._apply('start_listener', loadbalancer, amphora, timeout_dict)

    def delete(self, listener):
        loadbalancer = listener.load_balancer
        if self._has_udp_guard(listener):
            return self._update_scoped_udp_listeners(
                loadbalancer, [listener], delete=True)
        if listener.protocol in consts.LVS_PROTOCOLS:
            for amp in loadbalancer.amphorae:
                if amp.status != consts.DELETED:
                    self._populate_amphora_api_version(amp)
                    self.clients[amp.api_version].delete_listener(
                        amp, listener.id)
            return

        # In case the listener is not UDP or SCTP, things get more complicated.
        for amp in loadbalancer.amphorae:
            if amp.status != consts.DELETED:
                self._combined_config_delete(amp, listener)

    def _combined_config_delete(self, amphora, listener):
        # Remove the listener from the listener list on the LB before
        # passing the whole thing over to update (so it'll actually delete)
        # In case of amphorae in ACTIVE_STANDBY topology, ensure that we don't
        # remove an already removed listener.
        if listener in listener.load_balancer.listeners:
            listener.load_balancer.listeners.remove(listener)

        # Check if there's any certs that we need to delete
        certs = self._process_tls_certificates(listener)
        certs_to_delete = set()
        if certs['tls_cert']:
            certs_to_delete.add(certs['tls_cert'].id)
        for sni_cert in certs['sni_certs']:
            certs_to_delete.add(sni_cert.id)

        # Delete them (they'll be recreated before the reload if they are
        # needed for other listeners anyway)
        self._populate_amphora_api_version(amphora)
        for cert_id in certs_to_delete:
            self.clients[amphora.api_version].delete_cert_pem(
                amphora, listener.load_balancer.id,
                f'{cert_id}.pem')

        # See how many non-UDP/SCTP listeners we have left
        non_lvs_listener_count = len([
            1 for li in listener.load_balancer.listeners
            if li.protocol not in consts.LVS_PROTOCOLS])
        if not non_lvs_listener_count:
            with self._system_ca_render_results(listener.load_balancer):
                self.clients[amphora.api_version].delete_listener(
                    amphora, listener.load_balancer.id)
        else:
            # We have other listeners, so just update is fine.
            # TODO(rm_work): This is a little inefficient since this duplicates
            # a lot of the detection logic that has already been done, but it
            # is probably safer to reuse the existing code-path.
            self.update_amphora_listeners(listener.load_balancer, amphora)

    def get_info(self, amphora, raise_retry_exception=False,
                 timeout_dict=None):
        self._populate_amphora_api_version(
            amphora, raise_retry_exception=raise_retry_exception,
            timeout_dict=timeout_dict)
        return self.clients[amphora.api_version].get_info(
            amphora, raise_retry_exception=raise_retry_exception,
            timeout_dict=timeout_dict)

    def get_diagnostics(self, amphora):
        pass

    def finalize_amphora(self, amphora):
        pass

    def _build_net_info(self, port, amphora, subnet, mtu=None, sriov=False):
        # NOTE(blogan): using the vrrp port here because that
        # is what the allowed address pairs network driver sets
        # this particular port to.  This does expose a bit of
        # tight coupling between the network driver and amphora
        # driver.  We will need to revisit this to try and remove
        # this tight coupling.
        # NOTE (johnsom): I am loading the vrrp_ip into the
        # net_info structure here so that I don't break
        # compatibility with old amphora agent versions.
        host_routes = [{'nexthop': hr[consts.NEXTHOP],
                        'destination': hr[consts.DESTINATION]}
                       for hr in subnet[consts.HOST_ROUTES]]
        net_info = {'subnet_cidr': subnet[consts.CIDR],
                    'gateway': subnet[consts.GATEWAY_IP],
                    'mac_address': port[consts.MAC_ADDRESS],
                    'vrrp_ip': amphora[consts.VRRP_IP],
                    'mtu': mtu or port[consts.NETWORK][consts.MTU],
                    'host_routes': host_routes,
                    'additional_vips': [],
                    'is_sriov': sriov}
        return net_info

    def post_vip_plug(self, amphora, load_balancer, amphorae_network_config,
                      vrrp_port, vip_subnet, additional_vip_data=None):
        if amphora.status != consts.DELETED:
            self._populate_amphora_api_version(amphora)
            port = vrrp_port.to_dict(recurse=True)
            mtu = port[consts.NETWORK][consts.MTU]
            LOG.debug("Post-VIP-Plugging with vrrp_ip %s vrrp_port %s",
                      amphora.vrrp_ip, port[consts.ID])
            sriov = False
            if load_balancer.vip.vnic_type == consts.VNIC_TYPE_DIRECT:
                sriov = True
            net_info = self._build_net_info(
                port, amphora.to_dict(),
                vip_subnet.to_dict(recurse=True), mtu, sriov)
            for add_vip in additional_vip_data:
                add_host_routes = [{'nexthop': hr.nexthop,
                                    'destination': hr.destination}
                                   for hr in add_vip.subnet.host_routes]
                add_net_info = {'subnet_cidr': add_vip.subnet.cidr,
                                'ip_address': add_vip.ip_address,
                                'gateway': add_vip.subnet.gateway_ip,
                                'host_routes': add_host_routes}
                net_info['additional_vips'].append(add_net_info)
            try:
                self.clients[amphora.api_version].plug_vip(
                    amphora, load_balancer.vip.ip_address, net_info)
            except exc.Conflict:
                LOG.warning('VIP with MAC %(mac)s already exists on amphora, '
                            'skipping post_vip_plug',
                            {'mac': port[consts.MAC_ADDRESS]})

    def post_network_plug(self, amphora, port, amphora_network_config):
        fixed_ips = []
        for fixed_ip in port.fixed_ips:
            host_routes = [{'nexthop': hr.nexthop,
                            'destination': hr.destination}
                           for hr in fixed_ip.subnet.host_routes]
            ip = {'ip_address': fixed_ip.ip_address,
                  'subnet_cidr': fixed_ip.subnet.cidr,
                  'host_routes': host_routes,
                  'gateway': fixed_ip.subnet.gateway_ip}
            fixed_ips.append(ip)
        port_info = {'mac_address': port.mac_address,
                     'fixed_ips': fixed_ips,
                     'mtu': port.network.mtu,
                     'is_sriov': False}
        if port.vnic_type == consts.VNIC_TYPE_DIRECT:
            port_info['is_sriov'] = True
        if port.id == amphora.vrrp_port_id:
            # We have to special-case sharing the vrrp port and pass through
            # enough extra information to populate the whole VIP port
            net_info = self._build_net_info(
                port.to_dict(recurse=True), amphora.to_dict(),
                amphora_network_config[consts.VIP_SUBNET],
                port.network.mtu)
            net_info['vip'] = amphora.ha_ip
            port_info['vip_net_info'] = net_info
        try:
            self._populate_amphora_api_version(amphora)
            self.clients[amphora.api_version].plug_network(amphora, port_info)
        except exc.Conflict:
            LOG.warning('Network with MAC %(mac)s already exists on amphora, '
                        'skipping post_network_plug',
                        {'mac': port.mac_address})

    def _process_listener_tls_certs(self, listener, amphora, obj_id, *,
                                    validate_client_ca=False):
        server_certs = self._process_tls_certificates(listener, amphora, obj_id)
        ca_options = {}
        crl_options = {}
        if validate_client_ca:
            if (not listener.client_ca_tls_certificate_id or not (
                    server_certs['tls_cert'] or server_certs['sni_certs'])):
                raise driver_except.ListenerProvisioningError()
            ca_options['validate_pem'] = (
                cert_parser.load_frontend_client_ca_certificates)
            crl_options['validate_pem'] = x509.load_pem_x509_crl
        return {
            listener.tls_certificate_id: server_certs['tls_cert'],
            listener.client_ca_tls_certificate_id: self._process_secret(
                listener, listener.client_ca_tls_certificate_id,
                amphora, obj_id, **ca_options),
            listener.client_crl_container_id: self._process_secret(
                listener, listener.client_crl_container_id,
                amphora, obj_id, **crl_options),
        }

    def _process_tls_certificates(self, listener, amphora=None, obj_id=None):
        """Processes TLS data from the listener.

        Converts and uploads PEM data to the Amphora API

        return TLS_CERT and SNI_CERTS
        """
        tls_cert = None
        sni_certs = []
        certs = []
        cert_filename_list = []

        data = cert_parser.load_certificates_data(
            self.cert_manager, listener)
        if data['tls_cert'] is not None:
            tls_cert = data['tls_cert']
            # Note, the first cert is the TLS default cert
            certs.append(tls_cert)
        if data['sni_certs']:
            sni_certs = data['sni_certs']
            certs.extend(sni_certs)

        if amphora and obj_id:
            for cert in certs:
                pem = cert_parser.build_pem(cert)
                md5sum = hashlib.md5(
                    pem, usedforsecurity=False).hexdigest()  # nosec
                name = f'{cert.id}.pem'
                cert_filename_list.append(
                    os.path.join(
                        CONF.haproxy_amphora.base_cert_dir, obj_id, name))
                self._upload_cert(amphora, obj_id, pem, md5sum, name)

            if certs:
                # Build and upload the crt-list file for haproxy
                crt_list = "\n".join(cert_filename_list)
                crt_list = f'{crt_list}\n'.encode()
                md5sum = hashlib.md5(
                    crt_list, usedforsecurity=False).hexdigest()  # nosec
                name = f'{listener.id}.pem'
                self._upload_cert(amphora, obj_id, crt_list, md5sum, name)
        return {'tls_cert': tls_cert, 'sni_certs': sni_certs}

    def _process_secret(self, listener, secret_ref, amphora=None, obj_id=None,
                        *, validate_pem=None):
        """Get the secret from the cert manager and upload it to the amp.

        :returns: The filename of the secret in the amp.
        """
        if not secret_ref:
            return None
        context = oslo_context.RequestContext(project_id=listener.project_id)
        secret = self.cert_manager.get_secret(context, secret_ref)
        try:
            secret = secret.encode('utf-8')
        except AttributeError:
            pass
        if validate_pem is not None:
            validate_pem(secret)
        md5sum = hashlib.md5(
            secret, usedforsecurity=False).hexdigest()  # nosec
        id = hashlib.sha1(secret).hexdigest()  # nosec
        name = f'{id}.pem'

        if amphora and obj_id:
            self._upload_cert(
                amphora, obj_id, pem=secret, md5sum=md5sum, name=name)
        return name

    def _process_otlp_collector_certs(
            self, listener, loadbalancer, amphora, pool_id):
        pool = next((pool for pool in loadbalancer.pools
                     if pool.id == pool_id), None)
        if (pool is None or not pool.enabled or not pool.tls_enabled or
                pool.provisioning_status in (consts.PENDING_DELETE,
                                             consts.DELETED)):
            return {}
        try:
            material = self._process_pool_certs(
                listener, pool, amphora, loadbalancer.id)
            required = {'client_cert': pool.tls_certificate_id,
                        'ca_cert': pool.ca_tls_certificate_id,
                        'crl': pool.crl_container_id}
            if any(ref and not material.get(name)
                   for name, ref in required.items()):
                raise exceptions.ValidationException(detail=(
                    'Missing OTLP collector TLS material.'))
            return material
        except Exception as error:
            LOG.warning('OTLP collector pool %s TLS setup failed (%s).',
                        pool_id, type(error).__name__)
            return {'closed': True}

    def _process_listener_pool_certs(self, listener, amphora, obj_id):
        #     {'POOL-ID': {
        #         'client_cert': client_full_filename,
        #         'ca_cert': ca_cert_full_filename,
        #         'crl': crl_full_filename}}
        pool_certs_dict = {}
        pools = {pool.id: pool for pool in listener.pools}
        for l7policy in listener.l7policies:
            if l7policy.redirect_pool:
                pools.setdefault(l7policy.redirect_pool.id,
                                 l7policy.redirect_pool)
        for pool in pools.values():
            # Protected pools are staged once for the pair, independently of
            # the listener's own credentials and the legacy pool path.
            if utils.is_protected_backend_tls_pool(pool):
                continue
            pool_certs_dict[pool.id] = self._process_pool_certs(
                listener, pool, amphora, obj_id)
        return pool_certs_dict

    def _process_pool_certs(self, listener, pool, amphora, obj_id, *,
                            system_ca_material=None):
        pool_cert_dict = {}
        if utils.is_disabled_backend_tls_pool(pool):
            return pool_cert_dict
        hostname = getattr(pool, 'backend_tls_hostname', None)
        system_ca = getattr(pool, 'backend_tls_system_ca', False) is True
        valid_ca = bool(pool.ca_tls_certificate_id)
        if system_ca:
            valid_ca = (bool(system_ca_material) and
                        pool.ca_tls_certificate_id is None and
                        not pool.crl_container_id)
        if utils.is_protected_backend_tls_pool(pool) and (
                not validate.is_exact_sni_name(hostname) or
                pool.protocol not in (consts.PROTOCOL_HTTP,
                                      consts.PROTOCOL_TCP) or
                pool.tls_enabled is not True or
                not valid_ca or
                getattr(pool, 'backend_h2c', False)):
            raise exceptions.ValidationException(detail=(
                'Missing or invalid backend TLS identity or trust '
                'configuration.'))
        if pool.protocol == consts.PROTOCOL_TCP and hostname is not None:
            if (getattr(pool, 'backend_tls_require_h2', False) or
                    getattr(pool, 'backend_tls_subject_alt_names', None)):
                raise exceptions.ValidationException(detail=(
                    'Unsupported backend TLS options for a TCP pool.'))
            monitor = pool.health_monitor
            if (monitor and monitor.enabled and
                    monitor.provisioning_status not in
                    (consts.PENDING_DELETE, consts.DELETED)):
                validate.validate_tcp_tls_backend_monitor(monitor.type)

        if system_ca:
            pool_cert_dict.update(system_ca_material)

        # Handle the client cert(s) and key
        if pool.tls_certificate_id:
            data = cert_parser.load_certificates_data(self.cert_manager, pool)
            tls_cert = data['tls_cert']
            pem = cert_parser.build_pem(tls_cert)
            try:
                pem = pem.encode('utf-8')
            except AttributeError:
                pass
            md5sum = hashlib.md5(
                pem, usedforsecurity=False).hexdigest()  # nosec
            name = f'{tls_cert.id}.pem'
            if amphora and obj_id:
                self._upload_cert(amphora, obj_id, pem=pem,
                                  md5sum=md5sum, name=name)
            pool_cert_dict['client_cert'] = os.path.join(
                CONF.haproxy_amphora.base_cert_dir, obj_id, name)
        if pool.ca_tls_certificate_id:
            kwargs = {}
            if hostname is not None:
                kwargs['validate_pem'] = x509.load_pem_x509_certificates
            name = self._process_secret(listener, pool.ca_tls_certificate_id,
                                        amphora, obj_id, **kwargs)
            pool_cert_dict['ca_cert'] = os.path.join(
                CONF.haproxy_amphora.base_cert_dir, obj_id, name)
        if pool.crl_container_id:
            kwargs = {}
            if hostname is not None:
                kwargs['validate_pem'] = x509.load_pem_x509_crl
            name = self._process_secret(listener, pool.crl_container_id,
                                        amphora, obj_id, **kwargs)
            pool_cert_dict['crl'] = os.path.join(
                CONF.haproxy_amphora.base_cert_dir, obj_id, name)

        return pool_cert_dict

    def _upload_cert(self, amp, listener_id, pem, md5sum, name):
        try:
            if self.clients[amp.api_version].get_cert_md5sum(
                    amp, listener_id, name, ignore=(404,)) == md5sum:
                return
        except exc.NotFound:
            pass

        self.clients[amp.api_version].upload_cert_pem(
            amp, listener_id, name, pem)

    def update_amphora_agent_config(self, amphora, agent_config,
                                    timeout_dict=None):
        """Update the amphora agent configuration file.

        :param amphora: The amphora to update.
        :type amphora: object
        :param agent_config: The new amphora agent configuration.
        :type agent_config: string
        :param timeout_dict: Dictionary of timeout values for calls to the
                             amphora. May contain: req_conn_timeout,
                             req_read_timeout, conn_max_retries,
                             conn_retry_interval
        :returns: None

        Note: This will mutate the amphora agent config and adopt the
              new values.
        """
        try:
            self._populate_amphora_api_version(amphora)
            self.clients[amphora.api_version].update_agent_config(
                amphora, agent_config, timeout_dict=timeout_dict)
        except exc.NotFound as e:
            LOG.debug('Amphora %s does not support the update_agent_config '
                      'API.', amphora.id)
            raise driver_except.AmpDriverNotImplementedError() from e

    def get_interface_from_ip(self, amphora, ip_address, timeout_dict=None):
        """Get the interface name for an IP address.

        :param amphora: The amphora to query.
        :type amphora: octavia.db.models.Amphora
        :param ip_address: The IP address to lookup. (IPv4 or IPv6)
        :type ip_address: string
        :param timeout_dict: Dictionary of timeout values for calls to the
                             amphora. May contain: req_conn_timeout,
                             req_read_timeout, conn_max_retries,
                             conn_retry_interval
        :type timeout_dict: dict
        :returns: the interface name string if found.
        :raises octavia.amphorae.drivers.haproxy.exceptions.NotFound:
                No interface found on the amphora
        :raises TimeOutException: The amphora didn't reply
        """
        self._populate_amphora_api_version(amphora, timeout_dict)
        response_json = self.clients[amphora.api_version].get_interface(
            amphora, ip_address, timeout_dict, log_error=False)
        return response_json.get('interface', None)

    def set_interface_rules(self, amphora: db_models.Amphora,
                            ip_address, rules, timeout_dict=None):
        """Sets interface firewall rules in the amphora

        :param amphora: The amphora to query.
        :param ip_address: The IP address assigned to the interface the rules
                           will be applied on.
        :param rules: The l1st of allow rules to apply.
        """
        try:
            self._populate_amphora_api_version(amphora, timeout_dict)
            self.clients[amphora.api_version].set_interface_rules(
                amphora, ip_address, rules, timeout_dict=timeout_dict)
        except exc.NotFound as e:
            LOG.debug('Amphora %s does not support the set_interface_rules '
                      'API.', amphora.id)
            raise driver_except.AmpDriverNotImplementedError() from e


# Check a custom hostname
class CustomHostNameCheckingAdapter(requests.adapters.HTTPAdapter):
    def cert_verify(self, conn, url, verify, cert):
        conn.assert_hostname = self.uuid
        return super().cert_verify(conn, url, verify, cert)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        proto = CONF.amphora_agent.agent_tls_protocol.replace('.', '_')
        pool_kwargs['ssl_minimum_version'] = getattr(ssl.TLSVersion, proto)
        return super().init_poolmanager(*pool_args, **pool_kwargs)


class AmphoraAPIClientBase:
    def __init__(self):
        super().__init__()

        self.get = functools.partial(self.request, 'get')
        self.post = functools.partial(self.request, 'post')
        self.put = functools.partial(self.request, 'put')
        self.delete = functools.partial(self.request, 'delete')
        self.head = functools.partial(self.request, 'head')

        self.session = requests.Session()
        self.session.cert = CONF.haproxy_amphora.client_cert
        self.ssl_adapter = CustomHostNameCheckingAdapter()
        self.session.mount('https://', self.ssl_adapter)

    def _base_url(self, ip, api_version=None):
        if utils.is_ipv6_lla(ip):
            ip = f'[{ip}%{CONF.haproxy_amphora.lb_network_interface}]'
        elif utils.is_ipv6(ip):
            ip = f'[{ip}]'
        if api_version:
            return (f"https://{ip}:{CONF.haproxy_amphora.bind_port}"
                    f"/{api_version}/")
        return f"https://{ip}:{CONF.haproxy_amphora.bind_port}/"

    def request(self, method: str, amp: db_models.Amphora, path: str = '/',
                timeout_dict: Optional[dict] = None,
                retry_404: bool = True, raise_retry_exception: bool = False,
                **kwargs):
        cfg_ha_amp = CONF.haproxy_amphora
        if timeout_dict is None:
            timeout_dict = {}
        req_conn_timeout = timeout_dict.get(
            consts.REQ_CONN_TIMEOUT, cfg_ha_amp.rest_request_conn_timeout)
        req_read_timeout = timeout_dict.get(
            consts.REQ_READ_TIMEOUT, cfg_ha_amp.rest_request_read_timeout)
        conn_max_retries = timeout_dict.get(
            consts.CONN_MAX_RETRIES, cfg_ha_amp.connection_max_retries)
        conn_retry_interval = timeout_dict.get(
            consts.CONN_RETRY_INTERVAL, cfg_ha_amp.connection_retry_interval)

        LOG.debug("request url %s", path)
        _request = getattr(self.session, method.lower())
        _url = self._base_url(amp.lb_network_ip, amp.api_version) + path
        LOG.debug("request url %s", _url)
        reqargs = {
            'verify': CONF.haproxy_amphora.server_ca,
            'url': _url,
            'timeout': (req_conn_timeout, req_read_timeout), }
        reqargs.update(kwargs)
        headers = reqargs.setdefault('headers', {})

        headers['User-Agent'] = (
            f"Octavia HaProxy Rest Client/{amp.api_version} "
            f"(https://wiki.openstack.org/wiki/Octavia)")
        self.ssl_adapter.uuid = amp.id
        exception = None
        # Keep retrying
        for dummy in range(conn_max_retries):
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message="A true SSLContext object is not available"
                    )
                    r = _request(**reqargs)
                LOG.debug('Connected to amphora. Response: %(resp)s',
                          {'resp': r})

                content_type = r.headers.get('content-type', '')
                # Check the 404 to see if it is just that the network in the
                # amphora is not yet up, in which case retry.
                # Otherwise return the response quickly.
                if r.status_code == 404:
                    if not retry_404:
                        raise exc.NotFound()
                    LOG.debug('Got a 404 (content-type: %(content_type)s) -- '
                              'connection data: %(content)s',
                              {'content_type': content_type,
                               'content': r.content})
                    if content_type.find("application/json") == -1:
                        LOG.debug("Amphora agent not ready.")
                        raise requests.ConnectionError
                    try:
                        json_data = r.json().get('details', '')
                        if 'No suitable network interface found' in json_data:
                            LOG.debug("Amphora network interface not found.")
                            raise requests.ConnectionError
                    except json.JSONDecodeError:  # if r.json() fails
                        pass  # TODO(rm_work) Should we do something?
                return r
            except (requests.ConnectionError, requests.Timeout) as e:
                exception = e
                LOG.warning("Could not connect to instance. Retrying.")
                time.sleep(conn_retry_interval)
                if raise_retry_exception:
                    # For taskflow persistence cause attribute should
                    # be serializable to JSON. Pass None, as cause exception
                    # is described in the expection message.
                    raise driver_except.AmpConnectionRetry(
                        exception=str(e)) from None
        LOG.error("Connection retries (currently set to %(max_retries)s) "
                  "exhausted.  The amphora is unavailable. Reason: "
                  "%(exception)s",
                  {'max_retries': conn_max_retries,
                   'exception': exception})
        raise driver_except.TimeOutException()

    def get_api_version(self, amp, timeout_dict=None,
                        raise_retry_exception=False):
        amp.api_version = None
        r = self.get(amp, retry_404=False, timeout_dict=timeout_dict,
                     raise_retry_exception=raise_retry_exception)
        # Handle 404 special as we don't want to log an ERROR on 404
        exc.check_exception(r, (404,))
        if r.status_code == 404:
            raise exc.NotFound()
        return r.json()


class AmphoraAPIClient1_0(AmphoraAPIClientBase):
    def __init__(self):
        super().__init__()

        self.start_listener = functools.partial(self._action,
                                                consts.AMP_ACTION_START)
        self.reload_listener = functools.partial(self._action,
                                                 consts.AMP_ACTION_RELOAD)

        self.start_vrrp = functools.partial(self._vrrp_action,
                                            consts.AMP_ACTION_START)
        self.stop_vrrp = functools.partial(self._vrrp_action,
                                           consts.AMP_ACTION_STOP)
        self.reload_vrrp = functools.partial(self._vrrp_action,
                                             consts.AMP_ACTION_RELOAD)

    def upload_config(self, amp, loadbalancer_id, config, timeout_dict=None):
        r = self.put(
            amp,
            f'loadbalancer/{amp.id}/{loadbalancer_id}/haproxy',
            timeout_dict, data=config)
        return exc.check_exception(r)

    def get_listener_status(self, amp, listener_id):
        r = self.get(
            amp,
            f'listeners/{listener_id}')
        if exc.check_exception(r):
            return r.json()
        return None

    def _action(self, action, amp, object_id, timeout_dict=None, *,
                otlp_publication=None, config_publication=None):
        options = {}
        if config_publication is not None:
            options['headers'] = {
                consts.HAPROXY_CONFIG_PUBLICATION_HEADER: config_publication}
        elif otlp_publication is not None:
            options['headers'] = {
                consts.HAPROXY_OTLP_PUBLICATION_HEADER: otlp_publication}
        r = self.put(
            amp, f'loadbalancer/{object_id}/{action}',
            timeout_dict=timeout_dict, **options)
        return exc.check_exception(r)

    def stage_backend_tls_system_ca(self, amp, loadbalancer_id, path, digest,
                                    timeout_dict=None):
        response = self.put(
            amp, f'loadbalancer/{loadbalancer_id}/backend-system-ca',
            timeout_dict, json={'path': path, 'sha256': digest})
        return exc.check_exception(response).json()['sha256']

    def upload_cert_pem(self, amp, loadbalancer_id, pem_filename, pem_file):
        r = self.put(
            amp,
            f'loadbalancer/{loadbalancer_id}/certificates/{pem_filename}',
            data=pem_file)
        return exc.check_exception(r)

    def get_cert_md5sum(self, amp, loadbalancer_id, pem_filename,
                        ignore=tuple()):
        r = self.get(
            amp,
            f'loadbalancer/{loadbalancer_id}/certificates/{pem_filename}')
        if exc.check_exception(r, ignore):
            return r.json().get("md5sum")
        return None

    def delete_cert_pem(self, amp, loadbalancer_id, pem_filename):
        r = self.delete(
            amp,
            f'loadbalancer/{loadbalancer_id}/certificates/{pem_filename}')
        return exc.check_exception(r, (404,))

    def update_cert_for_rotation(self, amp, pem_file):
        r = self.put(amp, 'certificate', data=pem_file)
        return exc.check_exception(r)

    def delete_listener(self, amp, object_id):
        r = self.delete(
            amp, f'listeners/{object_id}')
        return exc.check_exception(r, (404,))

    def get_info(self, amp, raise_retry_exception=False,
                 timeout_dict=None):
        r = self.get(amp, "info", raise_retry_exception=raise_retry_exception,
                     timeout_dict=timeout_dict)
        if exc.check_exception(r):
            return r.json()
        return None

    def get_details(self, amp, timeout_dict=None):
        r = self.get(amp, "details", timeout_dict=timeout_dict)
        if exc.check_exception(r):
            return r.json()
        return None

    def get_all_listeners(self, amp):
        r = self.get(amp, "listeners")
        if exc.check_exception(r):
            return r.json()
        return None

    def plug_network(self, amp, port):
        r = self.post(amp, 'plug/network',
                      json=port)
        return exc.check_exception(r)

    def plug_vip(self, amp, vip, net_info):
        r = self.post(amp,
                      f'plug/vip/{vip}',
                      json=net_info)
        return exc.check_exception(r)

    def upload_vrrp_config(self, amp, config):
        r = self.put(amp, 'vrrp/upload', data=config)
        return exc.check_exception(r)

    def _vrrp_action(self, action, amp, timeout_dict=None):
        r = self.put(amp, f'vrrp/{action}',
                     timeout_dict=timeout_dict)
        return exc.check_exception(r)

    def get_interface(self, amp, ip_addr, timeout_dict=None, log_error=True):
        r = self.get(amp, f'interface/{ip_addr}',
                     timeout_dict=timeout_dict)
        return exc.check_exception(r, log_error=log_error).json()

    # The function is used for all LVS-supported protocol listener (UDP, SCTP)
    def upload_udp_config(self, amp, listener_id, config, timeout_dict=None):
        r = self.put(
            amp,
            f'listeners/{amp.id}/{listener_id}/udp_listener', timeout_dict,
            data=config)
        return exc.check_exception(r)

    def check_udp_guard(self, amp, timeout_dict=None):
        response = self.get(amp, 'udp_guard', timeout_dict=timeout_dict,
                            retry_404=False)
        exc.check_exception(response)
        if response.status_code != 200 or response.json() != {
                'udp_packet_drop_v1': True}:
            raise driver_except.AmpDriverNotImplementedError()

    def stage_udp_guard(self, amp, listener_id, config, guard,
                        timeout_dict=None):
        response = self.put(
            amp, f'listeners/{listener_id}/udp_guard',
            timeout_dict=timeout_dict, retry_404=False,
            json={'configuration': config, 'guard': guard})
        exc.check_exception(response)
        if response.status_code != 200:
            raise driver_except.ListenerProvisioningError()

    def activate_udp_guard(self, amp, listener_id, timeout_dict=None):
        response = self._action(consts.AMP_ACTION_RELOAD, amp, listener_id,
                                timeout_dict=timeout_dict)
        if (response.status_code != 202 or
                response.headers.get('X-Octavia-UDP-Guard') != '1'):
            raise driver_except.ListenerProvisioningError()

    def delete_guarded_udp_listener(self, amp, listener_id):
        response = self.delete(amp, f'listeners/{listener_id}',
                               retry_404=False)
        exc.check_exception(response)
        if (response.status_code != 200 or
                response.headers.get('X-Octavia-UDP-Guard') != '1'):
            raise driver_except.ListenerProvisioningError()

    def close_legacy_udp_listener(self, amp, listener_id, timeout_dict=None):
        def observe():
            response = self.get(amp, 'listeners', timeout_dict=timeout_dict)
            if response.status_code != 200:
                raise driver_except.ListenerProvisioningError()
            inventory = response.json()
            if not isinstance(inventory, list) or any(
                    not isinstance(item, dict) or 'uuid' not in item
                    for item in inventory):
                raise driver_except.ListenerProvisioningError()
            return [item for item in inventory if item['uuid'] == listener_id]

        observed = observe()
        if observed:
            if len(observed) != 1 or observed[0].get('type') != 'UDP':
                raise driver_except.ListenerProvisioningError()
            response = self._action(consts.AMP_ACTION_STOP, amp, listener_id,
                                    timeout_dict=timeout_dict)
            if response.status_code != 202:
                raise driver_except.ListenerProvisioningError()
            if not any(item.get('status') == consts.OFFLINE
                       for item in observe()):
                raise driver_except.ListenerProvisioningError()
            response = self.delete(amp, f'listeners/{listener_id}',
                                   timeout_dict=timeout_dict, retry_404=False)
            if response.status_code != 200:
                raise driver_except.ListenerProvisioningError()
        if observe():
            raise driver_except.ListenerProvisioningError()

    def update_agent_config(self, amp, agent_config, timeout_dict=None):
        r = self.put(amp, 'config', timeout_dict, data=agent_config)
        return exc.check_exception(r)

    def set_interface_rules(self, amp, ip_address, rules, timeout_dict=None):
        r = self.put(amp, f'interface/{ip_address}/rules', timeout_dict,
                     json=rules)
        return exc.check_exception(r)
