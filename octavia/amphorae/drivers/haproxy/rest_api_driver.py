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
                                 timeout_dict=None):
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
            return

        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        with (
            self._otlp_render_results(loadbalancer) as tracing_options,
            self._http_cookie_render_results(loadbalancer) as cookie_options
        ):
            if opted_in or fallback or withdrawn:
                peers = {amp.id: amp for amp in loadbalancer.amphorae
                         if amp.status != consts.DELETED}
                peers[amphora.id] = amphora
                self._update_protected_tls_listeners(
                    loadbalancer, [amphora], peers.values(), protected,
                    fallback, withdrawn, timeout_dict=timeout_dict,
                    **tracing_options, **cookie_options)
            else:
                self._update_amphora_listeners(
                    loadbalancer, amphora, timeout_dict=timeout_dict,
                    **tracing_options, **cookie_options)

    @staticmethod
    def _active_otlp_listeners(loadbalancer):
        return {
            listener.id: listener.otlp_tracing
            for listener in loadbalancer.listeners
            if (loadbalancer.enabled and listener.enabled and
                isinstance(getattr(listener, 'otlp_tracing', None), dict) and
                listener.provisioning_status not in (
                    consts.PENDING_DELETE, consts.DELETED))
        }

    @contextlib.contextmanager
    def _http_cookie_render_results(self, loadbalancer):
        policies = {}
        if loadbalancer.enabled:
            for listener in loadbalancer.listeners:
                if not listener.enabled or listener.provisioning_status in (
                        consts.PENDING_DELETE, consts.DELETED):
                    continue
                for pool in listener.pools:
                    persistence = pool.session_persistence
                    timeout = getattr(
                        persistence, 'cookie_absolute_timeout_ms', None)
                    if (pool.enabled and type(timeout) is int and
                            pool.provisioning_status not in (
                                consts.PENDING_DELETE, consts.DELETED)):
                        policies[pool.id] = (
                            persistence.cookie_name, timeout,
                            persistence.cookie_scope)
        if not policies:
            yield {}
            return

        votes = {}
        completed = False
        try:
            yield {'http_cookie_observed': votes}
            completed = True
        finally:
            self._publish_http_cookie_results(
                loadbalancer, policies, votes, completed)

    def _publish_http_cookie_results(self, loadbalancer, policies, votes,
                                     completed):
        # An acknowledged degradation is observable even if a subsequent
        # peer fails. Recovery requires every member of the allocated topology.
        expected = set()
        if completed:
            try:
                expected = {amp.id for amp in
                            self._allocated_amphorae(loadbalancer)}
            except driver_except.ListenerProvisioningError:
                pass
        failed = {pool_id for pool_id in policies
                  if any(vote.get(pool_id) == consts.ERROR
                         for vote in votes.values())}
        recovered = {
            pool_id for pool_id in policies.keys() - failed
            if expected and all(votes.get(amp_id, {}).get(pool_id) ==
                                consts.ACTIVE for amp_id in expected)}
        if failed or recovered:
            with db_api.session().begin() as session:
                repo.PoolRepository().set_http_cookie_pool_statuses(
                    session, policies, failed=failed, recovered=recovered)

    @contextlib.contextmanager
    def _otlp_render_results(self, loadbalancer):
        listeners = self._active_otlp_listeners(loadbalancer)
        if not listeners:
            yield {}
            return
        results = {}
        expected = {amp.id for amp in loadbalancer.amphorae
                    if amp.status != consts.DELETED}
        paired = loadbalancer.topology == consts.TOPOLOGY_ACTIVE_STANDBY
        complete = len(expected) == 2 if paired else bool(expected)
        try:
            yield {'otlp_observed': results}
        finally:
            statuses = {}
            for listener_id, tracing in listeners.items():
                votes = {amp: result[listener_id]
                         for amp, result in results.items()
                         if listener_id in result}
                if consts.ERROR in votes.values():
                    statuses[listener_id] = (tracing, consts.ERROR)
                elif complete and expected.issubset(votes):
                    statuses[listener_id] = (tracing, consts.ACTIVE)
            if statuses:
                listener_repo = repo.ListenerRepository()
                peer_check = ({
                    'expected_pair': (loadbalancer.id, expected)
                } if paired else {})
                with db_api.session().begin() as session:
                    listener_repo.set_otlp_tracing_statuses(
                        session, statuses, **peer_check)

    def _update_amphora_listeners(
            self, loadbalancer, amphora, timeout_dict=None, *,
            amp_details=None, backend_tls_certs=None,
            frontend_tls_certs=None, closed_frontend=(),
            l7policy_activation=False, otlp_observed=None,
            tcp_batch_configs=None, http_cookie_observed=None):
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
        tracing_results = {}
        certs = dict(backend_tls_certs or {})
        frontend_tls_certs = frontend_tls_certs or {}
        listeners_to_update = []
        for listener in loadbalancer.listeners:
            LOG.debug("%s updating listener %s on amphora %s",
                      self.__class__.__name__, listener.id, amphora.id)
            if listener.protocol in consts.LVS_PROTOCOLS:
                if l7policy_activation or tcp_batch_configs is not None:
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

                tracing = getattr(listener, 'otlp_tracing', None)
                if (listener.enabled and loadbalancer.enabled and
                        isinstance(tracing, dict) and
                        listener.provisioning_status not in (
                            consts.PENDING_DELETE, consts.DELETED)):
                    if 'sampling' in tracing and amp_details is None:
                        client = self.clients[amphora.api_version]
                        amp_details = client.get_details(amphora)
                    if ('sampling' in tracing and
                            not jinja_combo.otlp_sampling_supported(
                                loadbalancer, amp_details)):
                        tracing_results[listener.id] = consts.ERROR
                    else:
                        pool_id = tracing['collector_pool_id']
                        if pool_id not in otlp_tls_certs:
                            otlp_tls_certs[pool_id] = (
                                self._process_otlp_collector_certs(
                                    listener, loadbalancer, amphora, pool_id))
                        closed = otlp_tls_certs[pool_id].get('closed')
                        if tcp_batch_configs is not None and closed:
                            raise driver_except.ListenerProvisioningError()
                        tracing_results[listener.id] = (
                            consts.ERROR if closed else consts.ACTIVE)
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
                    if l7policy_activation or tcp_batch_configs is not None:
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
                cookie_results = {}
                cookie_options = (
                    {'http_cookie_results': cookie_results}
                    if http_cookie_observed is not None else {})
                config = self.jinja_combo.build_config(
                    host_amphora=amphora, listeners=listeners_to_update,
                    tls_certs=certs,
                    haproxy_versions=haproxy_versions,
                    amp_details=amp_details, **tracing_options,
                    **cookie_options)
                configured = {listener.id for listener in listeners_to_update}
                tracing_results = {
                    listener_id: tracing_results[listener_id]
                    for listener_id in configured & tracing_results.keys()}
                if tcp_batch_configs is not None:
                    tcp_batch_configs.append(
                        (amphora, config, cookie_results, tracing_results))
                    return configured
                self.clients[amphora.api_version].upload_config(
                    amphora, loadbalancer.id, config,
                    timeout_dict=timeout_dict)
                self.clients[amphora.api_version].reload_listener(
                    amphora, loadbalancer.id, timeout_dict=timeout_dict)
                if http_cookie_observed is not None:
                    http_cookie_observed[amphora.id] = cookie_results
                if otlp_observed is not None:
                    otlp_observed[amphora.id] = tracing_results
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
        roles = {
            consts.TOPOLOGY_SINGLE: {consts.ROLE_STANDALONE},
            consts.TOPOLOGY_ACTIVE_STANDBY: {
                consts.ROLE_MASTER, consts.ROLE_BACKUP},
        }.get(loadbalancer.topology, set())
        if (not roles or len(amphorae) != len(roles) or
                {amp.role for amp in amphorae} != roles or
                len({amp.id for amp in amphorae}) != len(roles)):
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
        if (l7policy_activation or tcp_member_batch) and not amphorae:
            raise driver_except.ListenerProvisioningError()
        tcp_batch_configs = [] if tcp_member_batch else None
        batch_options = (
            {'tcp_batch_configs': tcp_batch_configs}
            if tcp_member_batch else {})
        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        with (
            self._otlp_render_results(loadbalancer) as tracing_options,
            self._http_cookie_render_results(loadbalancer) as cookie_options
        ):
            if (opted_in or fallback or withdrawn) and amphorae:
                recovered = self._update_protected_tls_listeners(
                    loadbalancer, amphorae, amphorae, protected, fallback,
                    withdrawn, l7policy_activation=l7policy_activation,
                    l7policy_restoration=l7policy_restoration,
                    **tracing_options, **batch_options, **cookie_options)
                if not tcp_member_batch:
                    return recovered
            else:
                for amphora in amphorae:
                    self._update_amphora_listeners(
                        loadbalancer, amphora,
                        l7policy_activation=l7policy_activation,
                        **tracing_options, **batch_options, **cookie_options)
            if tcp_member_batch:
                # Build every peer's combined config before uploading any
                # candidate. Validate all uploads before requesting a reload.
                for amphora, config, _, _ in tcp_batch_configs:
                    self.clients[amphora.api_version].upload_config(
                        amphora, loadbalancer.id, config)
                votes = cookie_options.get('http_cookie_observed')
                tracing_votes = tracing_options.get('otlp_observed')
                for amphora, _, cookie_results, tracing_results in (
                        tcp_batch_configs):
                    self.clients[amphora.api_version].reload_listener(
                        amphora, loadbalancer.id)
                    if votes is not None:
                        votes[amphora.id] = cookie_results
                    if tracing_votes is not None:
                        tracing_votes[amphora.id] = tracing_results

    def update_failover_listeners(self, loadbalancer, amphora_index,
                                  amphorae_status, timeout_dict=None):
        opted_in, protected = self._backend_tls_pools(loadbalancer)
        fallback, withdrawn = self._frontend_fallback_listeners(loadbalancer)
        # A paired exporter needs confirmations from the same graph snapshot.
        tracing_pair = (
            loadbalancer.topology == consts.TOPOLOGY_ACTIVE_STANDBY and
            bool(self._active_otlp_listeners(loadbalancer)))
        coordinated = opted_in or bool(fallback or withdrawn) or tracing_pair
        if coordinated and amphora_index == 0:
            peers = [amp for amp in loadbalancer.amphorae
                     if amp.status != consts.DELETED]
            unreachable = {
                amp.id for amp in peers
                if (amphorae_status.get(amp.id, {}).get(consts.UNREACHABLE) or
                    (tracing_pair and amp.id not in amphorae_status))
            }
            with (
                self._otlp_render_results(loadbalancer) as tracing_options,
                self._http_cookie_render_results(loadbalancer) as cookie_state
            ):
                self._update_protected_tls_listeners(
                    loadbalancer, [amp for amp in peers
                                   if amp.id not in unreachable],
                    peers, protected, fallback, withdrawn,
                    timeout_dict=timeout_dict,
                    unreachable=unreachable, coordinating_failover=True,
                    **tracing_options, **cookie_state)
        return coordinated

    @staticmethod
    def _backend_tls_pools(loadbalancer):
        opted_in = False
        pools = {}
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
        return opted_in, pools

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
            http_cookie_observed=None):
        # Preflight the pair and stage the TLS material before any reload.
        details = {}
        for amphora in peers if protected or fallback else amphorae:
            if amphora.id in unreachable:
                details[amphora.id] = {}
                continue
            try:
                self._populate_amphora_api_version(amphora, timeout_dict)
                client = self.clients[amphora.api_version]
                detail = client.get_details(amphora, timeout_dict=timeout_dict)
                details[amphora.id] = (
                    detail if isinstance(detail, dict) else {})
            except (driver_except.AmphoraDriverError, exc.APIException,
                    requests.RequestException, ValueError):
                details[amphora.id] = {}

        frontend_certs, closed_frontend = self._stage_frontend_client_auth(
            loadbalancer.id, amphorae, peers, details, fallback)
        if (closed_frontend and
                (tcp_batch_configs is not None or
                 (l7policy_activation and not l7policy_restoration))):
            raise driver_except.ListenerProvisioningError()

        certs = {amphora.id: {} for amphora in amphorae}
        closed = set()
        for pool_id, (listener, pool) in protected.items():
            required = [consts.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME]
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
                    material = {
                        amphora.id: self._process_pool_certs(
                            listener, pool, amphora, loadbalancer.id)
                        for amphora in peers
                    }
                except Exception as error:
                    LOG.warning('Backend TLS pool %s will close because its '
                                'TLS configuration could not be prepared '
                                '(%s).', pool_id, type(error).__name__)
                else:
                    for amphora in amphorae:
                        certs[amphora.id][pool_id] = material[amphora.id]
                    continue
            closed.add(pool_id)
            for amphora in amphorae:
                certs[amphora.id][pool_id] = {'closed': True}

        if tcp_batch_configs is not None and closed:
            raise driver_except.ListenerProvisioningError()

        reload_errors = {}
        reloaded_listeners = []
        tracing_options = {}
        if otlp_observed is not None:
            tracing_options['otlp_observed'] = otlp_observed
        if tcp_batch_configs is not None:
            tracing_options['tcp_batch_configs'] = tcp_batch_configs
        if http_cookie_observed is not None:
            tracing_options['http_cookie_observed'] = http_cookie_observed
        for amphora in amphorae:
            try:
                configured = self._update_amphora_listeners(
                    loadbalancer, amphora, timeout_dict=timeout_dict,
                    amp_details=details[amphora.id],
                    backend_tls_certs=certs[amphora.id],
                    frontend_tls_certs=frontend_certs[amphora.id],
                    closed_frontend=closed_frontend,
                    l7policy_activation=l7policy_activation,
                    **tracing_options)
                reloaded_listeners.append(configured)
            except Exception as error:
                if tcp_batch_configs is not None:
                    raise
                LOG.warning('Could not reload listeners on amphora %s (%s).',
                            amphora.id, type(error).__name__)
                reload_errors[amphora.id] = error

        if tcp_batch_configs is not None:
            return

        recovered = set()
        restored_frontend = set()
        if not reload_errors and amphorae and len(amphorae) == len(peers):
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
        if l7policy_activation:
            return recovered

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
        if non_lvs_listener_count > 0:
            # We have other listeners, so just update is fine.
            # TODO(rm_work): This is a little inefficient since this duplicates
            # a lot of the detection logic that has already been done, but it
            # is probably safer to reuse the existing code-path.
            self.update_amphora_listeners(listener.load_balancer, amphora)
        else:
            # Deleting the last listener, so really do the delete
            self.clients[amphora.api_version].delete_listener(
                amphora, listener.load_balancer.id)

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

    def _process_pool_certs(self, listener, pool, amphora, obj_id):
        pool_cert_dict = {}
        if utils.is_disabled_backend_tls_pool(pool):
            return pool_cert_dict
        hostname = getattr(pool, 'backend_tls_hostname', None)
        if utils.is_protected_backend_tls_pool(pool) and (
                not validate.is_exact_sni_name(hostname) or
                pool.protocol not in (consts.PROTOCOL_HTTP,
                                      consts.PROTOCOL_TCP) or
                pool.tls_enabled is not True or
                not pool.ca_tls_certificate_id or
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

    def _action(self, action, amp, object_id, timeout_dict=None):
        r = self.put(
            amp, f'loadbalancer/{object_id}/{action}',
            timeout_dict=timeout_dict)
        return exc.check_exception(r)

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
