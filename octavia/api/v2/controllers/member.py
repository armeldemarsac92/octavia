#    Copyright 2014 Rackspace
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

from contextlib import ExitStack
import hashlib
import ipaddress
import json

from octavia_lib.api.drivers import data_models as driver_dm
from oslo_db import exception as odb_exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import uuidutils
from pecan import request as pecan_request
from sqlalchemy.orm import exc as sa_exception
from wsme import types as wtypes
from wsmeext import pecan as wsme_pecan

from octavia.api.drivers import driver_factory
from octavia.api.drivers import utils as driver_utils
from octavia.api.v2.controllers import base
from octavia.api.v2.types import member as member_types
from octavia.common import constants
from octavia.common import data_models
from octavia.common import exceptions
from octavia.common import validate
from octavia.db import prepare as db_prepare
from octavia.i18n import _


LOG = logging.getLogger(__name__)


class MemberController(base.BaseController):
    RBAC_TYPE = constants.RBAC_MEMBER

    def __init__(self, pool_id):
        super().__init__()
        self.pool_id = pool_id

    @wsme_pecan.wsexpose(member_types.MemberRootResponse, wtypes.text,
                         [wtypes.text], ignore_extra_args=True)
    def get(self, id, fields=None):
        """Gets a single pool member's details."""
        context = pecan_request.context.get('octavia_context')

        with context.session.begin():
            member = self._get_db_member(
                context.session,
                id,
                show_deleted=False
            )

            self._auth_validate_action(context, member.project_id,
                                       constants.RBAC_GET_ONE)

            self._validate_pool_id(id, member.pool_id)

            result = member_types.MemberResponse.from_db_obj(member)

        if fields is not None:
            result = self._filter_fields([result], fields)[0]
        return member_types.MemberRootResponse(member=result)

    @wsme_pecan.wsexpose(member_types.MembersRootResponse, [wtypes.text],
                         ignore_extra_args=True)
    def get_all(self, fields=None):
        """Lists all pool members of a pool."""
        pcontext = pecan_request.context
        context = pcontext.get('octavia_context')

        with context.session.begin():
            pool = self._get_db_pool(
                context.session,
                self.pool_id,
                show_deleted=False
            )

            self._auth_validate_action(context, pool.project_id,
                                       constants.RBAC_GET_ALL)

            members, links = self.repositories.member.get_all_API_list(
                context.session, show_deleted=False, pool_id=self.pool_id,
                pagination_helper=pcontext.get(constants.PAGINATION_HELPER))

            result = [
                member_types.MemberResponse.from_db_obj(member)
                for member in members
            ]

        if fields is not None:
            result = self._filter_fields(result, fields)
        return member_types.MembersRootResponse(
            members=result, members_links=links)

    def _get_affected_listener_ids(self, session, member=None):
        """Gets a list of all listeners this request potentially affects."""
        if member:
            listener_ids = [li.id for li in member.pool.listeners]
        else:
            pool = self._get_db_pool(session, self.pool_id)
            listener_ids = [li.id for li in pool.listeners]
        return listener_ids

    def _test_lb_and_listener_and_pool_statuses(
            self, session, member=None, *, pool=None, retry_batch=False,
            explicit_drop=False):
        """Verify load balancer is in a mutable state."""
        # We need to verify that any listeners referencing this member's
        # pool are also mutable
        pool = pool if pool is not None else self._get_db_pool(
            session, self.pool_id)
        # A failed managed batch retains a coherent desired graph and can be
        # retried by an authorized replacement of that same pool.
        failed_batch = (
            retry_batch and pool.provisioning_status == constants.ERROR and
            pool.tcp_member_batch_id == constants.TCP_MEMBER_BATCH_FAILED)
        if ((pool.provisioning_status not in constants.MUTABLE_STATUSES or
             pool.tcp_member_batch_id == constants.TCP_MEMBER_BATCH_FAILED) and
                not failed_batch):
            raise exceptions.ImmutableObject(resource='Pool', id=self.pool_id)
        load_balancer_id = pool.load_balancer_id
        if not self.repositories.test_and_set_lb_and_listeners_prov_status(
                session, load_balancer_id,
                constants.PENDING_UPDATE, constants.PENDING_UPDATE,
                listener_ids=self._get_affected_listener_ids(session, member),
                pool_id=self.pool_id):
            LOG.info("Member cannot be created or modified because the "
                     "Load Balancer is in an immutable state")
            raise exceptions.ImmutableObject(resource='Load Balancer',
                                             id=load_balancer_id)
        if pool.protocol == constants.PROTOCOL_UDP and not explicit_drop:
            # Enrollment and stock writes share the load balancer lock.
            # Check current state beyond the request's initial DB snapshot.
            current = self.repositories.pool.get_on_load_balancer_for_update(
                session, load_balancer_id, pool.project_id, self.pool_id)
            if current.udp_packet_drop is not None:
                raise exceptions.ValidationException(detail=_(
                    'Members of a managed UDP pool require a full batch '
                    'with udp_packet_drop.'))

    def _validate_tcp_tls_member_changes(self, session, driver, pool, changes):
        if pool.protocol != constants.PROTOCOL_TCP:
            return
        # Member writes and pool trust changes hold the same LB lock. Read
        # the current transport after its acquisition, including concurrent
        # enrollment of a previously unprotected TCP pool.
        transport = self.repositories.pool.get_transport_for_update(
            session, pool.id)
        if not transport.enabled:
            return
        capabilities = driver_utils.gateway_capabilities(driver)
        backend_auth_withdrawn = (
            transport.backend_tls_hostname is not None and
            constants.GATEWAY_CAPABILITY_TCP_TLS_BACKEND_AUTH not in
            capabilities)
        mixed_mode_withdrawn = (
            constants.GATEWAY_CAPABILITY_TCP_TLS_MIXED_MODE not in
            capabilities and self.repositories.l7policy.get_policy_using_pool(
                session, pool.id, tcp_tls_termination=None,
                tcp_tls_mixed_mode=True))
        if not (backend_auth_withdrawn or mixed_mode_withdrawn):
            return
        member_ids = [member_id for member_id, _ in changes if member_id]
        current = self.repositories.member.get_routing_for_update(
            session, pool.id, member_ids)
        for member_id, desired in changes:
            previous = current.get(member_id)
            enabled = desired.get('enabled',
                                  previous.enabled if previous else True)
            previous_weight = previous.weight if previous else None
            if previous_weight is None:
                previous_weight = constants.DEFAULT_WEIGHT
            weight = desired.get('weight', previous_weight)
            if weight is None:
                weight = constants.DEFAULT_WEIGHT
            if enabled is False or weight == 0:
                continue
            if (previous is None or not previous.enabled or
                    weight > previous_weight or
                    (previous.backup and desired.get('backup') is False) or
                    any(field in desired and
                        desired[field] != getattr(previous, field)
                        for field in ('monitor_address', 'monitor_port',
                                      'subnet_id'))):
                if backend_auth_withdrawn:
                    driver_utils.require_tcp_tls_backend_auth(driver)
                if mixed_mode_withdrawn:
                    driver_utils.require_tcp_tls_mixed_mode(driver)

    def _validate_create_member(self, lock_session, member_dict):
        """Validate creating member on pool."""
        try:
            ret = self.repositories.member.create(lock_session, **member_dict)
            lock_session.flush()
            return ret
        except odb_exceptions.DBDuplicateEntry as e:
            raise exceptions.DuplicateMemberEntry(
                ip_address=member_dict.get('ip_address'),
                port=member_dict.get('protocol_port')) from e
        except odb_exceptions.DBReferenceError as e:
            raise exceptions.InvalidOption(value=member_dict.get(e.key),
                                           option=e.key) from e
        except odb_exceptions.DBError as e:
            raise exceptions.APIException() from e
        return None

    def _validate_pool_id(self, member_id, db_member_pool_id):
        if db_member_pool_id != self.pool_id:
            raise exceptions.NotFound(resource='Member', id=member_id)

    @wsme_pecan.wsexpose(member_types.MemberRootResponse,
                         body=member_types.MemberRootPOST, status_code=201)
    def post(self, member_):
        """Creates a pool member on a pool."""
        member = member_.member
        context = pecan_request.context.get('octavia_context')

        flavor_dict = {}
        context.session.begin()
        try:
            pool = self.repositories.pool.get_orm(
                context.session,
                id=self.pool_id
            )
            member.project_id, provider = self._get_lb_project_id_provider(
                context.session, pool.load_balancer_id)
            if pool.load_balancer.flavor_id:
                try:
                    flavor_dict = (
                        self.repositories.flavor.get_flavor_metadata_dict(
                            context.session, pool.load_balancer.flavor_id))
                except sa_exception.NoResultFound:
                    LOG.error("load balancer has a flavor ID: %s that was not "
                              "found in the database. Assuming no flavor.",
                              pool.load_balancer.flavor_id)

            self._auth_validate_action(context, member.project_id,
                                       constants.RBAC_POST)

            validate.ip_not_reserved(member.address)

            # Validate member subnet
            if (member.subnet_id and
                    not validate.subnet_exists(
                        member.subnet_id,
                        context=context
                    )):
                raise exceptions.NotFound(
                    resource='Subnet',
                    id=member.subnet_id
                )

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            if self.repositories.check_quota_met(
                    context.session,
                    data_models.Member,
                    member.project_id):
                raise exceptions.QuotaException(
                    resource=data_models.Member._name())

            db_member_dict = member.to_dict(render_unsets=True)

            # Validate and store port SR-IOV vnic_type
            request_sriov = db_member_dict.pop('request_sriov')
            if (request_sriov and not
                    flavor_dict.get(constants.ALLOW_MEMBER_SRIOV, False)):
                raise exceptions.MemberSRIOVDisabled
            if request_sriov:
                db_member_dict[constants.VNIC_TYPE] = (
                    constants.VNIC_TYPE_DIRECT)
            else:
                db_member_dict[constants.VNIC_TYPE] = (
                    constants.VNIC_TYPE_NORMAL)

            member_dict = db_prepare.create_member(db_member_dict,
                                                   self.pool_id,
                                                   bool(pool.health_monitor))

            self._test_lb_and_listener_and_pool_statuses(context.session)

            self._validate_tcp_tls_member_changes(
                context.session, driver, pool, [(None, member_dict)])
            db_member = self._validate_create_member(context.session,
                                                     member_dict)

            # Prepare the data for the driver data model
            provider_member = (
                driver_utils.db_member_to_provider_member(db_member))

            # Dispatch to the driver
            LOG.info("Sending create Member %s to provider %s",
                     db_member.id, driver.name)
            driver_utils.call_provider(
                driver.name, driver.member_create, provider_member)

            context.session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                context.session.rollback()

        with context.session.begin():
            member = self._get_db_member(context.session, db_member.id)
            result = member_types.MemberResponse.from_db_obj(member)

        return member_types.MemberRootResponse(member=result)

    def _graph_create(self, lock_session, member_dict):
        pool = self.repositories.pool.get_orm(lock_session, id=self.pool_id)

        # Validate and store port SR-IOV vnic_type
        request_sriov = member_dict.pop('request_sriov')
        flavor_dict = {}
        if pool.load_balancer.flavor_id:
            try:
                flavor_dict = (
                    self.repositories.flavor.get_flavor_metadata_dict(
                        lock_session, pool.load_balancer.flavor_id))
            except sa_exception.NoResultFound:
                LOG.error("load balancer has a flavor ID: %s that was not "
                          "found in the database. Assuming no flavor.",
                          pool.load_balancer.flavor_id)
        if (request_sriov and not
                flavor_dict.get(constants.ALLOW_MEMBER_SRIOV, False)):
            raise exceptions.MemberSRIOVDisabled

        if request_sriov:
            member_dict[constants.VNIC_TYPE] = constants.VNIC_TYPE_DIRECT
        else:
            member_dict[constants.VNIC_TYPE] = constants.VNIC_TYPE_NORMAL

        member_dict = db_prepare.create_member(
            member_dict, self.pool_id, bool(pool.health_monitor))
        db_member = self._validate_create_member(lock_session, member_dict)

        return db_member

    def _set_default_on_none(self, member):
        """Reset settings to their default values if None/null was passed in

        A None/null value can be passed in to clear a value. PUT values
        that were not provided by the user have a type of wtypes.UnsetType.
        If the user is attempting to clear values, they should either
        be set to None (for example in the name field) or they should be
        reset to their default values.
        This method is intended to handle those values that need to be set
        back to a default value.
        """
        if member.backup is None:
            member.backup = False
        if member.weight is None:
            member.weight = constants.DEFAULT_WEIGHT

    @wsme_pecan.wsexpose(member_types.MemberRootResponse,
                         wtypes.text, body=member_types.MemberRootPUT,
                         status_code=200)
    def put(self, id, member_):
        """Updates a pool member."""
        member = member_.member
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_member = self._get_db_member(context.session, id,
                                            show_deleted=False)
            pool = self.repositories.pool.get_orm(context.session,
                                                  id=db_member.pool_id)
            project_id, provider = self._get_lb_project_id_provider(
                context.session, pool.load_balancer_id)

            self._auth_validate_action(context, project_id, constants.RBAC_PUT)

            self._validate_pool_id(id, db_member.pool_id)

            self._set_default_on_none(member)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            self._test_lb_and_listener_and_pool_statuses(context.session,
                                                         member=db_member)

            # Prepare the data for the driver data model
            member_dict = member.to_dict(render_unsets=False)
            self._validate_tcp_tls_member_changes(
                context.session, driver, pool, [(id, member_dict)])
            member_dict['id'] = id
            provider_member_dict = (
                driver_utils.member_dict_to_provider_dict(member_dict))

            # Also prepare the baseline object data
            old_provider_member = driver_utils.db_member_to_provider_member(
                db_member)

            # Dispatch to the driver
            LOG.info("Sending update Member %s to provider %s", id,
                     driver.name)
            driver_utils.call_provider(
                driver.name, driver.member_update,
                old_provider_member,
                driver_dm.Member.from_dict(provider_member_dict))

            # Update the database to reflect what the driver just accepted
            member.provisioning_status = constants.PENDING_UPDATE
            db_member_dict = member.to_dict(render_unsets=False)
            self.repositories.member.update(context.session, id,
                                            **db_member_dict)

        # Force SQL alchemy to query the DB, otherwise we get inconsistent
        # results
        context.session.expire_all()

        with context.session.begin():
            member = self._get_db_member(context.session, id)
            result = member_types.MemberResponse.from_db_obj(member)

        return member_types.MemberRootResponse(member=result)

    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, id):
        """Deletes a pool member."""
        context = pecan_request.context.get('octavia_context')
        with context.session.begin():
            db_member = self._get_db_member(context.session, id,
                                            show_deleted=False)

            pool = self.repositories.pool.get_orm(context.session,
                                                  id=db_member.pool_id)
            project_id, provider = self._get_lb_project_id_provider(
                context.session, pool.load_balancer_id)

            self._auth_validate_action(
                context,
                project_id,
                constants.RBAC_DELETE
            )

            self._validate_pool_id(id, db_member.pool_id)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            self._test_lb_and_listener_and_pool_statuses(context.session,
                                                         member=db_member)
            self.repositories.member.update(
                context.session, db_member.id,
                provisioning_status=constants.PENDING_DELETE)

            LOG.info("Sending delete Member %s to provider %s", id,
                     driver.name)
            provider_member = (
                driver_utils.db_member_to_provider_member(db_member))
            driver_utils.call_provider(driver.name, driver.member_delete,
                                       provider_member)


class MembersController(MemberController):

    def __init__(self, pool_id):
        super().__init__(pool_id)

    def _validate_rejection_batch(self, driver, pool, rejection,
                                  additive_only, *, replay):
        if additive_only:
            raise exceptions.ValidationException(detail=_(
                'tcp_connection_rejection requires a full member batch.'))
        if pool.protocol != constants.PROTOCOL_TCP:
            raise exceptions.ValidationException(detail=_(
                'tcp_connection_rejection requires a TCP pool.'))
        supported = driver_factory.supports_tcp_connection_rejection(driver)
        advertised = (constants.GATEWAY_CAPABILITY_TCP_CONNECTION_REJECTION
                      in driver_utils.gateway_capabilities(driver))
        if not supported or (rejection is not None and
                             not (advertised or replay)):
            raise exceptions.ProviderUnsupportedOptionError(
                prov=driver.name, user_msg=_(
                    'TCP connection rejection is unavailable.'))

    def _validate_drop_batch(self, driver, lb, pool, drop, members,
                             additive_only):
        if additive_only or drop is None:
            raise exceptions.ValidationException(detail=_(
                'udp_packet_drop requires a full batch with a fraction.'))
        listeners = pool.listeners
        if (pool.protocol != constants.PROTOCOL_UDP or
                pool.lb_algorithm != constants.LB_ALGORITHM_ROUND_ROBIN or
                pool.health_monitor or pool.session_persistence or
                len(listeners) != 1 or
                listeners[0].protocol != constants.PROTOCOL_UDP or
                listeners[0].default_pool_id != pool.id or
                lb.additional_vips or
                ipaddress.ip_address(lb.vip.ip_address).version != 4 or
                any(ipaddress.ip_address(member.address).version != 4
                    for member in members)):
            raise exceptions.ValidationException(detail=_(
                'udp_packet_drop requires a single IPv4 VIP, one dedicated '
                'UDP listener, IPv4 members and a UDP round-robin pool '
                'without health monitoring or session persistence.'))
        if any(member.backup for member in members):
            raise exceptions.ValidationException(detail=_(
                'Managed UDP pools do not support backup members.'))
        if any(member.admin_state_up is None or member.weight is None or
               member.backup is None for member in members):
            raise exceptions.ValidationException(detail=_(
                'Managed UDP member enabled state and weight cannot be null.'))
        has_destination = any(member.admin_state_up and member.weight > 0
                              for member in members)
        full_drop = drop['numerator'] == drop['denominator']
        if full_drop == has_destination:
            raise exceptions.ValidationException(detail=_(
                'udp_packet_drop requires enabled members of positive '
                'weight exactly when some datagrams are admitted.'))
        if (constants.GATEWAY_CAPABILITY_UDP_PACKET_DROP not in
                driver_utils.gateway_capabilities(driver)):
            raise exceptions.ProviderUnsupportedOptionError(
                prov=driver.name,
                user_msg=_('UDP packet drop is unavailable.'))

    @staticmethod
    def _managed_batch_digest(option, value, members):
        body = {
            option: value,
            'members': [m.to_dict(render_unsets=False) for m in sorted(
                members, key=lambda m: (m.address, m.protocol_port))],
        }
        encoded = json.dumps(body, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _dispatch_managed_batch(driver, lb_id, pool_id, batch_id, *, udp):
        apply_batch = (driver.apply_udp_member_batch if udp else
                       driver.apply_tcp_member_batch)
        driver_utils.call_provider(
            driver.name, apply_batch, lb_id, pool_id, batch_id)

    @wsme_pecan.wsexpose(None, wtypes.text,
                         body=member_types.MembersRootPUT, status_code=202)
    def put(self, additive_only=False, members_=None):
        """Updates all members."""
        members = members_.members
        rejection = members_.tcp_connection_rejection
        drop = members_.udp_packet_drop
        explicit_rejection = rejection is not wtypes.Unset
        explicit_drop = drop is not wtypes.Unset
        if explicit_rejection and explicit_drop:
            raise exceptions.ValidationException(detail=_(
                'Specify one of tcp_connection_rejection or udp_packet_drop.'))
        explicit_batch = explicit_rejection or explicit_drop
        option = ('udp_packet_drop' if explicit_drop else
                  'tcp_connection_rejection')
        if explicit_batch and (members is wtypes.Unset or members is None):
            raise exceptions.ValidationException(detail=_(
                '%(option)s requires a complete members list.') %
                {'option': option})
        additive_only = strutils.bool_from_string(additive_only)
        context = pecan_request.context.get('octavia_context')

        session = context.session
        if explicit_batch:
            # Avoid a consistent read before taking the write lock.
            with session.begin():
                lb_id = self._get_db_pool(
                    session, self.pool_id, show_deleted=False).load_balancer_id

        with ExitStack() as render_locks, session.begin():
            if explicit_batch:
                lb = self.repositories.load_balancer.get_for_update(
                    session, lb_id)
                if lb is None or lb.provisioning_status == constants.DELETED:
                    raise exceptions.NotFound(resource='Pool', id=self.pool_id)
                project_id, provider = lb.project_id, lb.provider
                db_pool = (
                    self.repositories.pool.get_on_load_balancer_for_update(
                        session, lb_id, project_id, self.pool_id,
                        include_pending_delete=explicit_drop))
            else:
                db_pool = self._get_db_pool(session, self.pool_id)
                project_id, provider = self._get_lb_project_id_provider(
                    session, db_pool.load_balancer_id)

            # Check POST+PUT+DELETE since this operation is all of 'CUD'
            self._auth_validate_action(
                context,
                project_id,
                constants.RBAC_POST
            )
            self._auth_validate_action(context, project_id, constants.RBAC_PUT)
            if not additive_only:
                self._auth_validate_action(context, project_id,
                                           constants.RBAC_DELETE)

            # Load the driver early as it also provides validation
            driver = driver_factory.get_driver(provider)

            managed_batch = False
            replace_pending_udp = False
            if explicit_batch:
                self._auth_validate_action(
                    context, project_id, constants.RBAC_PUT,
                    rbac_type=constants.RBAC_POOL)
                operation = lb.tcp_member_batch or {}
                pending = self.repositories.load_balancer.tcp_batch_pending(lb)
                digest = self._managed_batch_digest(
                    option, drop if explicit_drop else rejection, members)
                replay = (pending and
                          operation.get('pool_id') == self.pool_id and
                          operation.get('digest') == digest)
                pending_udp = (
                    self.repositories.load_balancer.pending_udp_pool_operation(
                        lb, self.pool_id) if explicit_drop else None)
                replace_pending_udp = bool(
                    pending_udp and pending_udp.get('action') is None and
                    db_pool.provisioning_status == constants.PENDING_UPDATE and
                    db_pool.tcp_member_batch_id == pending_udp['id'])
                if explicit_drop:
                    replay = replay and replace_pending_udp
                if pending and not (replay or replace_pending_udp):
                    raise exceptions.ImmutableObject(
                        resource='Load Balancer', id=lb_id)
                if explicit_drop:
                    self._validate_drop_batch(
                        driver, lb, db_pool, drop, members, additive_only)
                else:
                    self._validate_rejection_batch(
                        driver, db_pool, rejection, additive_only,
                        replay=replay)
                if replace_pending_udp:
                    driver_utils.require_listener_render_lock(
                        render_locks, lb_id)
                if replay:
                    self._dispatch_managed_batch(
                        driver, lb_id, db_pool.id, operation['id'],
                        udp=explicit_drop)
                    return
                if replace_pending_udp:
                    # Member CRUD fences the previous receipt. Clear it while
                    # holding both locks and commit only the replacement.
                    lb.tcp_member_batch = None
                managed_batch = (
                    explicit_drop or rejection is not None or
                    db_pool.tcp_connection_rejection is not None or
                    db_pool.tcp_member_batch_id ==
                    constants.TCP_MEMBER_BATCH_FAILED)
            if not replace_pending_udp:
                self._test_lb_and_listener_and_pool_statuses(
                    session, pool=db_pool if explicit_batch else None,
                    retry_batch=managed_batch, explicit_drop=explicit_drop)
            if managed_batch:
                old_members = self.repositories.member.get_batch_for_update(
                    session, db_pool.id)
            else:
                # Reload after locking the load balancer.
                db_pool = self._get_db_pool(session, self.pool_id)
                old_members = db_pool.members

            old_member_uniques = {
                (m.ip_address, m.protocol_port): m.id for m in old_members}
            new_member_uniques = [
                (m.address, m.protocol_port) for m in members]

            # Find members that are brand new or updated
            new_members = []
            updated_members = []
            updated_member_uniques = set()
            for m in members:
                key = (m.address, m.protocol_port)
                if key not in old_member_uniques:
                    validate.ip_not_reserved(m.address)
                    new_members.append(m)
                else:
                    m.id = old_member_uniques[key]
                    if key in updated_member_uniques:
                        LOG.error("Member %s is updated multiple times in "
                                  "the same batch request.", m.id)
                        raise exceptions.ValidationException(
                            detail=_("Member must be updated only once in the "
                                     "same request."))
                    updated_member_uniques.add(key)
                    updated_members.append(m)

            if db_pool.protocol == constants.PROTOCOL_TCP:
                changes = [(None, item.to_dict(render_unsets=False))
                           for item in new_members]
                changes.extend((item.id, item.to_dict(render_unsets=False))
                               for item in updated_members)
                self._validate_tcp_tls_member_changes(
                    context.session, driver, db_pool, changes)

            # Find members that are deleted
            deleted_members = []
            for m in old_members:
                if (m.ip_address, m.protocol_port) not in new_member_uniques:
                    deleted_members.append(m)

            if not (managed_batch or deleted_members or new_members or
                    updated_members):
                LOG.info("Member batch update is a noop, rolling back and "
                         "returning early.")
                context.session.rollback()
                return

            if managed_batch:
                previous_count = sum(
                    not m.tcp_batch_quota_released and
                    m.provisioning_status != constants.DELETED
                    for m in old_members)
                member_count_diff = len(members) - previous_count
            elif additive_only:
                member_count_diff = len(new_members)
            else:
                member_count_diff = len(new_members) - len(deleted_members)
            if member_count_diff > 0 and self.repositories.check_quota_met(
                    context.session, data_models.Member,
                    db_pool.project_id, count=member_count_diff):
                raise exceptions.QuotaException(
                    resource=data_models.Member._name())
            if managed_batch and member_count_diff < 0:
                self.repositories.decrement_quota(
                    context.session, data_models.Member, db_pool.project_id,
                    quantity=-member_count_diff)

            provider_members = []
            valid_subnets = set()
            # Create new members
            for m in new_members:
                # NOTE(mnaser): In order to avoid hitting the Neutron API hard
                # when creating many new members, we cache the
                # validation results. We also validate new
                # members only since subnet ID is immutable.
                # If the member doesn't have a subnet, or the subnet is
                # already valid, move on. Run validate and add it to
                # cache otherwise.
                if m.subnet_id and m.subnet_id not in valid_subnets:
                    # If the subnet does not exist,
                    # raise an exception and get out.
                    if not validate.subnet_exists(
                            m.subnet_id, context=context):
                        raise exceptions.NotFound(
                            resource='Subnet', id=m.subnet_id)

                    # Mark the subnet as valid for future runs.
                    valid_subnets.add(m.subnet_id)

                m = m.to_dict(render_unsets=False)
                m['project_id'] = db_pool.project_id
                created_member = self._graph_create(context.session, m)
                if not managed_batch:
                    provider_members.append(
                        driver_utils.db_member_to_provider_member(
                            created_member))
            # Update old members
            for m in updated_members:
                m.provisioning_status = constants.PENDING_UPDATE
                m.project_id = db_pool.project_id
                db_member_dict = m.to_dict(render_unsets=False)
                db_member_dict.pop('id')
                # We don't allow updating the vnic_type
                # TODO(johnsom) Give the user an error once we change the
                #               wsme type for batch member update to not use
                #               the MemberPOST type
                db_member_dict.pop(constants.REQUEST_SRIOV)
                if managed_batch:
                    db_member_dict['tcp_batch_quota_released'] = False
                self.repositories.member.update(
                    context.session, m.id, **db_member_dict)

                if not managed_batch:
                    m.pool_id = self.pool_id
                    provider_members.append(
                        driver_utils.db_member_to_provider_member(m))
            # Delete old members
            for m in deleted_members:
                if additive_only:
                    # Members are appended to the dict and their status remains
                    # unchanged, because they are logically "untouched".
                    db_member_dict = m.to_dict(render_unsets=False)
                    db_member_dict.pop('id')
                    m.pool_id = self.pool_id
                    provider_members.append(
                        driver_utils.db_member_to_provider_member(m))
                else:
                    # Members are changed to PENDING_DELETE and not passed.
                    delete_values = {
                        'provisioning_status': constants.PENDING_DELETE}
                    if managed_batch:
                        delete_values['tcp_batch_quota_released'] = True
                    self.repositories.member.update(
                        session, m.id, **delete_values)

            # Dispatch to the driver
            LOG.info("Sending Pool %s batch member update to provider %s",
                     db_pool.id, driver.name)
            if managed_batch:
                setattr(db_pool, option, drop if explicit_drop else rejection)
                db_pool.tcp_member_batch_id = uuidutils.generate_uuid()
                operation = {
                    'id': db_pool.tcp_member_batch_id,
                    'pool_id': db_pool.id,
                    'listener_ids': [li.id for li in db_pool.listeners],
                    'digest': digest,
                    'phase': constants.TCP_MEMBER_BATCH_PENDING,
                }
                if explicit_drop:
                    operation['protocol'] = constants.PROTOCOL_UDP
                lb.tcp_member_batch = operation
                self._dispatch_managed_batch(
                    driver, lb_id, db_pool.id, db_pool.tcp_member_batch_id,
                    udp=explicit_drop)
            else:
                driver_utils.call_provider(
                    driver.name, driver.member_batch_update, db_pool.id,
                    provider_members)
