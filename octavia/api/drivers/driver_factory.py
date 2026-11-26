# Copyright 2018 Rackspace, US Inc.
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

import copy

from octavia_lib.api.drivers import data_models as driver_dm
from oslo_config import cfg
from oslo_log import log as logging
from stevedore import driver as stevedore_driver
from wsme import types as wtypes

from octavia.common import exceptions

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
TCP_DEFAULT_POOL_TLS_PAYLOAD_AVAILABLE = hasattr(
    driver_dm.Listener(), 'tcp_default_pool_tls')
TCP_DEFAULT_TARGETS_PAYLOAD_AVAILABLE = all(
    hasattr(driver_dm.Listener(), attribute) for attribute in
    ('tcp_default_targets', 'tcp_default_targets_revision'))


def get_driver(provider):
    # If this came in None it must be a load balancer that existed before
    # provider support was added. These must be of type 'amphora' and not
    # whatever the current "default" is set to.
    if isinstance(provider, wtypes.UnsetType):
        provider = CONF.api_settings.default_provider_driver
    elif not provider:
        provider = 'amphora'

    if provider not in CONF.api_settings.enabled_provider_drivers:
        LOG.warning("Requested provider driver '%s' was not enabled in the "
                    "configuration file.", provider)
        raise exceptions.ProviderNotEnabled(prov=provider)

    try:
        driver = stevedore_driver.DriverManager(
            namespace='octavia.api.drivers',
            name=provider,
            invoke_on_load=True).driver
        driver.name = provider
    except Exception as e:
        LOG.error('Unable to load provider driver %s due to: %s',
                  provider, str(e))
        raise exceptions.ProviderNotFound(prov=provider)
    return driver


def supports_tcp_connection_rejection(driver):
    driver_class = driver if isinstance(driver, type) else type(driver)
    return getattr(
        driver_class, 'supports_tcp_connection_rejection', False) is True


def provider_supports_tcp_connection_rejection(provider):
    """Inspect the registered driver without creating an RPC client."""
    try:
        driver = stevedore_driver.DriverManager(
            namespace='octavia.api.drivers',
            name=provider or 'amphora', invoke_on_load=False).driver
    except RuntimeError:
        return False
    return supports_tcp_connection_rejection(driver)


def tcp_default_pool_tls_available(provider, driver=None):
    provider = provider or 'amphora'
    api = CONF.api_settings
    if (not TCP_DEFAULT_POOL_TLS_PAYLOAD_AVAILABLE or
            provider not in api.enabled_provider_drivers or
            provider not in api.enabled_tcp_default_pool_tls_providers or
            provider not in api.enabled_backend_tls_hostname_providers):
        return False
    if driver is None:
        # Listener readback needs the advertised support without an RPC client.
        try:
            driver = stevedore_driver.DriverManager(
                namespace='octavia.api.drivers', name=provider,
                invoke_on_load=False).driver
        except RuntimeError:
            return False
    supports_default_tls = getattr(
        driver, 'supports_tcp_default_pool_tls', False)
    supports_hostname = getattr(driver, 'supports_backend_tls_hostname', False)
    return supports_default_tls is True and supports_hostname is True


def tcp_weighted_default_pools_available(provider, driver=None):
    provider = provider or 'amphora'
    api = CONF.api_settings
    if (not TCP_DEFAULT_TARGETS_PAYLOAD_AVAILABLE or
            provider not in api.enabled_provider_drivers or
            provider not in api.enabled_tcp_weighted_default_pool_providers or
            provider not in api.enabled_backend_tls_hostname_providers):
        return False
    if driver is None:
        try:
            driver = stevedore_driver.DriverManager(
                namespace='octavia.api.drivers', name=provider,
                invoke_on_load=False).driver
        except RuntimeError:
            return False
    return (getattr(driver, 'supports_tcp_weighted_default_pools', False)
            is True and
            getattr(driver, 'supports_backend_tls_hostname', False) is True)


def supports_udp_packet_drop(driver, *, extended_weights=False):
    if getattr(type(driver), 'supports_udp_packet_drop', False) is not True:
        return False
    if extended_weights and getattr(
            type(driver), 'supports_udp_extended_member_weights',
            False) is not True:
        return False
    try:
        amphora_driver = stevedore_driver.DriverManager(
            namespace='octavia.amphora.drivers',
            name=CONF.controller_worker.amphora_driver,
            invoke_on_load=False).driver
    except RuntimeError:
        return False
    return (
        callable(getattr(amphora_driver, 'apply_udp_member_batch', None)) and
        (not extended_weights or getattr(
            amphora_driver, 'supports_udp_extended_member_weights',
            False) is True))


def remove_providers(providers):
    # Presumably these provider drivers failed to load, remove so they do not
    # show up in the available list
    override = copy.deepcopy(CONF.api_settings.enabled_provider_drivers)
    for provider in providers:
        override.pop(provider)
    CONF.set_override(
        "enabled_provider_drivers",
        override,
        group="api_settings")


def get_providers():
    return CONF.api_settings.enabled_provider_drivers
