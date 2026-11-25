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

from oslo_config import cfg
from oslo_log import log as logging
from stevedore import driver as stevedore_driver
from wsme import types as wtypes

from octavia.common import exceptions

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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


def supports_udp_packet_drop(driver):
    if getattr(type(driver), 'supports_udp_packet_drop', False) is not True:
        return False
    try:
        amphora_driver = stevedore_driver.DriverManager(
            namespace='octavia.amphora.drivers',
            name=CONF.controller_worker.amphora_driver,
            invoke_on_load=False).driver
    except RuntimeError:
        return False
    return callable(getattr(amphora_driver, 'apply_udp_member_batch', None))


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
