..
      Copyright 2018 Rackspace, US Inc.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Amphora
=======

This is the reference driver for Octavia, meaning it is used for testing the
Octavia code base. It is an open source, scalable, and highly available load
balancing provider.
It adopts taskflow jobboard feature and saves task states into the persistence
backend, this allows to continue task execution if controller work was
interrupted.

Default provider name: **amphora**

The driver package: https://pypi.org/project/octavia/

The driver source: https://opendev.org/openstack/octavia/

The documentation: https://docs.openstack.org/octavia/latest/

Where to report issues with the driver: https://launchpad.net/octavia


.. _amphora-gateway-actions:

Gateway API actions in the Hibiscus build
-----------------------------------------

The Hibiscus build of Octavia adds fixed HTTP responses and weighted HTTP
targets to the Amphora provider. The API rejects new use of these actions
until the operator enables the provider by name in that region.

1. Leave ``[api_settings] enabled_gateway_action_providers`` empty during the
   upgrade. Apply the Octavia database migrations and install the paired
   Hibiscus builds of Octavia and octavia-lib on the region's API and worker
   services. Complete the upgrade of any other Octavia services that can
   operate on those load balancers.
2. Verify the Amphora images used for new load balancers, including spare
   instances and failover replacements. Upgrade the existing Amphorae for
   every fleet reachable through the provider name, including fleets selected
   via flavors or availability zones. The renderer requires HAProxy 2.2 or
   later. The local distribution tests used HAProxy 3.0.19.
3. Set the option on every Octavia API replica in the region and reload the
   service configuration.

   .. code-block:: ini

      [api_settings]
      enabled_gateway_action_providers = amphora

   Use the exact provider names enabled in ``enabled_provider_drivers``. Add
   the corresponding alias, such as ``octavia``, if clients in the region use
   it and its fleets are ready.
4. Use an authenticated request to check
   ``GET /v2/lbaas/providers/amphora/gateway_capabilities``. A ready Amphora
   provider returns ``fixed_http_responses_v1`` and
   ``weighted_http_targets_v1``.

To stop admitting new use, remove the provider name from the option on every
API replica. The patched workers continue to render existing configurations
and can process their removal. Before downgrading a worker or replacing an
Amphora with an incompatible image, clear listener defaults and convert or
delete the affected L7 policies. Wait for those operations to finish.
