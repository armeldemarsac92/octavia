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
and can process their removal. Enabled matching rules require opt-in when
added or changed. Restoring the active state of a listener with a fixed
default or enabled extended policies also requires opt-in. Before downgrading
a worker or replacing an Amphora with an incompatible image, clear listener
defaults and convert or delete the affected L7 policies. Wait for those
operations to finish.


Request header operations in L7 policies
---------------------------------------

Request header operations are enabled separately for each provider name.
Keep ``[api_settings] enabled_request_header_operation_providers`` empty
during upgrades. Apply the request header operations database migration
and install matched Hibiscus builds of Octavia and octavia-lib on the
region's API and workers. Verify that the current, new and replacement Amphorae
for that provider run HAProxy 2.2 or later.

Set the exact enabled provider names on every Octavia API replica in the
region and reload the service configuration.

.. code-block:: ini

   [api_settings]
   enabled_request_header_operation_providers = amphora

An authenticated GET on the provider's ``gateway_capabilities`` endpoint
then returns ``request_header_operations_v1``. Existing
``enabled_gateway_action_providers`` settings continue to control fixed
responses and weighted targets.

Removing a provider from the request header option prevents new operations
and reactivation of stored operations. Patched workers keep rendering
live configurations while operators clear or retire those policies.


Response header operations in L7 policies
-----------------------------------------

Apply migration ``9372b8ac16d4`` and upgrade the Octavia API, workers and
octavia-lib. Amphorae for the provider need HAProxy 2.2 or later. Enable
response header operations on each API replica in the region with:

.. code-block:: ini

   [api_settings]
   enabled_response_header_operation_providers = amphora

The provider then advertises ``response_header_operations_v1``. Only the
winning L7 policy modifies its responses, including a programmed fixed
response. Operators can disable the option and clear existing lists.
Request and response header options can be enabled independently.


Structured HTTP redirects in L7 policies
---------------------------------------

Keep enrollment empty during the upgrade. Apply migration ``675c8279483a``
and install the matching octavia-lib with the structured ``L7Policy``
payload on API servers and workers. Octavia can run with the previous
regional octavia-lib during the rollout and suppresses the new capability
and its writes until the matching payload is installed. Upgrade the
provider's Amphora fleet before enrolling the provider on every regional
API replica. The renderer was qualified with HAProxy 3.0.19.

.. code-block:: ini

   [api_settings]
   enabled_http_request_redirect_providers = amphora

When a request matches a ``REDIRECT_REQUEST`` policy, Amphora evaluates
structured and legacy redirects in position order with forwarding policies.
Other requests follow the legacy HAProxy redirect phase. A client that
needs position-order resolution between a fixed-destination redirect and
forwarding can use ``REDIRECT_REQUEST`` with an explicit hostname and
effective scheme and port. The stock ``REJECT`` action continues to run in
HAProxy's deny phase.

Removing the provider from the list blocks creation and changes that
activate or modify structured redirects. Stored policies remain readable.
Operators can disable them, delete them or convert them to stock actions.
Disable the policy or listener before removing individual predicates from
an active redirect. Removing an enabled rule while another remains would
broaden the redirect. Patched workers continue rendering stored enabled
policies during retirement. Remove all structured policies before rolling
back octavia-lib or Octavia.


HTTP request URL rewrites in L7 policies
---------------------------------------

Apply migration ``36ab5d95ca27`` and upgrade Octavia, octavia-lib and the
Amphora fleet. Enroll the provider on every regional API replica only
after those upgrades. The renderer requires HAProxy 2.2 or newer.

.. code-block:: ini

   [api_settings]
   enabled_request_url_rewrite_providers = amphora

The provider advertises ``request_url_rewrite_v1`` when both the driver
and the installed octavia-lib support the field. The winning forwarding
policy can rewrite the HTTP hostname or path while preserving the query.
Routing uses the original hostname, path and headers. Request-header
operations run on the selected backend, followed by any URL rewrite.

Removing regional enrollment stops new settings and changes that
reactivate or expand a stored rewrite. Stored active rewrites continue
to run on patched workers. Disable or delete a policy, or clear
``request_url_rewrite`` with ``null``, during retirement. Clear existing
settings before rolling back the services or provider library.


Full-value exact request header matching
----------------------------------------

An L7 rule of type ``HTTP_HEADER_EXACT`` uses comparison ``EQUAL_TO`` on an
HTTP or terminated HTTPS listener. Its ``key`` is a case-insensitive HTTP
field name of up to 255 ASCII characters. Its ``value`` is a case-sensitive
literal of up to 4096 characters. Internal spaces, tabs and commas are
part of the value. Surrounding HTTP whitespace is excluded from the field
content. When a request carries repeated fields with the same name, an
exact match on any one occurrence satisfies the rule. The stock
``HEADER`` rule continues to compare individual comma-separated values.

The regional opt-in defaults to empty. Apply database migration
``e9c83aa47e21`` and upgrade the API and workers before enabling it. Verify
that existing, new and replacement Amphorae accept the generated
``req.fhdr`` and binary ACL configuration. Local testing used HAProxy
3.0.19.

Set the exact provider names on every regional API replica and reload the
configuration.

.. code-block:: ini

   [api_settings]
   enabled_http_header_exact_providers = amphora

The provider's ``gateway_capabilities`` endpoint then includes
``http_header_exact_v1``. Removing a provider name prevents creation,
match changes and re-enabling of these rules. Reopening a policy,
listener or load balancer that would activate an enabled exact rule
requires the same enrollment. Operators can keep serving existing rules,
disable them or delete them. Drain them before downgrading the workers.

Amphora compares the UTF-8 bytes of the configured value with the request
field content. A MySQL-compatible database connection must support
``utf8mb4`` for four-byte characters. HAProxy rejects field names over
255 bytes before evaluating rules. The API value character limit applies
independently of the byte limits imposed by the HTTP transport, HAProxy
request buffers and the total size of the request headers.


Exact HTTP method matching
--------------------------

An ``HTTP_METHOD`` L7 rule compares the request method case-sensitively
using HAProxy's ``method`` ACL. Use ``EQUAL_TO`` on an HTTP or terminated
HTTPS listener and leave ``key`` unset and ``invert`` false. The supported
methods follow the Gateway API v1.7.0 ``HTTPMethod`` enum: ``GET``, ``HEAD``,
``POST``, ``PUT``, ``DELETE``, ``CONNECT``, ``OPTIONS``, ``TRACE`` and ``PATCH``.
Combine the method rule with a ``PATH`` rule in the same policy to require
both. Requests that fail the method rule continue through the listener's
ordinary policy order and default routing.

Apply database migration ``e4c57b2d836f`` and upgrade the regional API and
workers. Verify that the existing and replacement Amphorae accept the
rendered configuration. Set the registered provider names on each regional
API replica and reload the configuration. The opt-in defaults to empty.

.. code-block:: ini

   [api_settings]
   enabled_http_method_match_providers = amphora

The provider's ``gateway_capabilities`` endpoint then lists
``http_method_match_v1``. Removing the provider name stops new rule creation,
match changes and re-enabling. Reopening a policy, listener or load balancer
that would activate an enabled method rule also requires enrollment. Existing
active rules continue to serve and can be disabled or removed. Retire them
before rolling back the workers.

Exact HTTP query parameter matching
-----------------------------------

An ``HTTP_QUERY_PARAM_EXACT`` L7 rule with ``EQUAL_TO`` matches the first
occurrence of a case-sensitive parameter name on an HTTP or terminated
HTTPS listener. Amphora splits the query on literal ampersands, recognizes
percent-encoded names, and form URL decodes the selected value once before
comparing it byte for byte with the configured UTF-8 value.

Apply database migration ``ff81efc318ad`` and upgrade the API and workers.
Verify that existing and replacement Amphorae support the generated HAProxy
configuration. Amphora uses POSIX regular expressions to recognize encoded
names. Local testing used HAProxy 3.0.19 with libc and PCRE2. Configure the
database connection to use ``utf8mb4`` for four-byte characters.

Set the provider names on each regional API replica and reload the
configuration. The opt-in defaults to empty.

.. code-block:: ini

   [api_settings]
   enabled_http_query_param_exact_providers = amphora

The provider then advertises ``http_query_param_exact_v1``. Removing the
provider name prevents new rules, match changes and re-enabling a rule or
parent that would activate it. Existing rules remain readable and can be
disabled or deleted. Retire the rules before rolling back the workers.


Native gRPC media type matching
-------------------------------

``GRPC_CONTENT_TYPE`` matches a single HTTP Content-Type field on HTTP and
terminated HTTPS listeners. It accepts ``application/grpc``, an optional
``+`` followed by an HTTP token, and optional media type parameters.
Amphora uses a fixed POSIX expression compatible with both libc and PCRE
builds of HAProxy. A comma can appear within a quoted parameter.

Apply migration ``4f1a36c90e8b`` and upgrade the regional API, workers and
Amphora fleet. Verify the generated configuration with the fleet's HAProxy
build before adding the provider to the following setting on each API
replica. The opt-in defaults to empty.

.. code-block:: ini

   [api_settings]
   enabled_grpc_content_type_providers = amphora

The provider then advertises ``grpc_content_type_v1``. Removing the
provider name stops new rules, match changes and re-enabling a rule or
parent that would activate it. Existing rules remain readable and can be
disabled or deleted. Retire the rules before rolling back the workers.


TLS passthrough by SNI
----------------------

The Amphora provider can route a TLS connection on a TCP listener using the
server name in the ClientHello. TLS terminates at the backend. Use a
``REDIRECT_TO_POOL`` policy and a rule of type ``TLS_SNI`` with comparison
``EQUAL_TO``. The target pool must use TCP with ``tls_enabled`` set to
``false``. A rule takes an exact DNS hostname, compared case-insensitively,
and accepts neither a key nor inversion. A connection without a matching
name uses the listener's default pool when one exists and is closed
otherwise.

The regional opt-in defaults to empty. Apply the Octavia database migration
``c7e2860f4b41`` and upgrade the API and workers before enabling any provider.
Verify that existing, new and replacement Amphorae for those providers accept
the generated HAProxy configuration. Local testing used HAProxy 3.0.19.

Set the exact names as registered in ``enabled_provider_drivers`` on every
Octavia API replica in the region and reload the configuration.

.. code-block:: ini

   [api_settings]
   enabled_tls_sni_providers = amphora

An authenticated ``GET /v2/lbaas/providers/amphora/gateway_capabilities`` then
includes ``tls_sni_passthrough_v1``. Removing the provider name disables new
SNI policy and rule admission. Updated workers can still render existing
routes and handle their removal. Remove the SNI policies before downgrading
the workers.

TLS passthrough by wildcard SNI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use a ``TLS_SNI`` rule with comparison ``ENDS_WITH`` and a DNS wildcard
such as ``*.example.test``. It matches subdomains such as
``a.example.test`` and ``a.b.example.test``, case-insensitively. It does
not match the apex ``example.test`` or names such as
``a.notexample.test``. Keys and inversion are unsupported.

On a TCP listener, a matching exact rule takes precedence over a wildcard,
and the longest matching wildcard suffix takes precedence over broader
suffixes. Policy position breaks ties. The rules in each policy must still
all match.

Wildcard admission defaults to disabled. After upgrading the API, workers
and Amphora fleet, enroll the provider in both settings.

.. code-block:: ini

   [api_settings]
   enabled_tls_sni_providers = amphora
   enabled_tls_sni_suffix_providers = amphora

The capabilities endpoint then also includes ``tls_sni_suffix_v1``.
Removing the provider from the wildcard opt-in prevents new wildcard rules,
changes to wildcard matches and reactivation. Existing wildcard routes
continue to render and can be disabled or removed.

TLS termination on a TCP listener
---------------------------------

Amphora can terminate TLS and forward the decrypted stream to a plaintext TCP
pool. Create a listener with ``protocol=TCP``, ``tcp_tls_termination=true`` and
``default_tls_container_ref`` pointing to a project-authorized Barbican
certificate. The existing optional SNI certificate list and client CA and CRL
settings apply. The TCP listener starts without ALPN advertisements unless
configured explicitly. HTTP insertion, redirects and response handling are
unavailable in this mode.

Use the ``TLS_SNI`` rule type with ``EQUAL_TO`` for exact names or ``ENDS_WITH``
for wildcard suffixes. Exact names take precedence over wildcard matches, with
the longest suffix first among wildcards. Configure a plaintext TCP default
pool for a deliberate catch-all. Without a default pool, unmatched names
close without connecting to a member. A matching disabled pool is closed.

The default is disabled. After upgrading the database, API, octavia-lib and
all workers, add the provider name to
``[api_settings] enabled_tcp_tls_termination_providers`` only in regions with a
qualified TLS-capable HAProxy fleet. This publishes
``tcp_tls_termination_v1`` for that provider independently of the TLS
passthrough capabilities. It also requires
``[api_settings] allow_tls_terminated_listeners``. Removing the opt-in blocks
creation, routing and certificate changes, and reactivation. Existing traffic
can continue, and operators can still disable or delete the endpoint. Drain
and remove these listeners before downgrading workers.

This listener mode is chosen at creation. Use a different listener for TLS
passthrough. Supported targets have ``protocol=TCP`` and
``tls_enabled=false``. Backend TLS re-encryption requires a separate
capability.
