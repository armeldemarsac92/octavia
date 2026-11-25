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
to run on patched workers. If a routing change could expose a retained
rewrite, first clear that rewrite with ``request_url_rewrite: null`` or
disable the listener and retire the affected settings before reopening it.
A disabled listener or load balancer can reopen with a stored rewrite
that has no enabled match or forwarding destination. Clear existing
settings before rolling back the services or provider library.


CORS in L7 forwarding policies
-----------------------------

Apply migration ``c9b157a8be42`` and upgrade Octavia, octavia-lib and the
Amphora fleet before enrolling the provider on every regional API replica.

.. code-block:: ini

   [api_settings]
   enabled_request_cors_providers = amphora

The provider advertises ``request_cors_v1`` when the regional setting,
provider driver and installed octavia-lib all support the field. A winning
HTTP or terminated HTTPS policy can answer preflights and control the CORS
headers returned to clients, including when a weighted target responds
with a local error.

Removing regional enrollment prevents creation, replacement and changes
that would expose or reactivate a retained CORS filter. Stored active
filters continue to run on upgraded workers. Clear a filter with
``request_cors: null`` before a routing change that would expose it.
Clear stored filters before rolling back Octavia, octavia-lib or Amphora.

Deadlines and retries in L7 forwarding policies
----------------------------------------------

Apply migration ``d3d72b90b815`` and upgrade the regional API, octavia-lib
and workers. Qualify the eligible Amphora fleet, including existing,
replacement and failover images, before enabling the provider on every
regional API replica.

.. code-block:: ini

   [api_settings]
   enabled_http_request_policy_providers = amphora

Discovery advertises ``http_request_policy_v1`` when the regional setting,
provider driver and installed octavia-lib support the field. For Amphora,
the renderer also requires the capability reported by the Amphora agent
from the HAProxy build with the ``-backend-sans-v1-http-policy-v1`` suffix.

Removing regional enrollment prevents adding HTTP request policies and
expanding or reactivating stored ones. Existing policies continue to run
on upgraded Amphorae. Clear them with ``http_request_policy: null`` before
rolling back Octavia, octavia-lib or Amphora images.

Explicit HTTP retry backoff
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Upgrade the API, workers and Amphora agents, and qualify HAProxy on all
eligible Amphorae, including replacement and failover images. With the
base HTTP request policy capability enabled, enroll the provider on each
regional API replica.

.. code-block:: ini

   [api_settings]
   enabled_http_request_policy_providers = amphora
   enabled_http_retry_backoff_providers = amphora

Discovery then includes ``http_retry_backoff_v1`` alongside
``http_request_policy_v1``. The Amphora agent checks that its configured
HAProxy binary accepts the explicit delay in a policy directive. Octavia
requires confirmation from the allocated Amphorae before activating the
delay. When a serving peer lacks the capability, requests matching an
affected policy receive HTTP 503 after the degraded configuration is
loaded. Its provisioning status is ERROR. Other forwarding policies and
withdrawals can proceed on the same listener.

During an active/standby rebuild, the first replacement can load that
degraded configuration while Octavia brings up its peer. Final failover
requires a successful configuration reload and capability confirmation
from the topology's serving Amphorae.

``http_request_policy.retry.backoff_ms`` delays each eligible retry by the
configured number of milliseconds, within the existing overall deadline.
An omitted value keeps the existing retry timing. An explicit zero requests
an immediate retry. Retry limits and pool retry budgets continue to apply.

Removing regional enrollment blocks adding, increasing or reactivating
the explicit delay. Operators can reduce it or replace the retry object
without ``backoff_ms`` while retaining its other settings. Withdraw the
field from stored policies before downgrading the workers or Amphora images.

HTTP request mirroring
----------------------

Apply migration ``b22da9155c2b`` and upgrade the regional API, octavia-lib,
workers and Amphora agents. Qualify the eligible Amphora fleet before
enabling the provider on each regional API replica.

.. code-block:: ini

   [api_settings]
   enabled_http_request_mirror_providers = amphora

Discovery advertises ``http_request_mirror_v1`` when regional enrollment,
the provider and the installed octavia-lib support it. Amphora also checks
the capability reported by the agent for the HAProxy build. Private HTTP
delivery sockets are managed inside Amphora and use the target pool's
members, balancing algorithm, health checks and transport profile.
Copies use independent connection and I/O timeouts and a single attempt.
They use pool balancing without primary session persistence.

After withdrawing the regional capability, existing mirrors can be removed
from prepared or active policies. Clear them before rolling back to an
Octavia, octavia-lib or Amphora build that predates the capability. A
destination pool remains in use until every mirror reference is removed.

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
passthrough. Plaintext targets have ``protocol=TCP`` and
``tls_enabled=false``.

Weighted TLS passthrough pools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enroll Amphora after updating the regional API, workers, and each eligible
Amphora agent. The agent checks its own HAProxy binary for the required
ClientHello and weighted selection support. The worker checks the Amphorae
that can serve the load balancer and reads back the installed generation from
each active HAProxy worker before acknowledging activation. Use HAProxy 2.2
or newer, or HAProxy 3.0 or newer for mixed TLS routing.

.. code-block:: ini

   [api_settings]
   allow_tls_terminated_listeners = true
   enabled_tcp_tls_termination_providers = amphora
   enabled_tls_sni_weighted_pool_providers = amphora
   enabled_tls_sni_providers = amphora
   enabled_tls_sni_passthrough_weighted_pool_providers = amphora

These settings advertise ``tls_sni_passthrough_weighted_pools_v1``.
A pure passthrough listener works without an Octavia certificate.
Omit both ``tcp_tls_termination`` on the listener and
``tcp_tls_passthrough`` on its policies. For mixed mode, enroll Amphora
separately in ``enabled_tcp_tls_mixed_mode_providers``, configure the
listener certificate, and set ``tcp_tls_passthrough=true`` on each
passthrough policy when creating it. Enable ``enabled_tls_sni_suffix_providers``
for wildcard passthrough selectors.

A ``WEIGHTED_TARGETS`` policy with ``TLS_SNI`` rules draws one target per
connection. Each target specifies an existing TCP pool and a weight of
0 to 1,000,000. All target pools must use ``tls_enabled=false`` so the
origin negotiates TLS with the client. Use an empty TCP pool for a share
that must close. A disabled or unavailable target also closes its share.
Broader policies and default pools can handle other connections.

To withdraw enrollment, remove the provider from
``enabled_tls_sni_passthrough_weighted_pool_providers``. Already installed
selectors can continue serving. New weighted passthrough policies,
positive-target changes, and reopening require enrollment. Operators can
disable or delete an admitted policy, drain members, and remove zero-weight
targets. A pending grouped activation can be read and replayed after
withdrawal to restore its disabled policies. If a serving Amphora cannot
confirm the configuration, Octavia applies closures to the reachable
Amphorae and reports the update as unconfirmed. A failover must confirm the
configuration before proceeding. Drain and remove weighted passthrough
policies before downgrading workers or Amphorae.

Authenticated TLS backends on terminating TCP listeners
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enroll the provider in
``[api_settings] enabled_tcp_tls_backend_auth_providers`` after qualifying
the regional API, workers and every Amphora image. The provider publishes
``tcp_tls_backend_auth_v1`` when ``tcp_tls_termination_v1`` and
``backend_tls_hostname_v1`` are also enabled.

Use a TCP pool with ``tls_enabled=true``, a literal DNS
``backend_tls_hostname``, and a trusted CA in ``ca_tls_container_ref``.
Attach it through a TCP listener default or a TLS SNI policy on a TCP
listener that terminates TLS. HAProxy sends the configured backend name as
SNI and verifies the certificate chain and its DNS subject alternative
names for traffic and health checks, including checks on a separate port.
Use TCP, TLS-HELLO, HTTP, or HTTPS health monitors with these pools.

A backend that cannot be authenticated or whose Amphora credentials or
capabilities cannot be prepared closes independently of other routes.
Removing regional enrollment blocks new protected pools, protected routing
changes and reopening. Changing a pool's trusted CA or opening a member
on an active protected pool also requires regional enrollment. Existing
protected pools can keep serving, drain or be removed. Disable and detach a pool before clearing its hostname
requirement.

System trust for authenticated TLS backends
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Upgrade the Octavia API, workers, provider library, database and Amphora
agents before enrolling a region. Qualify the fleet's strict backend TLS
hostname support and confirm that the CA package installs the same readable
PEM bundle on every eligible image.

.. code-block:: ini

   [api_settings]
   enabled_backend_tls_hostname_providers = amphora
   enabled_backend_tls_system_ca_providers = amphora

   [haproxy_amphora]
   backend_tls_system_ca_path = /etc/ssl/certs/ca-certificates.crt
   backend_tls_system_ca_sha256 = <lowercase SHA-256 of the exact PEM file>

Set these options consistently on the regional API and workers. The path is
on each Amphora. An operator supplies the profile and a pool selects it with
``backend_tls_system_ca: true``. The pool also requires ``tls_enabled`` and
a literal ``backend_tls_hostname``. A pool can supply its own client
certificate and use independently supported SAN or ALPN options.

Octavia compares the local bundle to the configured SHA-256 on every
serving Amphora when programming the pool. It stages the verified bytes at
a digest-addressed path and reloads HAProxy with strict verification. A
pool with a missing, invalid or different bundle closes while the remaining
pools can serve. When the full topology acknowledges the installed config,
the API publishes the applied digest. An enabled pool attached to an
enabled listener can report the digest without members.

Rotate the bundle through the image or the system CA package. Confirm the
regional digest and reconcile affected load balancers to install that
generation. The loaded generation continues using its snapshot until the
next reconciliation. A mismatching peer on reconcile or failover closes
the affected system pools. Disable a pool before withdrawing the mode.

Backend Service retry budgets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apply the pool database migration and update the API, provider library,
workers, and every eligible Amphora image with the Octavia HAProxy
``backend-retry-budget-v1`` build before enabling discovery.

.. code-block:: ini

   [api_settings]
   enabled_backend_retry_budget_providers = amphora

Use the Kubernetes Service UID in the ``service_uid`` of every HTTP pool
that serves that Service. All participating listeners and pools in a
single HAProxy process share the original-request and retry history.
Each separate Amphora process, including a process started by reload or
failover, starts with its own history. Regional discovery applies to
new writes. Clear a persisted budget with ``backend_retry_budget: null``
even when discovery is disabled.

Load balancer-generated persistence cookie names
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apply the session persistence database migration and upgrade the API and
workers before enabling the option in the region.

.. code-block:: ini

   [api_settings]
   enabled_http_cookie_name_providers = amphora

An authenticated ``GET /v2/lbaas/providers/amphora/gateway_capabilities``
then includes ``http_cookie_name_v1``. HTTP pools can set
``session_persistence.cookie_name`` when using ``HTTP_COOKIE``.
Amphora generates these cookies without the ``Secure`` and ``HttpOnly``
attributes. Names starting with ``__Host-`` (including ``__Host-Http-``),
``__Secure-`` or ``__Http-`` are rejected regardless of case.
Named cookies use the same session lifetime and default root path as the
``SRV`` cookie. Their opaque member identifier is derived from the project,
cookie name, member IP address and port. Pools serving the same backend
can share a name and recognize affinity to the same endpoint across routes.
The identifier has no role in authorization. The default ``SRV`` cookie
continues to use the Octavia member UUID.

When regional discovery is disabled, pools with a name already configured
keep serving it. For pools without an absolute timeout, send
``session_persistence: {"type": "HTTP_COOKIE"}`` in a pool update to return
to the default. To remove persistence entirely, send
``session_persistence: null``.

Load balancer-generated persistence cookie paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apply database revision ``1c4fd3a0b279``, update the regional API,
workers and Amphora agents, and qualify all eligible Amphora images.
Then enable the provider.

.. code-block:: ini

   [api_settings]
   enabled_http_cookie_path_providers = amphora

The provider advertises ``http_cookie_path_v1``. An HTTP pool with
``HTTP_COOKIE`` persistence can set ``session_persistence.cookie_path``.
Octavia preserves the exact configured value, including the empty string.
By default the cookie uses ``Path=/``. Regional discovery applies to new
custom paths and changes to existing ones.

Each agent advertises ``http_cookie_path_v1`` in its details only after
the configured ``haproxy_cmd`` accepts a compatibility configuration.
The worker checks this capability on every allocated Amphora, including
both peers in active/standby. When a confirmation is missing, reachable
peers balance traffic for pools with custom paths without affinity. A
pool with a custom path reports ``ERROR`` until the full topology applies
its affinity configuration. The previous configuration stays loaded on
a peer that cannot be reached or reloaded. Withdrawal works even when a
peer lacks support. Before rolling back services or images, set
``cookie_path`` to ``null`` or ``/`` and let the affected pools provision.

Absolute HTTP session cookie timeouts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apply database migrations through ``6529f4796d83`` and update the API, workers
and eligible Amphora agents. Qualify the regional OpenSSL-enabled HAProxy builds
before enabling discovery. The profile uses native HAProxy facilities and
was qualified against HAProxy 3.0.19. The upgraded agent advertises support
to the worker for HAProxy 3.0 and newer with OpenSSL. Qualify any later build
for cookie handling, failover and reload before adding it to the fleet.
Custom HAProxy templates must provide the same absolute timeout profile.

Provision a dedicated key of exactly 32 random bytes to every Octavia
worker in the region. The key file must be a regular file readable by the
worker with no group or other access, for example mode ``0400`` or
``0600`` owned by the worker. Use the same key bytes for all workers that
can rebuild the same pool, including during failover. Configure only the
file path in the worker configuration.

.. code-block:: ini

   [haproxy_amphora]
   http_cookie_signing_key_file = /run/octavia/http-cookie-key

Keep private file contents out of configuration, logs and diagnostics.
Amphora configurations carry only a derived key scoped to the Octavia
project, logical scope, cookie name, timeout and format version. Restrict
access to these configurations and to any captured management-plane
requests. Rotate the worker key in a coordinated maintenance window and
re-render the affected load balancers. Rotation invalidates earlier
cookies as each Amphora reloads.

Once the worker key and Amphora fleet are ready, enable the profile for
the provider on the API.

.. code-block:: ini

   [api_settings]
   enabled_http_cookie_name_providers = amphora
   enabled_http_cookie_absolute_timeout_providers = amphora

The provider then advertises ``http_cookie_absolute_timeout_v1``. A named
``HTTP_COOKIE`` pool can supply ``cookie_absolute_timeout_ms`` and
``cookie_scope``. Across pools of the same logical backend, identical
scope, project, name and timeout preserve affinity to the same destination
address and port after a reload or failover. A cookie for an expired,
unavailable or unknown member falls back to the pool's normal balancing.
The affinity cookie name is reserved in responses. A response header
modifier targeting that cookie does not affect the session or remove
other application cookies.

HAProxy checks age with its native microsecond wall-clock sample. HAProxy
refreshes this sample after polling and gives no maximum sampling delay
under overload or a process pause. Keep wall clocks synchronized among
Amphorae. The difference between their clocks can shift the observed
deadline by that difference, in addition to sampling delay. A backward
clock step may make a previously expired cookie eligible again until its
age reaches the deadline. The arrival check applies to new requests.

Removing API discovery prevents new enrollment and replacement. Existing
pools continue using their stored policy. If a worker cannot read a valid
key, or an Amphora does not advertise support, the new configuration
balances the affected pool without affinity. After an Amphora confirms
this reload, pool reads report ``ERROR`` for an otherwise active pool.
Re-render after restoring the key and eligible Amphora support. All
Amphorae in the allocated topology must confirm the restored policy before
pool reads stop reporting this affinity error. The pool's own provisioning
failures remain visible. The load balancer's previously loaded
configuration remains in use until a reload. Explicitly clear both fields
with ``null`` to return to named affinity without a timeout, or set
``session_persistence`` to ``null`` to remove affinity entirely.

Permanent HTTP affinity cookies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Apply database revision ``b3d57e9a2c41`` and update the regional API,
workers and Amphora agents. Qualify the same HAProxy profile and provision
the shared signing key described above. Then enable the provider for all
three cookie capabilities.

.. code-block:: ini

   [api_settings]
   enabled_http_cookie_name_providers = amphora
   enabled_http_cookie_absolute_timeout_providers = amphora
   enabled_http_cookie_permanent_providers = amphora

The provider advertises ``http_cookie_permanent_v1``. When
``session_persistence.cookie_permanent`` is ``true``, the load balancer
issues the configured path and ``Max-Age``, rounded up from the configured
millisecond timeout. A zero timeout gives ``Max-Age=0``. Server-side expiry
uses the exact timeout. Use the same cookie mode across pools that
share an affinity scope. Cookies signed for one mode are replaced when
the mode changes, and existing browser session cookie signatures remain
compatible.

When an Amphora agent cannot advertise permanent cookie support, the
worker renders the affected pool without affinity. The acknowledged
reload and recovery rules for the absolute timeout profile also apply
here. To return to a browser session cookie while retaining the existing
absolute timeout, send ``session_persistence: {cookie_permanent: false}``.
