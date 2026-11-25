.. -*- rst -*-

List Providers
==============

.. rest_method:: GET /v2/lbaas/providers

Lists all enabled provider drivers.

Use the ``fields`` query parameter to control which fields are
returned in the response body.

The list might be empty.

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - fields: fields

Curl Example
------------

.. literalinclude:: examples/provider-list-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - name: provider-name
   - description: provider-description

Response Example
----------------

.. literalinclude:: examples/provider-list-response.json
   :language: javascript

Show Provider Flavor Capabilities
=================================

.. rest_method:: GET /v2/lbaas/providers/{provider}/flavor_capabilities

Shows the provider driver flavor capabilities. These are the features of the
provider driver that can be configured in an Octavia flavor. This API returns
a list of dictionaries with the name and description of each flavor capability
of the provider.

The list might be empty and a provider driver may not implement this feature.

**New in version 2.6**

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 500
   - 501

Request
-------

.. rest_parameters:: ../parameters.yaml

   - fields: fields
   - provider: path-provider

Curl Example
------------

.. literalinclude:: examples/provider-flavor-capability-show-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - flavor_capabilities: flavor-capabilities
   - name: flavor-capability-name
   - description: flavor-capability-description

Response Example
----------------

.. literalinclude:: examples/provider-flavor-capability-show-response.json
   :language: javascript

Show Provider Availability Zone Capabilities
============================================

.. rest_method:: GET /v2/lbaas/providers/{provider}/availability_zone_capabilities

Shows the provider driver availability zone capabilities. These are the
features of the provider driver that can be configured in an Octavia
availability zone. This API returns a list of dictionaries with the name and
description of each availability zone capability of the provider.

The list might be empty and a provider driver may not implement this feature.

**New in version 2.14**

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 500
   - 501

Request
-------

.. rest_parameters:: ../parameters.yaml

   - fields: fields
   - provider: path-provider

Curl Example
------------

.. literalinclude:: examples/provider-availability-zone-capability-show-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - availability_zone_capabilities: availability-zone-capabilities
   - name: availability-zone-capability-name
   - description: availability-zone-capability-description

Response Example
----------------

.. literalinclude:: examples/provider-availability-zone-capability-show-response.json
   :language: javascript


Show Provider Gateway API Capabilities
======================================

.. rest_method:: GET /v2/lbaas/providers/{provider}/gateway_capabilities

Shows the capabilities for the named provider in the Hibiscus build. The
response contains only capabilities supported by the driver and enabled by
the operator for that provider in this region. An enabled provider without
any available capabilities returns ``{"gateway_capabilities": []}``.

``fixed_http_responses_v1`` enables listener ``default_http_response`` and
L7 policy ``FIXED_RESPONSE``. Both take a ``{"status_code": 404}`` or
``{"status_code": 500}`` object. The listener field is mutually exclusive
with a default pool. The policy uses the ``fixed_response`` field.

``weighted_http_targets_v1`` enables the L7 policy ``WEIGHTED_TARGETS``.
Its ``targets`` list contains 1 to 16 ordered items. Each item has an
integer ``weight`` from 0 to 1,000,000 and either a ``pool_id`` on the
same load balancer or a ``fixed_response``. At least one weight must be
positive. A matching request selects one target proportionally to its
weight. A pool target must be created before it is referenced.

``request_header_operations_v1`` enables the L7 policy field
``request_header_operations`` for ``REDIRECT_TO_POOL`` and
``WEIGHTED_TARGETS``. The field contains up to 48 operations. Each
operation has a case-insensitive, unique header ``name`` and an
``operation`` of ``SET``, ``ADD`` or ``REMOVE``. A string ``value`` is
required for ``SET`` and ``ADD``. The operations run on requests forwarded
by the selected policy to a pool. Send an empty list to clear a stored
list.

``response_header_operations_v1`` enables the independent L7 policy field
``response_header_operations``. The same list format applies to responses
returned by a pool or by a selected ``FIXED_RESPONSE`` or ``WEIGHTED_TARGETS``
policy. ``ADD`` appends a field, ``SET`` replaces its values and ``REMOVE``
removes the field. Connection management and message framing stay with the
listener. Operations on ``Connection``, ``Content-Length``, ``Keep-Alive``,
``Proxy-Connection``, ``TE``, ``Trailer``, ``Transfer-Encoding`` and ``Upgrade``
return HTTP 400. A policy update preserves omitted fields. Send an empty
list to clear the response operations.

``l7policy_initial_rules_v1`` allows creating a disabled L7 policy and its
initial rules in one POST to ``/v2/lbaas/l7policies`` on an existing HTTP or
terminated HTTPS listener. Enable a compatible provider in
``[api_settings] enabled_l7policy_initial_rules_providers`` after upgrading
the API and all workers in the region. Removing a provider from that list
disables admission of new policy posts with rules. Existing policies and rules
can be read and managed through their regular endpoints.

``http_request_redirect_v1`` enables the L7 policy action
``REDIRECT_REQUEST``. Set ``redirect_request`` to an object with
``scheme`` (``http`` or ``https``) and ``port`` (an integer from 1 to
65535). These are the effective destination values. The corresponding
conventional port (80 or 443) is omitted from the Location header.
An optional DNS ``hostname`` overrides the incoming hostname. Otherwise,
Octavia uses the incoming hostname and discards its port. The policy's
``redirect_http_code`` defaults to 302 and also accepts 301, 303, 307 and
308.

Omit the path modifiers to preserve the request target's path and query.
``replace_full_path`` replaces the whole path. Alternatively,
``replace_prefix`` takes ``match`` and ``replacement``. The request path must
match the prefix on a segment boundary in addition to satisfying the
policy's L7 rules. The replacement preserves the suffix and the query.
Replacement text may have up to 1024 characters. Relative text is rooted
at ``/``, URI path characters and valid percent escapes are retained, and
other UTF-8 bytes are percent encoded. An empty full replacement produces
``/``. An empty prefix replacement removes the matching prefix. An empty
resulting path becomes ``/``. The top-level ``redirect_request`` field is
omitted for other actions.

For a request that matches a structured redirect, Amphora selects between
redirects and forwarding policies by position. Legacy redirects retain
their usual priority on other requests. Use ``REDIRECT_REQUEST`` with an
explicit DNS hostname and effective scheme and port for a fixed destination
that needs position-order precedence with forwarding.

``request_url_rewrite_v1`` enables ``request_url_rewrite`` on
``REDIRECT_TO_POOL`` and ``WEIGHTED_TARGETS`` policies. Amphora evaluates
the L7 rules on the original request and applies the rewrite after selecting
the destination pool. A rewrite on a weighted policy applies to each
selected pool. Fixed responses do not rewrite the request.

Set ``hostname`` to replace the HTTP authority with a DNS name.
``replace_full_path`` and ``replace_prefix`` have the same shape and
replacement encoding as in ``redirect_request``. A prefix changes only an
exact path or a descendant on a segment boundary. The original query
travels with the rewritten path. Send ``request_url_rewrite: null`` to clear
the settings. Omission in an update preserves the settings.

``request_cors_v1`` enables ``request_cors`` on ``REDIRECT_TO_POOL`` and
``WEIGHTED_TARGETS`` policies on HTTP and ``TERMINATED_HTTPS`` listeners.
Amphora applies the settings of the winning policy after evaluating
the L7 rules on the original request. A policy can answer a CORS
preflight locally even when its selected target cannot serve traffic.

The object has six optional keys with the
`Gateway API v1.7.0 CORS filter
<https://gateway-api.sigs.k8s.io/reference/api-types/httproute/#cors>`_
semantics:

* ``allow_origins`` takes up to 64 distinct origins of up to 253 characters.
  Use ``http://`` or ``https://`` with an exact host, a leading ``*.``
  wildcard, or the host ``*``. Ports range from 1 to 65535 with effective
  defaults of 80 and 443. A standalone ``*`` allows any origin and must
  be the only list entry.
* ``allow_credentials`` is a JSON boolean and defaults to ``false``.
* ``allow_methods`` takes up to nine distinct uppercase HTTP methods
  from the Gateway API enum (GET, HEAD, POST, PUT, DELETE, CONNECT,
  OPTIONS, TRACE and PATCH), or ``*`` by itself.
* ``allow_headers`` and ``expose_headers`` each take up to 64 distinct
  HTTP header names of 1 to 256 ASCII token characters. Header matching
  is case-insensitive. ``*`` must be the sole entry in ``allow_headers``.
* ``max_age`` takes an integer from 1 to 2147483647 seconds and defaults
  to 5.

An empty object applies CORS with no allowed origins. Omission in an
update preserves the settings. Send ``request_cors: null`` to clear them.

``http_request_policy_v1`` enables ``http_request_policy`` on
``REDIRECT_TO_POOL`` and ``WEIGHTED_TARGETS`` policies on HTTP and
``TERMINATED_HTTPS`` listeners. It applies to requests forwarded by
the winning policy to a pool, including a weighted pool target. Existing
listener and pool timeout settings still apply.

* ``request_timeout_ms`` is the overall deadline in milliseconds from
  forwarding policy processing through completion, including all attempts.
* ``backend_request_timeout_ms`` is the deadline in milliseconds for each
  backend attempt, through receipt of its complete response.
* Both deadlines accept integers in the range 0 to 9223372036854775807.
  An omitted value leaves the provider default. Zero disables that
  deadline. A finite overall deadline must be at least as large as a
  finite per-attempt deadline.
* Omit ``retry`` to leave the provider's default retry behavior. When present,
  ``retry.attempts`` defaults to 1 and accepts up to 2147483647 additional
  attempts. Set it to zero to disable retries. ``retry.codes`` defaults to
  an empty array, allowing only eligible connection failures before
  processing. The array can also contain distinct codes from 500, 502,
  503 and 504. Retries after sending a request require HAProxy to retain
  a replayable request, and a response that has begun reaching the client
  cannot be retried. The API does not accept a backoff setting.

A policy can combine both deadlines with status-based retries.

.. code-block:: json

   {
     "request_timeout_ms": 15000,
     "backend_request_timeout_ms": 500,
     "retry": {"attempts": 3, "codes": [500]}
   }

Omission in an update preserves the object. Send
``http_request_policy: null`` to clear it.

``http_cookie_name_v1`` enables the optional ``session_persistence.cookie_name``
on HTTP pools with ``HTTP_COOKIE`` persistence. The load balancer generates
the cookie and uses it to select a member after selecting the pool. See
:ref:`session_persistence` for the name and update rules.

``tcp_connection_rejection_v1`` enables a per-connection rejection fraction
on Amphora TCP pools. Operators enable it by setting
``[api_settings] enabled_tcp_connection_rejection_providers`` after upgrading
the database, API, every worker and the Amphora fleet. Keep it disabled during
a rolling worker upgrade. The HAProxy rules have been qualified with 3.0.19.
Each new connection to the selected TCP backend is
rejected before connecting to a server with probability
``reject_weight / total_weight``. The remaining connections use the pool's
normal member selection. A graceful reload lets established connections
drain, and the batch leaves existing member networks attached for them.
Octavia prepares and uploads the combined configuration to all participating
Amphorae before requesting any reload. An upload can leave a validated file
on disk even if a later upload fails. Reloads are acknowledged by individual
Amphorae. A partial reload can temporarily leave peers on different
configurations, and the pool remains in ``ERROR`` until a replacement batch
completes.

``udp_packet_drop_v1`` enables proportional datagram drop on managed
Amphora IPv4 UDP listeners. Enable the provider in
``[api_settings] enabled_udp_packet_drop_providers`` after upgrading the
database, API, every worker and all participating Amphora images. The
configured worker driver must support guarded LVS reloads. Amphora closes
the affected VIP and port during reconfiguration and verifies the new
IPVS service before forwarding the admitted share. Each Amphora applies
the update separately, so the port may briefly be unavailable and peers
may temporarily apply different configurations.

``backend_retry_budget_v1`` enables ``backend_retry_budget`` on HTTP
pools forwarding ingress on HTTP and ``TERMINATED_HTTPS`` listeners. It
shares request and retry history among participating pools with the same
``service_uid`` in a single HAProxy process. Use the same Service UID for
all pools and ports targeting that Service. Delivered request mirrors count
as original requests for their destination Service and are never retried.
Each process, including a replacement upon reload or failover, has
independent counters.

Each object requires all five fields.

* ``service_uid`` accepts 1 to 128 ASCII letters, digits, dots, underscores,
  or hyphens.
* ``budget_percent`` accepts integers from 0 to 100. The percentage counts
  retries as a share of original requests plus retries over
  ``budget_interval_ms`` (1000 to 3600000 milliseconds).
* ``min_retry_count`` accepts 1 to 1000000. The minimum allows this many
  retries over a moving window of ``min_retry_interval_ms`` (1 to 3600000
  milliseconds) even when the percentage allowance is lower.

Each permitted retry consumes budget. Original requests proceed normally.
A retry selected by native HAProxy or ``http_request_policy`` receives a
local HTTP 503 when the Service budget is exhausted. The pool budget does
not create retry attempts. Omit the field on update to keep the current
policy, or send ``backend_retry_budget: null`` to withdraw it.

``http_request_mirror_v1`` enables an ordered ``request_mirrors`` list
on a winning HTTP policy and on each selected weighted HTTP pool target.
A list can hold up to 16 entries. Each entry identifies an HTTP pool
in the listener's project and load balancer by ``pool_id``. A pool can
appear multiple times.

Set ``numerator`` and ``denominator`` to integers from 0 to 2147483647.
The denominator must be positive and the numerator must be at most the
denominator. Zero keeps the pool reference and disables sampling for that
entry. Each positive ratio is sampled independently of the primary backend
selection. The copy's response is discarded.

At each level, an optional ``phase`` selects ``before_transforms``,
``after_headers`` or ``after_rewrite``. These phases follow request
header operations and URL rewrites in that order. The default is
``after_rewrite``. List entries follow phase order and preserve their
relative order within a phase. A CORS preflight answered by the policy
completes before request transformation and mirroring.

``weighted_http_target_request_filters_v1`` adds optional
``request_header_operations`` and ``request_url_rewrite`` to each
``WEIGHTED_TARGETS.targets`` item with a ``pool_id``. Both fields have
the same format as their policy-level counterparts. Amphora selects the
policy and draws the target on the original request. In the selected pool,
it applies the policy's header operations and URL rewrite first, then the
target's header operations and URL rewrite. The same pool can occur more
than once with different filters. A target with zero weight does not receive
requests. A local fixed response or an unavailable target runs no request
filter.

A rule and its filtered target can each rewrite a different part of the URL.
Two path rewrites, two hostname rewrites, or a hostname rewrite combined
with an operation on the Host header return HTTP 400. Header operations
across the two levels are sequential. A matching prefix rewrite preserves
the query and path suffix. This contract does not add named targets to
the initial load balancer graph. Create the pool and listener first, then
send pool targets to the L7 policy endpoint. A PUT replaces the complete
ordered target list. Omit the filter fields from target entries to clear
them and omit ``targets`` itself to retain the list.

After regional withdrawal, a policy update can remove filters from selected
targets. Each retained filter must stay at its original position and pool.
A positive-weight filter can keep its share of the ordered draw or occupy a
smaller interval within it. A policy whose remaining filters all have zero
weight can be reactivated. Adding a filter or expanding its reach requires
regional enrollment.

Enable the capability with
``[api_settings] enabled_weighted_target_request_filter_providers`` after
upgrading the database, API, workers and Amphora images. The provider must
also be enrolled for ``weighted_http_targets_v1``. The policy-level
capabilities are required only when the corresponding policy-level fields
are used. Withdrawing the target capability preserves established routing,
allows reads and removal of the filters, and blocks changes that would
expand their use. Ordinary weighted targets remain available while the base
weighted capability is enabled.

These fields require HTTP or terminated HTTPS. Create extended policies
through the L7 policy endpoint or in the initial load balancer graph. To
add one to a standalone listener, create the listener first.

Octavia returns HTTP 501 for an otherwise valid request to add or replace
action values, reactivate an extended action, or add or change its enabled
matching rules while the capability is unavailable. The JSON fields
are available for projection with ``fields``. Use scalar fields for sorting
and filtering. Stored values remain readable. Clear a listener
default with ``default_http_response: null``. Convert a policy to a stock
action or delete it to remove its stored action data.

``backend_h2c_v1`` enables HTTP/2 prior knowledge from Amphora to members of
an HTTP pool. Upgrade the regional API services, database schema, workers
and Amphora fleet before adding the provider name to
``[api_settings] enabled_backend_h2c_providers``. The pool selects this
transport with ``backend_h2c: true`` and ``tls_enabled: false``. Removing
the provider name stops advertisement and admission of new h2c settings.
Existing pools keep their stored setting. Set it to false or drain those
pools before rolling back the fleet.

``listener_otlp_tracing_v1`` enables listener OTLP/HTTP tracing with Amphora.
Upgrade regional API services, workers, the database, octavia-lib, and the
Amphora fleet before adding the provider name to
``[api_settings] enabled_listener_otlp_tracing_providers``. Removing the
provider name stops discovery and new enrollment. Existing settings remain
readable and can be cleared with ``otlp_tracing: null``. Clear existing
settings before rolling back the Amphora fleet.

``http_header_exact_v1`` enables ``HTTP_HEADER_EXACT`` rules for HTTP and
terminated HTTPS listeners. This capability requires the provider name in
``[api_settings] enabled_http_header_exact_providers`` after the regional
database, API services, workers and Amphora fleet are upgraded.

``http_method_match_v1`` enables ``HTTP_METHOD`` rules for HTTP and
terminated HTTPS listeners. This capability requires the provider name in
``[api_settings] enabled_http_method_match_providers``. Apply the database
migration and upgrade the regional API, workers and Amphora fleet first.

``http_query_param_exact_v1`` enables ``HTTP_QUERY_PARAM_EXACT`` rules for
HTTP and terminated HTTPS listeners. Apply the database migration and
upgrade the regional API, workers and Amphora fleet before adding the
provider name to ``[api_settings] enabled_http_query_param_exact_providers``.

``grpc_content_type_v1`` enables ``GRPC_CONTENT_TYPE`` rules for HTTP and
terminated HTTPS listeners. Apply the database migration and upgrade the
regional API, workers and Amphora fleet before adding the provider name to
``[api_settings] enabled_grpc_content_type_providers``.

``https_listener_isolation_v1`` allows several host sections on a single
``TERMINATED_HTTPS`` listener. Set ``https_virtual_hosts`` to a nonempty set
of exact DNS names, DNS wildcard suffixes beginning with ``*.``, or ``*``
for a catch-all. Use one project-authorized default certificate and omit
SNI certificate references and the default pool. The fallback is HTTP
404, also accepted as an explicit ``default_http_response``. Each policy
on the listener must set ``https_listener_hostname`` to a configured
section, including policies created with the initial load balancer graph.

Amphora independently selects a section from TLS SNI and HTTP authority.
Exact names come first, then the longest matching suffix, then the
catch-all. Wildcard suffixes match one or more leading DNS labels.
Authority matching ignores case and port. A request whose authority matches
another section receives 421. An unmatched authority or a section without
a matching policy receives 404. Policy evaluation stays within the
selected section.

Enroll the provider in ``[api_settings]
enabled_https_listener_isolation_providers`` after upgrading the regional
API, workers, driver library, database and Amphora fleet (HAProxy 3.0 or
newer). Withdrawing enrollment preserves isolation on existing listeners.
Delete policies selecting a section before removing it from the listener.
Replace the listener to remove isolation.

``frontend_client_auth_insecure_fallback_v1`` enables insecure fallback for
client certificate validation on a ``TERMINATED_HTTPS`` listener. Configure
``client_authentication: MANDATORY``, a project-authorized client CA
certificate bundle and ``client_authentication_insecure_fallback: true``.
Amphora requests the client certificate and uses the configured CA to
verify it. Clients can connect when the certificate is absent or invalid.
The existing ``X-SSL-Client-Has-Cert`` and ``X-SSL-Client-Verify`` listener
header insertions expose the certificate presence and verification result
to the backend. Set the flag to false to restore strict verification.

Enroll the provider in ``[api_settings]
enabled_frontend_client_auth_insecure_fallback_providers`` after upgrading
the driver library, database, API, workers and all Amphora agents. Each
Amphora agent must confirm support in its details response (HAProxy 3.0 or newer
with OpenSSL). If one peer cannot confirm support or stage the required
TLS material, both peers omit the affected listener from their generated
configuration. Other listeners retain their own TLS settings.

``tcp_tls_termination_v1`` enables ``tcp_tls_termination: true`` on TCP
listeners. Set the field on creation with a project-authorized
``default_tls_container_ref``. Route the decrypted stream to TCP pools
with ``tls_enabled: false``. Use ``TLS_SNI`` rules for exact names or
wildcard suffixes. Connections without a match close if the listener has
no default pool.

Enable this capability with ``[api_settings] allow_tls_terminated_listeners``
and add the provider name to ``enabled_tcp_tls_termination_providers`` after
upgrading the regional database, API, workers, driver library and Amphora
fleet. This enrollment is independent of TLS passthrough.

``tcp_tls_mixed_mode_v1`` combines terminating and passthrough TLS SNI
policies on one TCP listener. It requires both ``tcp_tls_termination_v1`` and
``tls_sni_passthrough_v1``. Add the provider name to
``[api_settings] enabled_tcp_tls_mixed_mode_providers`` after upgrading
octavia-lib, the database, API, workers and the Amphora fleet to HAProxy 3.0
or newer. Use
``tcp_tls_mixed_mode: true`` and the terminating listener's certificate
parameters, and omit a default pool. The listener closes connections that
match no active TLS SNI policy.

``tcp_tls_backend_auth_v1`` also allows a terminating TCP listener to route to
a TCP pool with ``tls_enabled: true``, a literal DNS ``backend_tls_hostname``,
and a ``ca_tls_container_ref``. The backend hostname controls SNI and
certificate verification for application and health-check connections.
Both ``tcp_tls_termination_v1`` and ``backend_tls_hostname_v1`` are required.
Enroll the provider in
``[api_settings] enabled_tcp_tls_backend_auth_providers`` after qualifying
the regional API, workers and Amphora fleet.

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - provider: path-provider

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - gateway_capabilities: gateway-capabilities

Response Example
----------------

.. code-block:: json

   {
     "gateway_capabilities": [
       "fixed_http_responses_v1",
       "weighted_http_targets_v1",
       "request_header_operations_v1"
     ]
   }
