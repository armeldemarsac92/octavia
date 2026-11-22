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
