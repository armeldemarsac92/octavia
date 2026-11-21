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
