.. -*- rst -*-

List L7 Rules
=============

.. rest_method:: GET /v2/lbaas/l7policies/{l7policy_id}/rules

Lists all L7 rules for the project.

Use the ``fields`` query parameter to control which fields are
returned in the response body. Additionally, you can filter results
by using query string parameters. For information, see :ref:`filtering`.

Administrative users can specify a project ID that is different than their own
to list L7 policies for other projects.

The list might be empty.

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - fields: fields
   - l7policy_id: path-l7policy-id
   - project_id: project_id_query

Curl Example
------------

.. literalinclude:: examples/l7rules-list-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - compare_type: l7rule-compare_type
   - created_at: created_at
   - id: l7rule-id
   - invert: l7rule-invert
   - key: l7rule-key
   - operating_status: operating_status
   - project_id: project_id
   - provisioning_status: provisioning_status
   - tags: tags
   - type: l7rule-type
   - updated_at: updated_at
   - value: l7rule-value

Response Example
----------------

.. literalinclude:: examples/l7rules-list-response.json
   :language: javascript

Create an L7 Rule
=================

.. rest_method:: POST /v2/lbaas/l7policies/{l7policy_id}/rules

Creates a L7 rule.

This operation provisions a new L7 rule by using the
configuration that you define in the request object. After the API
validates the request and starts the provisioning process, the API
returns a response object that contains a unique ID and the status
of provisioning the L7 rule.

In the response, the L7 rule :ref:`provisioning status<prov_status>` is
``ACTIVE``, ``PENDING_CREATE``, or ``ERROR``.

If the status is ``PENDING_CREATE``, issue GET
``/v2/lbaas/l7policies/{l7policy_id}/rules/{l7rule_id}`` to view the
progress of the provisioning operation. When the L7 rule status changes
to ``ACTIVE``, the L7 rule is successfully provisioned and
is ready for further configuration.

If the API cannot fulfill the request due to insufficient data or
data that is not valid, the service returns the HTTP ``Bad Request
(400)`` response code with information about the failure in the
response body. Validation errors require that you correct the error
and submit the request again.

All the rules associated with a given policy are logically ANDed together. A
request must match all the policy's rules to match the policy.

If you need to express a logical OR operation between rules, then do this by
creating multiple policies with the same action.

The Amphora provider can route connections on a TCP listener by the TLS
ClientHello server name or by the SNI of a terminated TLS session. A
``TLS_SNI`` rule belongs to a
``REDIRECT_TO_POOL`` policy targeting a TCP pool with ``tls_enabled`` set
to ``false``. Both comparisons ignore case and accept neither a key nor
inversion.

For an exact DNS hostname, use ``EQUAL_TO``. TCP TLS termination requires
``tcp_tls_termination_v1``. TCP TLS passthrough requires
``tls_sni_passthrough_v1``.

.. code-block:: json

   {"rule": {"type": "TLS_SNI", "compare_type": "EQUAL_TO",
             "value": "a.example.test"}}

For a DNS wildcard, use ``ENDS_WITH``. TCP TLS passthrough additionally
requires ``tls_sni_suffix_v1``. The
wildcard matches subdomains at any depth, such as ``a.b.example.test``.
The apex ``example.test`` is excluded. Exact matches take precedence over
wildcards. The longest matching suffix wins among wildcards, with policy
position breaking ties.

.. code-block:: json

   {"rule": {"type": "TLS_SNI", "compare_type": "ENDS_WITH",
             "value": "*.example.test"}}

With ``http_long_hostname_v1`` enabled, ``HOST_NAME`` rules using
``REGEX`` accept values up to 512 characters on HTTP and TERMINATED_HTTPS
listeners. This accommodates escaped DNS hostnames up to 253 characters
and an optional numeric port in a single regex. The existing match and
``invert`` semantics apply to the entire regex. Without the capability,
new or changed hostname regexes have the standard 255-character limit.
An attempt to enable a stored long regex, or to enable a parent that
would activate it, returns HTTP 501 after capability withdrawal. Stored
rules remain readable and can be disabled, shortened or deleted.
Create these rules at the L7 rule endpoint, as initial rules at the L7
policy endpoint, or in a load balancer creation graph.

With ``http_literal_path_v1`` enabled, use ``HTTP_PATH_LITERAL`` with
``EQUAL_TO`` or ``STARTS_WITH`` on HTTP and TERMINATED_HTTPS listeners.
The value is a case-sensitive absolute Gateway API v1.7.0 path of up
to 1024 ASCII bytes. Omit the key. The rule compares the raw request
path without the query string or percent decoding. ``STARTS_WITH``
matches whole segments, so ``/store/`` matches ``/store``,
``/store/`` and ``/store/item``, while ``/storefront`` does
not match. A prefix of ``/`` matches every absolute path.
``invert`` negates the entire match.

Create these rules at the L7 rule endpoint, as initial rules at the L7
policy endpoint, or in a load balancer creation graph. Creating or
modifying the match, and enabling a rule or parent that would activate
it, returns HTTP 501 when the capability is unavailable. Stored rules
remain readable and can be disabled or deleted.

.. code-block:: json

   {"rule": {"type": "HTTP_PATH_LITERAL", "compare_type": "STARTS_WITH",
             "value": "/store/"}}

With ``http_header_exact_v1`` enabled, use ``HTTP_HEADER_EXACT`` with
``EQUAL_TO`` on HTTP or TERMINATED_HTTPS listeners. The key is an HTTP
field name of up to 255 ASCII characters, compared case-insensitively. The
value is a nonempty literal of up to 4096 characters, compared
case-sensitively against a full field occurrence. Internal whitespace and
commas are preserved.
The additional capability ``http_header_name_256_v1`` extends this rule
to exactly 256 ASCII bytes for the field name with the same comparison.
This limit applies to the standard L7 rule endpoint, initial policy
rules and load balancer creation graphs. An otherwise valid request
that creates, changes or reactivates a match returns HTTP 501 when
its capability is unavailable. Existing rules stay readable.

.. code-block:: json

   {"rule": {"type": "HTTP_HEADER_EXACT", "compare_type": "EQUAL_TO",
             "key": "Version", "value": "one, other"}}

With ``http_query_param_exact_v1`` enabled, use ``HTTP_QUERY_PARAM_EXACT``
with ``EQUAL_TO`` on HTTP or TERMINATED_HTTPS listeners. The key is a
case-sensitive ASCII token of 1 to 256 characters. The value is a
case-sensitive UTF-8 string of 1 to 1024 characters. The rule uses the first
occurrence of the decoded name and compares its value after one form URL
decoding pass. A plus sign in the URL represents a space, and a literal
plus is encoded as ``%2B``. An absent parameter does not match unless the
rule is inverted. An otherwise valid request for this rule type returns
HTTP 501 when the capability is unavailable.

.. code-block:: json

   {"rule": {"type": "HTTP_QUERY_PARAM_EXACT", "compare_type": "EQUAL_TO",
             "key": "Color", "value": "light blue"}}

With ``grpc_content_type_v1`` enabled, use ``GRPC_CONTENT_TYPE`` with
``EQUAL_TO`` and the canonical value ``application/grpc`` on HTTP or
TERMINATED_HTTPS listeners. Omit the key and leave ``invert`` false.
The rule matches a single Content-Type field containing the native gRPC
media type, an optional ``+`` followed by an HTTP token, and optional
media type parameters. Media type comparison ignores ASCII case.
An otherwise valid rule returns HTTP 501 when the capability is unavailable.

.. code-block:: json

   {"rule": {"type": "GRPC_CONTENT_TYPE", "compare_type": "EQUAL_TO",
             "value": "application/grpc"}}

With ``http_method_match_v1`` enabled, use ``HTTP_METHOD`` with
``EQUAL_TO`` on HTTP or TERMINATED_HTTPS listeners. Omit the key and leave
``invert`` false. The case-sensitive value must be one of ``GET``, ``HEAD``,
``POST``, ``PUT``, ``DELETE``, ``CONNECT``, ``OPTIONS``, ``TRACE`` or ``PATCH``.
An otherwise valid request for this rule type returns HTTP 501 when the
capability is unavailable.

.. code-block:: json

   {"rule": {"type": "HTTP_METHOD", "compare_type": "EQUAL_TO",
             "value": "GET"}}

.. rest_status_code:: success ../http-status.yaml

   - 201

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 500
   - 503

Request
-------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up-default-optional
   - compare_type: l7rule-compare_type
   - invert: l7rule-invert-optional
   - key: l7rule-key-optional
   - l7policy_id: path-l7policy-id
   - project_id: project_id-optional
   - tags: tags-optional
   - type: l7rule-type
   - value: l7rule-value

Request Example
----------------

.. literalinclude:: examples/l7rule-create-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/l7rule-create-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - compare_type: l7rule-compare_type
   - created_at: created_at
   - id: l7rule-id
   - invert: l7rule-invert
   - key: l7rule-key
   - operating_status: operating_status
   - project_id: project_id
   - provisioning_status: provisioning_status
   - tags: tags
   - type: l7rule-type
   - updated_at: updated_at
   - value: l7rule-value

Response Example
----------------

.. literalinclude:: examples/l7rule-create-response.json
   :language: javascript

Show L7 Rule details
==========================

.. rest_method:: GET /v2/lbaas/l7policies/{l7policy_id}/rules/{l7rule_id}

Shows the details of a L7 rule.

If you are not an administrative user and the L7 rule object does not
belong to your project, the service returns the HTTP ``Forbidden (403)``
response code.

This operation does not require a request body.

.. rest_status_code:: success ../http-status.yaml

   - 200

.. rest_status_code:: error ../http-status.yaml

   - 401
   - 403
   - 404
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - fields: fields
   - l7policy_id: path-l7policy-id
   - l7rule_id: path-l7rule-id

Curl Example
------------

.. literalinclude:: examples/l7rule-show-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - compare_type: l7rule-compare_type
   - created_at: created_at
   - id: l7rule-id
   - invert: l7rule-invert
   - key: l7rule-key
   - operating_status: operating_status
   - project_id: project_id
   - provisioning_status: provisioning_status
   - tags: tags
   - type: l7rule-type
   - updated_at: updated_at
   - value: l7rule-value

Response Example
----------------

.. literalinclude:: examples/l7rule-show-response.json
   :language: javascript

Update a L7 Rule
================

.. rest_method:: PUT /v2/lbaas/l7policies/{l7policy_id}/rules/{l7rule_id}

Updates a L7 rule.

If the request is valid, the service returns the ``Accepted (202)``
response code. To confirm the update, check that the L7 rule
provisioning status is ``ACTIVE``. If the status is
``PENDING_UPDATE``, use a GET operation to poll the L7 rule
object for changes.

This operation returns the updated L7 rule object with the
``ACTIVE``, ``PENDING_UPDATE``, or ``ERROR`` provisioning status.

.. rest_status_code:: success ../http-status.yaml

   - 202

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up-default-optional
   - compare_type: l7rule-compare_type-optional
   - invert: l7rule-invert-optional
   - key: l7rule-key-optional
   - l7policy_id: path-l7policy-id
   - l7rule_id: path-l7rule-id
   - tags: tags-optional
   - type: l7rule-type-optional
   - value: l7rule-value-optional

Request Example
---------------

.. literalinclude:: examples/l7rule-update-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/l7rule-update-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - compare_type: l7rule-compare_type
   - created_at: created_at
   - id: l7rule-id
   - invert: l7rule-invert
   - key: l7rule-key
   - operating_status: operating_status
   - project_id: project_id
   - provisioning_status: provisioning_status
   - tags: tags
   - type: l7rule-type
   - updated_at: updated_at
   - value: l7rule-value

Response Example
----------------

.. literalinclude:: examples/l7rule-update-response.json
   :language: javascript

Remove a L7 Rule
================

.. rest_method:: DELETE /v2/lbaas/l7policies/{l7policy_id}/rules/{l7rule_id}

Removes a L7 rule and its associated configuration from the project.

The API immediately purges any and all configuration data, depending on the
configuration settings. You cannot recover it.

.. rest_status_code:: success ../http-status.yaml

   - 204

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 500

Request
-------

.. rest_parameters:: ../parameters.yaml

   - l7policy_id: path-l7policy-id
   - l7rule_id: path-l7rule-id

Curl Example
------------

.. literalinclude:: examples/l7rule-delete-curl
   :language: bash

Response
--------

There is no body content for the response of a successful DELETE request.
