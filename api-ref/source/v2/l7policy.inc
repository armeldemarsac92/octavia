.. -*- rst -*-

Read the activation snapshot for a listener
===========================================

.. rest_method:: GET /v2/lbaas/listeners/{listener_id}/l7policy_activation

This regional v2 extension is available for HTTP and TERMINATED_HTTPS
listeners whose provider advertises ``l7policy_batch_activation_v1`` on
``GET /v2/lbaas/providers/{provider}/gateway_capabilities``. It uses the
Octavia provider capability discovery mechanism.

The HTTP 200 response contains an ``l7policy_activation`` object. It includes
the standard ``loadbalancer`` and ``listener`` representations, plus a
``pools`` array of destinations referenced by the listener or its policies.
Each destination has a ``pool`` object with ``healthmonitor`` when present
and a separate ``members`` array with detailed members and their ``pool_id``.

The ``policies`` array contains every non-deleted policy of the listener in
position order, without pagination. Each element has an opaque ``revision``
and a ``policy`` containing the ordinary policy fields and full non-deleted
``rules``. An opaque ``graph_revision`` covers policy and rule identity,
administrative state, routing fields and the supporting graph. Compare
these resources with the intended routing and ownership before using the
revisions.

Activate prepared L7 policies for a listener
=============================================

.. rest_method:: POST /v2/lbaas/listeners/{listener_id}/l7policy_activation

Send the observed graph revision, the complete observed UUID order and the
revisions of two to 64 unique policies from the same listener and project.
Each selected policy must have at least one enabled rule and be in
provisioning status ``ACTIVE``.

.. code-block:: json

   {
     "l7policy_activation": {
       "expected_graph_revision":
       "4faf00b3b4b1fae36ae4268f9708fb30e38c80572823231ef1ac05d3ea912e65",
       "expected_order": [
         "8af9a5fb-380e-45dd-9d5c-33bd0ca20187",
         "b22b947a-91bc-4c9b-af04-76ae18c31ad8"
       ],
       "policies": [
         {
           "id": "8af9a5fb-380e-45dd-9d5c-33bd0ca20187",
           "revision":
           "e60d315debcd749b51f67832f662a77f30fee27f58884c80ff6254af37d11a539"
         },
         {
           "id": "b22b947a-91bc-4c9b-af04-76ae18c31ad8",
           "revision":
           "f44276c4131d818380312975339c2594182dc5c966e8227bc0a1738512b804b4"
         }
       ]
     }
   }

An HTTP 204 response accepts asynchronous activation of a disabled group.
Wait for the load balancer and selected policies to finish provisioning.
An identical POST redelivers a pending request under its original operation
identity. It returns HTTP 204 without dispatch after success while the
applied configuration is current. An ordinary mutation of the load balancer
or its children invalidates the old request, including explicit withdrawal
of policies. HTTP 409 means the observed order, revisions, membership or
readiness changed. Refresh the snapshot and confirm the intended change
before retrying. HTTP 501 indicates that the regional provider or listener
protocol does not support the action.

An Amphora worker applies the group through one combined HAProxy refresh per
Amphora. If the refresh fails, all selected policies remain disabled with
provisioning status ``ERROR``. The listener and load balancer also enter
``ERROR`` if the worker could not restore their prior configuration. Their
activation request remains available for a retry of the restoration.

List L7 Policies
================

.. rest_method:: GET /v2/lbaas/l7policies

Lists all L7 policies for the project.

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
   - project_id: project_id_query

Curl Example
------------

.. literalinclude:: examples/l7policies-list-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action
   - admin_state_up: admin_state_up
   - created_at: created_at
   - description: description
   - id: l7policy-id
   - listener_id: listener-id
   - name: name
   - operating_status: operating_status
   - position: l7policy-position
   - project_id: project_id
   - provisioning_status: provisioning_status
   - redirect_http_code: l7policy-redirect-http-code
   - redirect_pool_id: l7policy-redirect-pool_id
   - redirect_prefix: l7policy-redirect-prefix
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url
   - rules: l7policy-rule-ids
   - tags: tags
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/l7policies-list-response.json
   :language: javascript

Create an L7 Policy
===================

.. rest_method:: POST /v2/lbaas/l7policies

Creates a L7 policy.

This operation provisions a new L7 policy by using the
configuration that you define in the request object. After the API
validates the request and starts the provisioning process, the API
returns a response object that contains a unique ID and the status
of provisioning the L7 policy.

In the response, the L7 policy :ref:`provisioning status<prov_status>` is
``ACTIVE``, ``PENDING_CREATE``, or ``ERROR``.

If the status is ``PENDING_CREATE``, issue GET
``/v2/lbaas/l7policies/{l7policy_id}`` to view the progress of
the provisioning operation. When the L7 policy status changes
to ``ACTIVE``, the L7 policy is successfully provisioned and
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

If a new policy is created with a position that matches that of an existing
policy, then the new policy is inserted at the given position.

On HTTP and terminated HTTPS listeners whose provider advertises
``l7policy_initial_rules_v1``, send a non-empty ``rules`` array and
``admin_state_up: false`` to create the policy and its initial rules in one
operation. The policy and rules are written in one transaction. The response
contains the policy and rule IDs. Before enabling the policy with PUT, read
back the policy and its rule list, confirm that both the policy and every rule
are ``ACTIVE``, and verify that the full rule set matches the intended scope.

L7 policies with ``action`` of ``REDIRECT_TO_URL`` will return the default HTTP
``Found (302)`` response code with the ``redirect_url``. Also, specify
``redirect_http_code`` to configure the needed HTTP response code, such as,
301, 302, 303, 307 and 308.

The regional ``http_request_redirect_v1`` provider capability enables
``REDIRECT_REQUEST`` and its structured ``redirect_request`` field.
See the provider Gateway API capabilities for the fields and defaults.

The regional ``request_url_rewrite_v1`` provider capability enables
``request_url_rewrite`` on forwarding policies. The winning policy can
replace the hostname, path or both before forwarding.

The regional ``request_cors_v1`` provider capability enables
``request_cors`` on ``REDIRECT_TO_POOL`` and ``WEIGHTED_TARGETS``
policies. See the provider Gateway API capabilities for the fields,
limits and defaults.

L7 policies with ``action`` of ``REJECT`` will return a ``Forbidden (403)``
response code to the requester.

For TCP listeners, the Amphora provider supports ``REDIRECT_TO_POOL``
policies with ``TLS_SNI`` rules. TCP TLS termination requires
``tcp_tls_termination_v1``. TCP TLS passthrough requires
``tls_sni_passthrough_v1``, with ``tls_sni_suffix_v1`` for wildcard rules.
The redirect pool must use TCP with ``tls_enabled`` set to ``false``.

.. rest_status_code:: success ../http-status.yaml

   - 201

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 500
   - 501
   - 503

Request
-------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action
   - admin_state_up: admin_state_up-default-optional
   - description: description-optional
   - listener_id: listener-id
   - name: name-optional
   - position: l7policy-position-optional
   - project_id: project_id-optional
   - redirect_http_code: l7policy-redirect-http-code-optional
   - redirect_pool_id: l7policy-redirect-pool_id-optional
   - redirect_prefix: l7policy-redirect-prefix-optional
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url-optional
   - rules: l7policy-initial-rules
   - tags: tags-optional

Request Example
----------------

.. literalinclude:: examples/l7policy-create-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/l7policy-create-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action
   - admin_state_up: admin_state_up
   - created_at: created_at
   - description: description
   - id: l7policy-id
   - listener_id: listener-id
   - name: name
   - operating_status: operating_status
   - position: l7policy-position
   - project_id: project_id
   - provisioning_status: provisioning_status
   - redirect_http_code: l7policy-redirect-http-code
   - redirect_pool_id: l7policy-redirect-pool_id
   - redirect_prefix: l7policy-redirect-prefix
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url
   - rules: l7policy-rule-ids
   - tags: tags
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/l7policy-create-response.json
   :language: javascript

Show L7 Policy details
==========================

.. rest_method:: GET /v2/lbaas/l7policies/{l7policy_id}

Shows the details of a L7 policy.

If you are not an administrative user and the L7 policy object does not
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

Curl Example
------------

.. literalinclude:: examples/l7policy-show-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action
   - admin_state_up: admin_state_up
   - created_at: created_at
   - description: description
   - id: l7policy-id
   - listener_id: listener-id
   - name: name
   - operating_status: operating_status
   - position: l7policy-position
   - project_id: project_id
   - provisioning_status: provisioning_status
   - redirect_http_code: l7policy-redirect-http-code
   - redirect_pool_id: l7policy-redirect-pool_id
   - redirect_prefix: l7policy-redirect-prefix
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url
   - rules: l7policy-rule-ids
   - tags: tags
   - updated_at: updated_at


Response Example
----------------

.. literalinclude:: examples/l7policy-show-response.json
   :language: javascript

Update a L7 Policy
==================

.. rest_method:: PUT /v2/lbaas/l7policies/{l7policy_id}

Updates a L7 policy.

If the request is valid, the service returns the ``Accepted (202)``
response code. To confirm the update, check that the L7 policy
provisioning status is ``ACTIVE``. If the status is
``PENDING_UPDATE``, use a GET operation to poll the L7 policy
object for changes.

This operation returns the updated L7 policy object with the
``ACTIVE``, ``PENDING_UPDATE``, or ``ERROR`` provisioning status.

If a policy is updated with a position that matches that of an existing
policy, then the updated policy is inserted at the given position.

.. rest_status_code:: success ../http-status.yaml

   - 202

.. rest_status_code:: error ../http-status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 500
   - 501

Request
-------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action-optional
   - admin_state_up: admin_state_up-default-optional
   - description: description-optional
   - l7policy_id: path-l7policy-id
   - name: name-optional
   - position: l7policy-position-optional
   - redirect_http_code: l7policy-redirect-http-code-optional
   - redirect_pool_id: l7policy-redirect-pool_id-optional
   - redirect_prefix: l7policy-redirect-prefix-optional
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url-optional
   - tags: tags-optional

Request Example
---------------

.. literalinclude:: examples/l7policy-update-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/l7policy-update-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - action: l7policy-action
   - admin_state_up: admin_state_up
   - created_at: created_at
   - description: description
   - id: l7policy-id
   - listener_id: listener-id
   - name: name
   - operating_status: operating_status
   - position: l7policy-position
   - project_id: project_id
   - provisioning_status: provisioning_status
   - redirect_http_code: l7policy-redirect-http-code
   - redirect_pool_id: l7policy-redirect-pool_id
   - redirect_prefix: l7policy-redirect-prefix
   - redirect_request: l7policy-redirect-request
   - request_url_rewrite: l7policy-request-url-rewrite
   - request_cors: l7policy-request-cors
   - redirect_url: l7policy-redirect-url
   - rules: l7policy-rule-ids
   - tags: tags
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/l7policy-update-response.json
   :language: javascript

Remove a L7 Policy
==================

.. rest_method:: DELETE /v2/lbaas/l7policies/{l7policy_id}

Removes a L7 policy and its associated configuration from the project.

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

Curl Example
------------

.. literalinclude:: examples/l7policy-delete-curl
   :language: bash

Response
--------

There is no body content for the response of a successful DELETE request.
