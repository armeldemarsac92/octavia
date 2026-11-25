.. -*- rst -*-

List Pools
==========

.. rest_method:: GET /v2/lbaas/pools

Lists all pools for the project.

Use the ``fields`` query parameter to control which fields are
returned in the response body. Additionally, you can filter results
by using query string parameters. For information, see :ref:`filtering`.

Administrative users can specify a project ID that is different than their own
to list pools for other projects.

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

.. literalinclude:: examples/pools-list-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - alpn_protocols: alpn_protocols-pool
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - tcp_connection_rejection: tcp-connection-rejection
   - ca_tls_container_ref: ca_tls_container_ref
   - created_at: created_at
   - crl_container_ref: crl_container_ref
   - description: description
   - healthmonitor_id: healthmonitor-id
   - id: pool-id
   - lb_algorithm: lb-algorithm
   - listeners: listener-ids
   - loadbalancers: loadbalancer-ids
   - members: member-ids
   - name: name
   - operating_status: operating_status
   - project_id: project_id
   - protocol: protocol-pools
   - provisioning_status: provisioning_status
   - session_persistence: session_persistence
   - tags: tags
   - tls_ciphers: tls_ciphers
   - tls_container_ref: tls_container_ref
   - tls_enabled: tls_enabled
   - tls_versions: tls_versions
   - udp_packet_drop: udp-packet-drop
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/pools-list-response.json
   :language: javascript

Create Pool
===========

.. rest_method:: POST /v2/lbaas/pools

Creates a pool for a load balancer.

The pool defines how requests should be balanced across the backend
member servers.

This operation provisions a pool by using the configuration that
you define in the request object. After the API validates the
request and starts the provisioning process, the API returns a
response object, which contains a unique ID.

In the response, the pool :ref:`provisioning status<prov_status>` is
``ACTIVE``, ``PENDING_CREATE``, or ``ERROR``.

If the status is ``PENDING_CREATE``, issue GET
``/v2/lbaas/pools/{pool_id}`` to view the progress of
the provisioning operation. When the pool status changes
to ``ACTIVE``, the pool is successfully provisioned and
is ready for further configuration.

At a minimum, you must specify these pool attributes:

- ``protocol`` The protocol for which this pool and its members
  listen. A valid value is ``HTTP``, ``HTTPS``, ``PROXY``, ``PROXYV2``,
  ``SCTP``, ``TCP``, or ``UDP``.

- ``lb_algorithm`` The load-balancer algorithm, such as
  ``ROUND_ROBIN``, ``LEAST_CONNECTIONS``, ``SOURCE_IP`` and ``SOURCE_IP_PORT``,
  that distributes traffic to the pool members. The load-balancer
  provider must support this algorithm.

- ``listener_id`` The ID of the listener in which this pool
  becomes the default pool. Each listener has only one default
  pool.

  ---OR---

- ``loadbalancer_id`` The ID of the load balancer under which this
  pool will be created.  Each load balancer can have zero or more pools
  associated with it.  These pools can be used for L7policies.

.. note::
   Either ``listener_id`` or ``loadbalancer_id`` must be specified.

Some attributes receive default values if you omit them from the
request:

- ``admin_state_up`` Default is ``true``.

- ``name`` Default is an empty string.

- ``description`` Default is an empty string.

If the API cannot fulfill the request due to insufficient data or
data that is not valid, the service returns the HTTP ``Bad Request
(400)`` response code with information about the failure in the
response body. Validation errors require that you correct the error
and submit the request again.

Specifying a project_id is deprecated.  The pool will inherit the
project_id of the parent load balancer.

You can configure all documented features of the pool at creation time by
specifying the additional elements or attributes in the request.

To create a pool, the parent load balancer must have an ``ACTIVE``
provisioning status.

``SOURCE_IP_PORT`` algorithm is available from version 2.13.


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
   - alpn_protocols: alpn_protocols-pool-optional
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - ca_tls_container_ref: ca_tls_container_ref-optional
   - crl_container_ref: crl_container_ref-optional
   - description: description-optional
   - lb_algorithm: lb-algorithm
   - listener_id: listener-id-pool-optional
   - loadbalancer_id: loadbalancer-id-pool-optional
   - name: name-optional
   - project_id: project_id-optional-deprecated
   - protocol: protocol-pools
   - session_persistence: session_persistence-optional
   - tags: tags-optional
   - tls_enabled: tls_enabled-optional
   - tls_ciphers: tls_ciphers-optional
   - tls_container_ref: tls_container_ref-optional
   - tls_versions: tls_versions-optional

.. _session_persistence:

Pool Session Persistence
------------------------

Pool session persistence tells the load balancer to attempt to send future
requests from a client to the same backend member as the initial request.

When the pool has no session persistence, the session persistence object is
``null``.

Octavia currently support three session persistence methods:

+-----------------+----------------------------------------------------------+
| Method          | Description                                              |
+=================+==========================================================+
| ``APP_COOKIE``  | Use the specified ``cookie_name`` send future requests   |
|                 | to the same member.                                      |
+-----------------+----------------------------------------------------------+
| ``HTTP_COOKIE`` | The load balancer will generate a cookie that is         |
|                 | inserted into the response.  This cookie will be used to |
|                 | send future requests to the same member.                 |
+-----------------+----------------------------------------------------------+
| ``SOURCE_IP``   | The source IP address on the request will be hashed to   |
|                 | send future requests to the same member.                 |
+-----------------+----------------------------------------------------------+

For an HTTP pool, a provider advertising ``http_cookie_name_v1`` accepts
an optional ``cookie_name`` for ``HTTP_COOKIE``. Use 1 to 255 ASCII
letters, digits, underscores, dots or hyphens. The browser-reserved
prefixes ``__Host-`` (including ``__Host-Http-``), ``__Secure-`` and
``__Http-`` are rejected regardless of case. In a shared client cookie
scope, use distinct names for unrelated backends. Pools in the same
project can share a name to preserve affinity to the same member address
and port across routes. Member identifiers only affect load balancing.

On Amphora, when there is no stored absolute timeout, omitting the name or
setting it to ``null`` in an ``HTTP_COOKIE`` object uses the default name
``SRV``. Omitting the whole ``session_persistence`` object in a pool update
preserves the current settings. Setting the object to ``null`` removes session
persistence.

For an HTTP pool, a provider advertising ``http_cookie_path_v1`` accepts
``cookie_path`` for any generated ``HTTP_COOKIE``, including one using the
default cookie name. The API uses the string exactly as supplied, including
an empty string. A new pool with no configured path uses ``Path=/``.
Omitting the field on an update preserves an existing path while the
persistence type stays the same. Set the field to ``null`` or ``/`` to
restore the root path, including after regional discovery is disabled.
An update that supplies only ``cookie_path`` keeps an enrolled cookie name.
Pool GET includes ``cookie_path`` when a custom path is configured.
When the provider cannot apply a configured path across the Amphorae,
the affected pool reports ``ERROR``. After reloading, Amphorae balance
traffic for the pool without cookie affinity until the whole topology
supports the path again.

A provider advertising ``http_cookie_absolute_timeout_v1`` also accepts
``cookie_absolute_timeout_ms`` and ``cookie_scope`` together on a named
``HTTP_COOKIE`` HTTP pool. By default the cookie lasts for the browser
session. The load balancer accepts it only if its age is nonnegative and
below the configured timeout. A request that keeps its member keeps the
original expiry.

In a pool update, omitting both fields preserves a stored absolute timeout.
When supplying or preserving a timeout, Octavia uses the enrolled name if
omitted on an HTTP_COOKIE update. When changing the cookie name or
persistence type, explicitly replace
or clear the policy. Set both fields to ``null`` to clear the absolute
timeout. Pool GET includes both fields while configured and omits them after
removal. Explicit removal remains available after regional discovery is
disabled.

A provider advertising ``http_cookie_permanent_v1`` accepts the boolean
``cookie_permanent`` with that named cookie, timeout and scope. With
``true``, a newly issued cookie has the configured path and ``Max-Age``
equal to the timeout rounded up to a whole second. A zero timeout uses
``Max-Age=0``. The load balancer still checks the exact configured
millisecond timeout. Reusing a valid cookie for the same member leaves
its original expiry in place. Changing the mode causes existing cookies
to be replaced on the next request.

Omitting ``cookie_permanent`` in an update preserves the mode while the
absolute timeout remains set. Set it to ``false`` to return to a browser
session cookie, including after permanent cookie discovery is disabled.
Replacing the name, scope or timeout of a permanent cookie requires the
provider to advertise permanent cookie support.
Clearing the timeout or removing session persistence clears this setting.
Pool GET includes ``cookie_permanent`` only when it is ``true``.

Pool Session Persistence Object
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. rest_parameters:: ../parameters.yaml

   - type: session_persistence_type
   - cookie_name: session_persistence_cookie
   - cookie_path: session_persistence_cookie_path
   - cookie_absolute_timeout_ms: session_persistence_cookie_absolute_timeout_ms
   - cookie_scope: session_persistence_cookie_scope
   - cookie_permanent: session_persistence_cookie_permanent
   - persistence_timeout: session_persistence_timeout
   - persistence_granularity: session_persistence_granularity

Pool Session Persistence Object Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: examples/pool-session-persistence-obj.json
   :language: javascript

Request Example
----------------

.. literalinclude:: examples/pool-create-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/pool-create-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - alpn_protocols: alpn_protocols-pool
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - tcp_connection_rejection: tcp-connection-rejection
   - ca_tls_container_ref: ca_tls_container_ref
   - created_at: created_at
   - crl_container_ref: crl_container_ref
   - description: description
   - healthmonitor_id: healthmonitor-id
   - id: pool-id
   - lb_algorithm: lb-algorithm
   - listeners: listener-ids
   - loadbalancers: loadbalancer-ids
   - members: member-ids
   - name: name
   - operating_status: operating_status
   - project_id: project_id
   - protocol: protocol-pools
   - provisioning_status: provisioning_status
   - session_persistence: session_persistence
   - tags: tags
   - tls_enabled: tls_enabled
   - tls_ciphers: tls_ciphers
   - tls_container_ref: tls_container_ref
   - tls_versions: tls_versions
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/pool-create-response.json
   :language: javascript

Show Pool details
=================

.. rest_method:: GET /v2/lbaas/pools/{pool_id}

Shows the details of a pool.

If you are not an administrative user and the parent load balancer does not
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
   - pool_id: path-pool-id

Curl Example
------------

.. literalinclude:: examples/pool-show-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - alpn_protocols: alpn_protocols-pool
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - tcp_connection_rejection: tcp-connection-rejection
   - ca_tls_container_ref: ca_tls_container_ref
   - created_at: created_at
   - crl_container_ref: crl_container_ref
   - description: description
   - healthmonitor_id: healthmonitor-id
   - id: pool-id
   - lb_algorithm: lb-algorithm
   - listeners: listener-ids
   - loadbalancers: loadbalancer-ids
   - members: member-ids
   - name: name
   - operating_status: operating_status
   - project_id: project_id
   - protocol: protocol-pools
   - provisioning_status: provisioning_status
   - session_persistence: session_persistence
   - tags: tags
   - tls_enabled: tls_enabled
   - tls_ciphers: tls_ciphers
   - tls_container_ref: tls_container_ref
   - tls_versions: tls_versions
   - udp_packet_drop: udp-packet-drop
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/pool-show-response.json
   :language: javascript

Update a Pool
=============

.. rest_method:: PUT /v2/lbaas/pools/{pool_id}

Update an existing pool.

If the request is valid, the service returns the ``Accepted (202)``
response code. To confirm the update, check that the pool provisioning
status is ``ACTIVE``. If the status is ``PENDING_UPDATE``, use a GET
operation to poll the pool object for changes.

This operation returns the updated pool object with the
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
   - alpn_protocols: alpn_protocols-pool-optional
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - ca_tls_container_ref: ca_tls_container_ref-optional
   - crl_container_ref: crl_container_ref-optional
   - description: description-optional
   - lb_algorithm: lb-algorithm-optional
   - name: name-optional
   - pool_id: path-pool-id
   - session_persistence: session_persistence-optional
   - tags: tags-optional
   - tls_enabled: tls_enabled-optional
   - tls_ciphers: tls_ciphers-optional
   - tls_container_ref: tls_container_ref-optional
   - tls_versions: tls_versions-optional

Request Example
---------------

.. literalinclude:: examples/pool-update-request.json
   :language: javascript

Curl Example
------------

.. literalinclude:: examples/pool-update-curl
   :language: bash

Response Parameters
-------------------

.. rest_parameters:: ../parameters.yaml

   - admin_state_up: admin_state_up
   - alpn_protocols: alpn_protocols-pool
   - backend_h2c: backend-h2c
   - backend_tls_hostname: backend-tls-hostname
   - backend_tls_require_h2: backend-tls-require-h2
   - backend_tls_subject_alt_names: backend-tls-subject-alt-names
   - backend_retry_budget: backend-retry-budget
   - tcp_connection_rejection: tcp-connection-rejection
   - ca_tls_container_ref: ca_tls_container_ref
   - created_at: created_at
   - crl_container_ref: crl_container_ref
   - description: description
   - healthmonitor_id: healthmonitor-id
   - id: pool-id
   - lb_algorithm: lb-algorithm
   - listeners: listener-ids
   - loadbalancers: loadbalancer-ids
   - members: member-ids
   - name: name
   - operating_status: operating_status
   - project_id: project_id
   - protocol: protocol-pools
   - provisioning_status: provisioning_status
   - session_persistence: session_persistence
   - tags: tags
   - tls_enabled: tls_enabled
   - tls_ciphers: tls_ciphers
   - tls_container_ref: tls_container_ref
   - tls_versions: tls_versions
   - updated_at: updated_at

Response Example
----------------

.. literalinclude:: examples/pool-update-response.json
   :language: javascript

Remove a Pool
=============

.. rest_method:: DELETE /v2/lbaas/pools/{pool_id}

Removes a pool and its associated configuration from the load balancer.

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

   - pool_id: path-pool-id

Curl Example
------------

.. literalinclude:: examples/pool-delete-curl
   :language: bash

Response
--------

There is no body content for the response of a successful DELETE request.
