Element to install an Octavia Amphora with an haproxy backend.



Strict DNS authentication for backend TLS
========================================

The ``backend_tls_hostname_v1`` pool capability requires the Octavia HAProxy
build. This build verifies DNS subject alternative names through OpenSSL before
transferring traffic. The distribution binary retains its usual behavior for
other Octavia deployments.

Build the binary on the target image distribution and architecture::

    ./elements/haproxy-octavia/build-haproxy.sh \
        /path/to/haproxy-3.0.19.tar.gz /path/to/haproxy

The script checks the HAProxy 3.0.19 tarball and each patch by SHA-256. It
applies the strict DNS, required HTTP/2 ALPN, explicit SAN, HTTP policy,
HTTP mirror, listener authorization, retry budget and route retry backoff
patches, in that order, with zero fuzz.

Set ``DIB_OCTAVIA_HAPROXY_BINARY`` to the absolute path of the resulting binary
when running Octavia's ``diskimage-create.sh``. The element checks the binary in
the target filesystem before installing it at ``/usr/sbin/haproxy``.

The Amphora agent reports support based on its configured HAProxy executable.
An absent or unknown runtime capability fails protected listener rendering.
Roll out the patched agent and HAProxy to the regional Amphora fleet and the
Octavia database, octavia-lib, API and workers before adding the provider to
``[api_settings] enabled_backend_tls_hostname_providers``. During withdrawal,
leave the upgraded workers and Amphora binaries in place while traffic drains
from protected pools. A package upgrade that replaces the patched HAProxy
requires a new verified build before that image can serve protected pools.

Listener OTLP/HTTP tracing
==========================

Build the tracing variant with the pinned Lua 5.4.9 source archive as the
third argument to the existing build command::

    ./elements/haproxy-octavia/build-haproxy.sh \
        /path/to/haproxy-3.0.19.tar.gz /path/to/haproxy \
        /path/to/lua-5.4.9.tar.gz

The script verifies and statically links Lua. With
``DIB_OCTAVIA_HAPROXY_BINARY`` set to this variant, the element installs the
Lua instrumentation and a tmpfiles entry for the private Unix sockets. The
Amphora agent checks the build marker, Lua support and presence of the
instrumentation file before reporting ``listener_otlp_tracing_v1``.
The updated image also installs the versioned Lua script
``/var/lib/octavia/octavia-telemetry-sampling-v1.lua``. The upgraded agent
requires this file as well as the tracing capability before reporting
``listener_otlp_sampling_v1``. It uses the same Lua-enabled HAProxy build.
Opt in through ``[api_settings] enabled_listener_otlp_sampling_providers``
only after qualifying the script and agents across the eligible fleet.
Apply database revision ``f831dfeaac94`` and update all regional API processes
and workers before accepting tracing updates. The worker pairs each tracing
publication with an ID that the agent checks against the running HAProxy
configuration. Older agents can reload the application configuration and
omit the acknowledgement. Upgrade them and retry the affected tracing
requests or withdrawals to confirm publication.

Run the local wire check using the built binary and an OpenTelemetry Collector
binary with the OTLP receiver and file exporter. From the Octavia checkout,
with its Python dependencies installed::

    PYTHONPATH=. python3 elements/haproxy-octavia/test-telemetry-wire.py \
        /path/to/haproxy /path/to/otelcol /path/to/evidence-directory

Add ``--sampling`` to exercise propagation and collector delivery for
zero, full and fractional rates with the same harness and binaries.
Use ``--attributes --sampling-lua /path/to/previous-sampling.lua`` to check
attribute listeners alongside the previous sampling script. Repeat with
``--sampling-first`` to reverse the load order.

The ``backend_tls_h2_alpn_v1`` pool capability additionally verifies negotiated
HTTP/2 before sending application data, including TLS health checks. HTTP
health probes on these pools send HTTP/2 with the monitor's configured domain
name or the pool's SNI hostname as the request authority. The capability
requires a full handshake on every new TLS connection and disables early data.
Enable ``[api_settings] enabled_backend_tls_h2_alpn_providers`` after those same
upgrades with the combined binary. Older strict DNS binaries remain compatible
with pools which only require hostname authentication.

The ``backend_tls_subject_alt_names_v1`` pool capability additionally allows
an explicit list of DNS and URI identities. The same static SNI is sent to
the backend, and both the CA chain and a matching leaf SAN are required on
TLS connections and TLS health checks. Once the combined binary is installed
across the fleet, enable
``[api_settings] enabled_backend_tls_subject_alt_names_providers`` along with
``enabled_backend_tls_hostname_providers``.

Listener OTLP span attributes
=============================

The Amphora image installs
``/var/lib/octavia/octavia-telemetry-span-attributes-v1.lua`` with the same
Lua-enabled HAProxy build. The agent reports
``listener_otlp_span_attributes_v1`` when tracing and this script are
available. Qualify eligible Amphora images, API processes and workers before
including the provider in
``[api_settings] enabled_listener_otlp_span_attributes_providers``. Enable
``enabled_listener_otlp_tracing_providers`` alongside it. Sampling has its
own opt-in and can be combined with span attributes.

``otlp_tracing.attributes`` is a list of attributes with distinct ``name``
values. Each item has ``source_type`` set to ``Literal`` with
``literal_value``, ``Header`` with ``header_name`` or ``Attribute`` with
``attribute_key``. Literal strings are encoded as data in HAProxy's
configuration and exported as OTLP string values.

The listener captures incoming request headers before proxy filters and
separately reads outgoing response headers after response processing. For
``Header``, the first full field line from the request takes precedence,
including commas within the field. The first response field is used when
the request header is absent. If both headers are absent or the selected
value is invalid UTF-8, the attribute is omitted. Collecting headers leaves
the application headers intact.

``Attribute`` supports ``http.request.method`` (incoming method), ``url.path``
(incoming path without query), ``url.scheme`` (from frontend TLS) and
``http.response.status_code`` (outgoing status). The status is an OTLP
integer and the other values are strings. The standard
``http.response.status_code`` output key is reserved. It may explicitly
reference the same built-in without creating a duplicate.

The default known HTTP methods are CONNECT, DELETE, GET, HEAD, OPTIONS,
PATCH, POST, PUT, QUERY and TRACE.
Unknown methods are exported as ``_OTHER``. Set
``OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS`` in the Amphora HAProxy process
environment to replace the entire list with comma-separated, case-sensitive
method names.

The API returns attributes sorted by name with lowercase header names and
omits empty lists. Setting the tracing object without attributes withdraws
the custom attributes while retaining tracing when the base profile is still
enabled. The published status is tied to the complete desired tracing
configuration and only reaches ``ACTIVE`` when each peer confirms its
reload with the requested profile. A peer missing attribute support loads
the application listener without tracing for that profile.

Use ``--attributes`` in the local wire check to capture typed spans in a
real Collector and verify that HTTP traffic continues when the Amphora
does not report the capability.

HTTP request budgets and retries
================================

The combined binary exposes this HTTP request action for a matched rule::

    http-request octavia-http-policy <request-ms> <backend-ms> <retries> <codes> [<backoff-ms>] if ...

Each of the first three arguments accepts a decimal literal or ``default``.
Duration literals are signed 64-bit milliseconds. Zero explicitly disables a
deadline. A default duration leaves HAProxy's normal inactivity timers in
place without adding an absolute deadline. The request deadline begins when the
action selects the policy and covers backend queuing, connection setup and all
attempts. The backend deadline applies from the first request bytes handed to
the backend protocol through the end of its response.

The retry count is the maximum number of additional attempts. A default count
retains HAProxy's backend retry policy and requires ``none`` as the fourth
argument. Use ``none`` when no HTTP response codes should trigger a retry.
The other accepted values are comma-separated selections of 500, 502, 503 and
504. A positive retry count also covers connection failures before sending, an
HTTP/2 REFUSED_STREAM and expiration of an attempt before final headers. A
request deadline takes precedence over further attempts. A zero count disables
retries.

The optional fifth argument sets a fixed delay from each retryable failure to
the next attempt. It accepts a nonnegative 64-bit signed millisecond value.
An explicit zero starts the retry immediately. Omission or ``default`` uses
HAProxy's native timing. The request deadline runs during the delay and can
end the request before the next attempt. The backend deadline starts anew with
the first request bytes of that attempt.

Replaying an already-sent request requires a complete request in HAProxy's
replay buffer. This also applies to a small body if its last bytes arrive after
sending starts.
After final response bytes reach the client protocol, expiration interrupts that
response without sending another status. A successful HTTP upgrade ends the
HTTP budget when the handshake response is handed to the client protocol.

Streaming HTTP request mirrors
==============================

The ``http_request_mirror_v1`` build supports a filter and HTTP request rule
for a matched Octavia policy::

    filter octavia-mirror /run/octavia/mirror
    http-request octavia-mirror <pool-uuid> <numerator> <denominator> if ...

The denominator is a positive decimal integer up to INT_MAX. The numerator
is between zero and the denominator. Each rule samples independently. A
selected rule snapshots the request line and end-to-end headers as they
appear at that point, then copies body data and trailers as they arrive.
The action can run in the HTTP backend selected by a frontend that has
the filter. Filters within one HAProxy process share the socket directory.
An already complete request can be mirrored when a later rule issues a
local reply.
The copy uses HTTP/1.1 on the private hop. A dedicated PROXYv2 TLV carries the
HTTP/2 scheme and the client TLS SNI. The delivery listener reads it on the
mode 600 UNIX socket after verifying the peer has the worker UID. CONNECT
and HTTP Upgrade tunnels are excluded.

The delivery pool is a dedicated HTTP ``listen`` section with its own server
configuration and a single private bind::

    bind /run/octavia/mirror/<pool-uuid>.sock user nobody mode 600 octavia-mirror-socket
    option abortonclose
    retries 0
    http-request disable-l7-retry

The listener uses the pool's configured members, balance algorithm and
backend TLS settings. The action accepts only pool UUIDs, and configuration
validation requires the corresponding private listener for each nonzero
ratio. The DIB element installs a systemd-tmpfiles entry for the socket
directory. The worker UID must be able to connect to the socket.

Each HAProxy worker process can run up to 128 copies with eight waiting
``tune.bufsize`` buffers and one HTTP client input buffer per copy. The
private listener does not consume the public connection quota. Connecting
to the UNIX socket has a two-second timeout, and the copy has a five-second
inactivity timeout and a 30-second total deadline. A copy can be dropped if
resources are scarce, the source upload is interrupted or its receiver falls
behind. Only a complete upload gets an end-of-message marker. The active
count and drop counters are available through ``show octavia mirrors`` on the
HAProxy stats socket.

Run the loopback qualification with OpenSSL, Python and the ``h2`` package::

    python elements/haproxy-octavia/test-request-mirror.py /path/to/haproxy -v


HTTP listener authorization
===========================

The ``listener_request_filters_v1`` capability supports ordered HTTP
authorization checks before route selection. Install the updated database,
octavia-lib, API, workers and Amphora agent and HAProxy image before enabling
``[api_settings] enabled_listener_request_filter_providers`` for Amphora.
The agent confirms the running image's configured HAProxy binary includes the
authorization filter. Existing listeners without request filters still render
on older images. Keep the updated runtime available while clearing filters on
existing listeners before rolling back the image to a version without the action.

An authorizer is a plain HTTP pool on the same load balancer and project with
the ``gw-api-listener-auth-pool-v1`` tag. The DIB element creates
``/run/octavia/listener-auth`` through systemd-tmpfiles. HAProxy opens a private
mode-600 Unix listener per authorizer pool and uses the pool's members and
health checks. It sends the request method and prefixed path with query
parameters, the original Host and Authorization when present, selected extra
request headers and Content-Length 0. HAProxy uses the response status and
headers and stops reading at the end of the headers.

Only status 200 advances the chain. An authorization failure responds with 401
or 403. Unavailable authorizers and exhausted checks respond with 503. Each
check has a three-second deadline and a worker process can run at most 256
checks concurrently. Authorized header values can affect the single ensuing
route selection. Host, authority and HTTP framing retain their original values.

Run the loopback qualification from the Octavia source tree with its Python
runtime dependencies, OpenSSL, a curl build with HTTP/2 and the patched
HAProxy installed::

    PYTHONPATH=. python elements/haproxy-octavia/test-listener-auth.py         /path/to/haproxy -v


HTTP backend retry budgets
==========================

The ``backend_retry_budget_v1`` capability shares rolling request and
retry counts across the HTTP pools serving a Service in one HAProxy
process. It applies to connection retries and replayable HTTP retries
already selected by the backend or its per-route request policy. The
proxy returns 503 when a retry would exceed both configured allowances.
Each Amphora process keeps its own history.
When a route sets a positive retry delay, the backend slot is released during
the wait. The budget admits and counts a retry once it has left any backend
queue and is about to connect. An expiry during the delay or in the queue
leaves the budget available for other requests.

Run the loopback checks with the patched binary::

    python elements/haproxy-octavia/test-backend-retry-budget.py /path/to/haproxy -v
