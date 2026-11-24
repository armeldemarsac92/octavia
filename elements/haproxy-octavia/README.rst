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
applies the strict DNS, required HTTP/2 ALPN and explicit SAN patches, in that
order, with zero fuzz.

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
