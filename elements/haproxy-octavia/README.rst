Element to install an Octavia Amphora with an haproxy backend.



Strict DNS authentication for backend TLS
========================================

The ``backend_tls_hostname_v1`` pool capability requires the Octavia HAProxy
build. This build verifies DNS subject alternative names through OpenSSL before
transferring traffic. The distribution binary retains its usual behavior for
other Octavia deployments.

Build the binary on the target image distribution and architecture, using
HAProxy 3.0.19 with the published tarball SHA-256
``85f2743a44e4226a0176926fbc8eebfa5551d22fe5f44366877570b6e18c6664``.
Apply ``haproxy-3.0.19-strict-dns.patch`` and then
``haproxy-3.0.19-require-alpn-h2.patch`` from this element with ``patch -p1``
inside the extracted source directory. Build with::

    make TARGET=linux-glibc USE_OPENSSL=1 USE_SYSTEMD=1 \
        EXTRAVERSION=-octavia-strict-dns-v1-h2-alpn-v1

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
HTTP/2 before sending application data, including TLS health checks. It uses
a full handshake on every new TLS connection and disables TLS early data.
Enable ``[api_settings] enabled_backend_tls_h2_alpn_providers`` after those same
upgrades with the combined binary. Older strict DNS binaries remain compatible
with pools which only require hostname authentication.
