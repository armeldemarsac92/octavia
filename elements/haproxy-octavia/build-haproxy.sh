#!/bin/bash
set -eu

if [[ $# != 2 ]]; then
    echo "Usage: $0 <HAProxy 3.0.19 source tarball> <output binary>" >&2
    exit 2
fi

element_dir=$(cd -- "$(dirname -- "$0")" && pwd)
tarball=$(realpath -- "$1")
binary=$(realpath -m -- "$2")
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

printf '%s  %s
' \
    85f2743a44e4226a0176926fbc8eebfa5551d22fe5f44366877570b6e18c6664 \
    "$tarball" | sha256sum --check --strict

cd -- "$element_dir"
sha256sum --check --strict <<'HASHES'
0af39e48ca415e0c3a64342a566c547f3fd3b7e4f4207c8a52987daca682cdad  haproxy-3.0.19-strict-dns.patch
3fce16bd97403e140d98f6102f462b8bca136020b00fb49eb719da6b1deb095d  haproxy-3.0.19-require-alpn-h2.patch
50787d7dddd98c52e990282f24aa406a7e83465dc39d61f087dab110bc0c391d  haproxy-3.0.19-backend-sans.patch
HASHES

tar -xzf "$tarball" -C "$work_dir"
cd -- "$work_dir/haproxy-3.0.19"
for patch_name in haproxy-3.0.19-strict-dns.patch \
    haproxy-3.0.19-require-alpn-h2.patch haproxy-3.0.19-backend-sans.patch; do
    patch --batch --forward --fuzz=0 -p1 -i "$element_dir/$patch_name"
done

LC_ALL=C SOURCE_DATE_EPOCH=1773936536 make \
    TARGET=linux-glibc USE_OPENSSL=1 USE_SYSTEMD=1 \
    EXTRAVERSION=-octavia-strict-dns-v1-h2-alpn-v1-backend-sans-v1
install -m 0755 haproxy "$binary"
