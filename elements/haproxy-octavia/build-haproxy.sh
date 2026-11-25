#!/bin/bash
set -eu

if [[ $# != 2 && $# != 3 ]]; then
    echo "Usage: $0 <HAProxy 3.0.19 source tarball> <output binary> [Lua 5.4.9 source tarball]" >&2
    exit 2
fi

element_dir=$(cd -- "$(dirname -- "$0")" && pwd)
tarball=$(realpath -- "$1")
binary=$(realpath -m -- "$2")
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
build_suffix=-octavia-strict-dns-v1-h2-alpn-v1-backend-sans-v1-http-policy-v1-http-mirror-v1-listener-auth-v1-backend-retry-budget-v1
lua_options=()
if [[ $# == 3 ]]; then
    lua_tarball=$(realpath -- "$3")
    printf '%s  %s\n' \
        2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6 \
        "$lua_tarball" | sha256sum --check --strict
    tar -xzf "$lua_tarball" -C "$work_dir"
    lua_source="$work_dir/lua-5.4.9/src"
    LC_ALL=C SOURCE_DATE_EPOCH=1773936536 make -C "$lua_source" \
        linux MYCFLAGS=-fPIC
    lua_options=(USE_LUA=1 "LUA_INC=$lua_source" "LUA_LIB=$lua_source"
                 LUA_LIB_NAME=lua)
    build_suffix+=-listener-otlp-v1
fi

printf '%s  %s
' \
    85f2743a44e4226a0176926fbc8eebfa5551d22fe5f44366877570b6e18c6664 \
    "$tarball" | sha256sum --check --strict

cd -- "$element_dir"
sha256sum --check --strict <<'HASHES'
0af39e48ca415e0c3a64342a566c547f3fd3b7e4f4207c8a52987daca682cdad  haproxy-3.0.19-strict-dns.patch
3fce16bd97403e140d98f6102f462b8bca136020b00fb49eb719da6b1deb095d  haproxy-3.0.19-require-alpn-h2.patch
50787d7dddd98c52e990282f24aa406a7e83465dc39d61f087dab110bc0c391d  haproxy-3.0.19-backend-sans.patch
4b48556f1b54ab2633c818b4aebabff3b5b3040c1a64a4cd093cb1eed752dd4e  haproxy-3.0.19-http-policy.patch
7d1fba6e89ac26f706b4eedca3e804be8b63c1289402179f3ae366579413f7dc  haproxy-3.0.19-http-mirror.patch
dfe62edf7729bb332753384c13d6b58488d0c8c19f9a0651c8b18d8dbce89891  haproxy-3.0.19-listener-auth.patch
692ebf63778ca21ad3442e85e17d66b405513ad63418a806f8695705573e20ad  haproxy-3.0.19-backend-retry-budget.patch
HASHES

tar -xzf "$tarball" -C "$work_dir"
cd -- "$work_dir/haproxy-3.0.19"
for patch_name in haproxy-3.0.19-strict-dns.patch \
    haproxy-3.0.19-require-alpn-h2.patch haproxy-3.0.19-backend-sans.patch \
    haproxy-3.0.19-http-policy.patch haproxy-3.0.19-http-mirror.patch \
    haproxy-3.0.19-listener-auth.patch haproxy-3.0.19-backend-retry-budget.patch; do
    patch --batch --forward --fuzz=0 -p1 -i "$element_dir/$patch_name"
done

LC_ALL=C SOURCE_DATE_EPOCH=1773936536 make \
    TARGET=linux-glibc USE_OPENSSL=1 USE_SYSTEMD=1 \
    "${lua_options[@]}" "EXTRAVERSION=$build_suffix"
install -m 0755 haproxy "$binary"
