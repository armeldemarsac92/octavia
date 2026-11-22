# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import os
from types import SimpleNamespace
from unittest import mock

from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.common import constants
from octavia.common import exceptions
from octavia.common.jinja.haproxy.combined_listeners import jinja_cfg
from octavia.tests.unit import base
from octavia.tests.unit.common.sample_configs import sample_configs_combined

CONF = cfg.CONF


class TestHaproxyCfg(base.TestCase):
    DEFAULT_TLS_CIPHERS = ':'.join(
        sorted(set(constants.CIPHERS_OWASP_SUITE_B.split(':')) -
               set(constants.DEFAULT_TLS_1_3_SUPPORTED_CIPHERS.split(':'))))
    DEFAULT_TLS_CIPHERSUITES = ':'.join(
        sorted(set(constants.CIPHERS_OWASP_SUITE_B.split(':')) &
               set(constants.DEFAULT_TLS_1_3_SUPPORTED_CIPHERS.split(':'))))

    def setUp(self):
        super().setUp()
        self.jinja_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs')

    def test_get_template(self):
        template = self.jinja_cfg._get_template()
        self.assertEqual('haproxy.cfg.j2', template.name)

    def test_render_template_tls(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              "ca-file /var/lib/octavia/certs/sample_loadbalancer_id_1/"
              "client_ca.pem verify required crl-file /var/lib/octavia/"
              "certs/sample_loadbalancer_id_1/SHA_ID.pem"
              f" ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              "no-sslv3 no-tlsv10 no-tlsv11 alpn "
              f"{','.join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n")
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, sni=True,
                client_ca_cert=True, client_crl_cert=True)],
            tls_tupe)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tlsv1_2_ciphers_only(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        tlsv1_2_ciphers = ("ECDHE-ECDSA-AES128-GCM-SHA256:"
                           "ECDHE-RSA-AES128-GCM-SHA256")
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              "ca-file /var/lib/octavia/certs/sample_loadbalancer_id_1/"
              "client_ca.pem verify required crl-file /var/lib/octavia/"
              "certs/sample_loadbalancer_id_1/SHA_ID.pem"
              f" ciphers {tlsv1_2_ciphers} "
              "no-sslv3 no-tlsv10 no-tlsv11 alpn "
              f"{','.join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n")
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, sni=True,
                client_ca_cert=True, client_crl_cert=True,
                tls_ciphers=tlsv1_2_ciphers)],
            tls_tupe)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tlsv1_3_ciphers_only(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        tlsv1_3_ciphers = ("TLS_AES_256_GCM_SHA384:"
                           "TLS_CHACHA20_POLY1305_SHA256")
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              "ca-file /var/lib/octavia/certs/sample_loadbalancer_id_1/"
              "client_ca.pem verify required crl-file /var/lib/octavia/"
              "certs/sample_loadbalancer_id_1/SHA_ID.pem"
              f" ciphersuites {tlsv1_3_ciphers} "
              "no-sslv3 no-tlsv10 no-tlsv11 alpn "
              f"{','.join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n")
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, sni=True,
                client_ca_cert=True, client_crl_cert=True,
                tls_ciphers=tlsv1_3_ciphers)],
            tls_tupe)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_sni(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              f"    bind 10.0.0.2:443 ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"no-sslv3 no-tlsv10 no-tlsv11 alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_ciphers(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 ssl crt-list "
              f"{FAKE_CRT_LIST_FILENAME} "
              f"no-sslv3 no-tlsv10 no-tlsv11 alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, tls_ciphers=None)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_versions(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              "ca-file /var/lib/octavia/certs/sample_loadbalancer_id_1/"
              "client_ca.pem verify required crl-file /var/lib/octavia/"
              "certs/sample_loadbalancer_id_1/SHA_ID.pem "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, sni=True,
                client_ca_cert=True, client_crl_cert=True, tls_versions=None)],
            tls_tupe)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_ciphers_or_versions(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 ssl crt-list "
              f"{FAKE_CRT_LIST_FILENAME} "
              f"alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, tls_ciphers=None,
                tls_versions=None)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_alpn(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn_protocols = ['chip', 'dale']
        alpn = ",".join(alpn_protocols)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              f"    bind 10.0.0.2:443 ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"no-sslv3 no-tlsv10 no-tlsv11 alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True,
                alpn_protocols=alpn_protocols)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_alpn(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 ssl crt-list "
              f"{FAKE_CRT_LIST_FILENAME} "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"no-sslv3 no-tlsv10 no-tlsv11\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True,
                alpn_protocols=None)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_alpn_hsts_max_age_only(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000;\"\n"
              "    bind 10.0.0.2:443 ssl crt-list "
              f"{FAKE_CRT_LIST_FILENAME} "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              "no-sslv3 no-tlsv10 no-tlsv11\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True,
                alpn_protocols=None, hsts_include_subdomains=False,
                hsts_preload=False)],
            tls_certs={'cont_id_1':
                       sample_configs_combined.sample_tls_container_tuple(
                           id='tls_container_id',
                           certificate='ImAalsdkfjCert',
                           private_key='ImAsdlfksdjPrivateKey',
                           primary_cn="FakeCN")})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_tls_no_hsts(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="haproxy_amphora", base_cert_dir='/fake_cert_dir')
        FAKE_CRT_LIST_FILENAME = os.path.join(
            CONF.haproxy_amphora.base_cert_dir,
            'sample_loadbalancer_id_1/sample_listener_id_1.pem')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    bind 10.0.0.2:443 "
              f"ssl crt-list {FAKE_CRT_LIST_FILENAME} "
              "ca-file /var/lib/octavia/certs/sample_loadbalancer_id_1/"
              "client_ca.pem verify required crl-file /var/lib/octavia/"
              "certs/sample_loadbalancer_id_1/SHA_ID.pem "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"no-sslv3 no-tlsv10 no-tlsv11 alpn {alpn}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS', tls=True, sni=True,
                client_ca_cert=True, client_crl_cert=True,
                hsts_max_age=None)],
            tls_tupe)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_http(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple()])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_prometheus(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:80\n"
              "    mode http\n"
              "    timeout client 50000\n"
              "    default_backend prometheus-exporter-internal\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        be = ""
        defaults = ("defaults\n"
                    "    log global\n"
                    "    retries 3\n"
                    "    option redispatch\n"
                    "    option splice-request\n"
                    "    option splice-response\n"
                    "    option http-keep-alive\n\n\n\n"
                    "frontend prometheus-exporter-internal-endpoint\n"
                    "    bind 127.0.0.1:9101\n"
                    "    mode http\n"
                    "    no log\n"
                    "    http-request use-service prometheus-exporter if { "
                    "path /metrics }\n"
                    "    http-request reject\n"
                    "    timeout http-request 5s\n"
                    "    timeout client 5s\n"
                    "backend prometheus-exporter-internal\n"
                    "    mode http\n"
                    "    no log\n"
                    "    balance first\n"
                    "    timeout connect 5s\n"
                    "    timeout server 5s\n"
                    "    server prometheus-internal 127.0.0.1:9102")
        logging = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
                   "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
                   "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
                   "%tsc\n\n")

        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto=lib_consts.PROTOCOL_PROMETHEUS, include_pools=False)],
            feature_compatibility={lib_consts.PROTOCOL_PROMETHEUS: True})

        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be, logging=logging, defaults=defaults),
            rendered_obj)

    def test_render_template_additional_vips(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:80\n"
              "    bind 10.0.1.2:80\n"
              "    bind 2001:db8::2:80\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                additional_vips=True)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(frontend=fe),
            rendered_obj)

    def test_render_template_member_backup(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "addr 192.168.1.1 port 9000 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "addr 192.168.1.1 port 9000 "
              "cookie sample_member_id_2 backup\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                monitor_ip_port=True, backup_member=True)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_custom_timeouts(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:80\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 2\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 1\n"
              "    timeout server 3\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                timeout_member_connect=1, timeout_client_data=2,
                timeout_member_data=3)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_null_timeouts(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:80\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie "
              "sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                timeout_member_connect=None, timeout_client_data=None,
                timeout_member_data=None)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    def test_render_template_member_monitor_addr_port(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "addr 192.168.1.1 port 9000 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "addr 192.168.1.1 port 9000 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                monitor_ip_port=True)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_h2c_member_with_http11_monitor_on_another_port(self):
        listener = sample_configs_combined.sample_listener_tuple(
            monitor_ip_port=True, hm_host_http_check=True)
        pool = SimpleNamespace(**listener.pools[0]._asdict(), backend_h2c=True)
        config = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [listener._replace(default_pool=pool, pools=[pool])])
        self.assertIn('option httpchk GET /index.html HTTP/1.1', config)
        members = [line for line in config.splitlines()
                   if line.lstrip().startswith('server ')]
        self.assertEqual(2, len(members))
        for line in members:
            self.assertIn('port 9000', line)
            self.assertIn('proto h2', line)
            self.assertIn('check-proto h1', line)

    def test_backend_tls_hostname_requires_capable_amphora(self):
        hostname = 'backend.example.test'
        listener = sample_configs_combined.sample_listener_tuple()
        values = dict(listener.pools[0]._asdict(), tls_enabled=True,
                      backend_tls_hostname=hostname,
                      ca_tls_certificate_id='ca-certificate')
        pool = SimpleNamespace(**values)
        listeners = [listener._replace(default_pool=pool, pools=[pool])]
        args = (sample_configs_combined.sample_amphora_tuple(), listeners)
        certs = {pool.id: {'ca_cert': '/path/to/backend-ca.pem'}}
        self.assertRaises(driver_except.AmpVersionUnsupported,
                          self.jinja_cfg.render_loadbalancer_obj,
                          *args, tls_certs=certs)
        amp_details = {constants.GATEWAY_CAPABILITY_BACKEND_TLS_HOSTNAME: True}
        self.assertRaises(exceptions.ValidationException,
                          self.jinja_cfg.render_loadbalancer_obj,
                          *args, amp_details=amp_details)
        config = self.jinja_cfg.render_loadbalancer_obj(
            *args, tls_certs=certs, amp_details=amp_details)
        self.assertIn(f'check-ssl check-sni {hostname}', config)
        self.assertIn('ca-file /path/to/backend-ca.pem verify required',
                      config)
        self.assertIn(f'sni str({hostname}) verifyhost-strict {hostname}',
                      config)
        self.assertNotIn('verify none', config)

    def test_disabled_protected_pool_keeps_its_l7_match(self):
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        healthy, target = listener.pools
        policy = listener.l7policies[0]._replace(
            action=constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
            l7rules=[sample_configs_combined.sample_l7rule_tuple(
                'protected-path', type=constants.L7RULE_TYPE_PATH,
                compare_type=constants.L7RULE_COMPARE_TYPE_EQUAL_TO,
                value='/protected')])
        # Both policies match. A closed pool must also prevent a lower
        # weighted policy from winning the same request.
        fallback = policy._replace(
            id='fallback', action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None,
            l7rules=[policy.l7rules[0]._replace(id='fallback-path')],
            targets=[{'weight': 1, 'pool_id': healthy.id}])
        amp = sample_configs_combined.sample_amphora_tuple()
        backend = f'{target.id}:{listener.id}'

        for hostname in ('backend.example.test', None):
            with self.subTest(hostname=hostname):
                disabled = SimpleNamespace(**dict(
                    target._asdict(), enabled=False, tls_enabled=True,
                    backend_tls_hostname=hostname,
                    ca_tls_certificate_id='unavailable-ca'))
                updated = listener._replace(
                    pools=[healthy, disabled], default_pool=healthy,
                    l7policies=[policy._replace(redirect_pool=disabled),
                                fallback])
                rendered = self.jinja_cfg.build_config(
                    amp, [updated], None, haproxy_versions=['3', '0', '19'],
                    amp_details={})
                frontend, _, backends = rendered.partition('\nbackend ')
                protected_route = f'use_backend {backend} if protected-path'
                self.assertIn(
                    f'default_backend {healthy.id}:{listener.id}', frontend)
                self.assertNotIn('verifyhost-strict', rendered)
                self.assertNotIn('ca-file', rendered)
                if hostname is not None:
                    self.assertIn(protected_route, frontend)
                    self.assertIn(
                        f'str({policy.id}) if !{{ var(txn.octavia_l7_policy) '
                        '-m found } protected-path', frontend)
                    routes = [line.strip() for line in frontend.splitlines()
                              if line.lstrip().startswith('use_backend ')]
                    self.assertEqual(protected_route, routes[0])
                    _, _, section = backends.partition(f'{backend}\n')
                    section = section.partition('\nbackend ')[0]
                    self.assertIn('mode http', section)
                    self.assertNotIn('\n    server ', section)
                else:
                    self.assertNotIn(protected_route, frontend)
                    self.assertNotIn(f'{backend}\n', backends)

    def test_render_template_https_real_monitor(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check check-ssl verify none inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check check-ssl verify none inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(proto='HTTPS')])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be), rendered_obj)

    def test_render_template_https_hello_monitor(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTPS', monitor_proto='TLS-HELLO')])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be), rendered_obj)

    def test_render_template_no_monitor_http(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "cookie sample_member_id_2\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(proto='HTTP',
                                                           monitor=False)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be), rendered_obj)

    def test_render_template_disabled_member(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    fullconn {maxconn}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "cookie sample_member_id_2 disabled\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor=False, disabled_member=True)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be), rendered_obj)

    def test_render_template_ping_monitor_http(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option external-check\n"
              "    external-check command /var/lib/octavia/ping-wrapper.sh\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        go = (f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              f"    external-check\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor_proto='PING')])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be, global_opts=go), rendered_obj)

    def test_render_template_ping_monitor_http_insecure_fork(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    load-server-state-from-file global\n"
              "    timeout check 31s\n"
              "    option external-check\n"
              "    external-check command /var/lib/octavia/ping-wrapper.sh\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        go = (
            "    server-state-file /var/lib/octavia/sample_loadbalancer_id_1/"
            "servers-state\n"
            f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
            "    external-check\n    insecure-fork-wanted\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor_proto='PING')],
            feature_compatibility={
                "requires_insecure_fork": True,
                constants.SERVER_STATE_FILE: True})
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be, global_opts=go), rendered_obj)

    def test_render_template_ping_monitor_http_with_cpu_count(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option external-check\n"
              "    external-check command /var/lib/octavia/ping-wrapper.sh\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        go = ("    maxconn 50000\n"
              "    nbthread 6\n"
              "    cpu-map auto:1/1-6 1-6\n"
              "    external-check\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor_proto='PING')],
            amp_details={"cpu_count": 7,
                         "active_tuned_profiles": "virtual-guest amphora"})
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be, global_opts=go), rendered_obj)

    def test_render_template_no_monitor_https(self):
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(proto='HTTPS',
                                                           monitor=False)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be), rendered_obj)

    def test_render_template_health_monitor_http_check(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.1\n"
              "    http-check send hdr Host testlab.com\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor_proto='HTTP', hm_host_http_check=True)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be), rendered_obj)

    def test_render_template_no_persistence_https(self):
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTPS', monitor=False, persistence=False)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be), rendered_obj)

    def test_render_template_no_persistence_http(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTP', monitor=False, persistence=False)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            backend=be), rendered_obj)

    def test_render_template_sourceip_persistence(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    stick-table type ipv6 size 10k\n"
              "    stick on src\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                persistence_type='SOURCE_IP')])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_appcookie_persistence(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    stick-table type string len 64 size 10k\n"
              "    stick store-response res.cook(JSESSIONID)\n"
              "    stick match req.cook(JSESSIONID)\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                persistence_type='APP_COOKIE',
                persistence_cookie='JSESSIONID')])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_unlimited_connections(self):
        sample_amphora = sample_configs_combined.sample_amphora_tuple()
        sample_listener = sample_configs_combined.sample_listener_tuple(
            proto='HTTPS', monitor=False)
        fe = ("frontend {listener_id}\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend {pool_id}:{listener_id}\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN,
            pool_id=sample_listener.default_pool.id,
            listener_id=sample_listener.id)
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = (f"backend {sample_listener.default_pool.id}:"
              f"{sample_listener.id}\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_amphora,
            [sample_listener])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be), rendered_obj)

    def test_render_template_limited_connections(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn 2014\n"
              "    bind 10.0.0.2:443\n"
              "    mode tcp\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        lg = ("    log-format 12345\\ sample_loadbalancer_id_1\\ %f\\ "
              "%ci\\ %cp\\ %t\\ -\\ -\\ %B\\ %U\\ "
              "%[ssl_c_verify]\\ %{+Q}[ssl_c_s_dn]\\ %b\\ %s\\ %Tt\\ "
              "%tsc\n\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode tcp\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    fullconn 2014\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "cookie sample_member_id_2\n\n")
        g_opts = "    maxconn 2014\n\n"
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='HTTPS', monitor=False, connection_limit=2014)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, logging=lg, backend=be, global_opts=g_opts),
            rendered_obj)

    def test_render_template_tls_cachesize(self):
        g_opts = (f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
                  f"    tune.ssl.cachesize 101722232\n\n")
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              "no-sslv3 no-tlsv10 no-tlsv11 alpn "
              f"{','.join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)}\n"
              "    mode http\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        tls_tupe = {'cont_id_1':
                    sample_configs_combined.sample_tls_container_tuple(
                        id='tls_container_id',
                        certificate='imaCert1', private_key='imaPrivateKey1',
                        primary_cn='FakeCN'),
                    'cont_id_ca': 'client_ca.pem',
                    'cont_id_crl': 'SHA_ID.pem'}
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                proto='TERMINATED_HTTPS')],
            tls_tupe,
            # 32GiB total
            amp_details={"memory": {
                "free": 32864004,
                "buffers": 32312392 // 2,
                "cached": 32312392 // 2,
            }})
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, global_opts=g_opts), rendered_obj)

    def test_render_https_listener_isolation_has_section_scoped_policies(self):
        samples = sample_configs_combined
        hostnames = ['*', '*.example.test', 'a.example.test',
                     '*.deep.example.test']
        policy = samples.sample_l7policy_tuple(
            'example-only')._replace(https_listener_hostname='*.example.test')
        listener = samples.sample_listener_tuple(
            proto='TERMINATED_HTTPS', tls=True, include_pools=False)._replace(
                default_pool=None, pools=[policy.redirect_pool],
                https_virtual_hosts=hostnames, l7policies=[
                    policy, policy._replace(id='unowned',
                                            https_listener_hostname=None)])
        amphora = samples.sample_amphora_tuple()
        config = self.jinja_cfg.render_loadbalancer_obj(
            amphora, [listener], haproxy_version='3.0.19')
        self.assertIn('req.fhdr(host),host_only', config)
        self.assertLess(config.index('-m str -i a.example.test'),
                        config.index('-m end -i .deep.example.test'))
        self.assertLess(config.index('-m end -i .deep.example.test'),
                        config.index('-m end -i .example.test'))
        self.assertIn('http-request return status 421', config)
        self.assertIn('http-request return status 404', config)
        self.assertIn(
            'if { var(txn.octavia_https_authority_section) -m str 3 } '
            'sample_l7rule_id_1', config)
        self.assertEqual(1, config.count('    use_backend '))
        self.assertRaises(
            driver_except.AmpVersionUnsupported,
            self.jinja_cfg.render_loadbalancer_obj,
            amphora, [listener], haproxy_version='2.8.0')

    def test_render_tcp_clienthello_sni(self):
        samples = sample_configs_combined
        default_pool = samples.sample_pool_tuple(
            proto='TCP', persistence=False)
        target = samples.sample_pool_tuple(
            proto='TCP', sample_pool=2, persistence=False)
        rule = samples.sample_l7rule_tuple(
            'route-sni', type='TLS_SNI', compare_type='EQUAL_TO',
            value='A.example.test')
        policy = samples.sample_l7policy_tuple('policy')._replace(
            redirect_pool=target, l7rules=[rule])
        listener = samples.sample_listener_tuple(
            proto='TCP', persistence=False)._replace(
                default_pool=default_pool, pools=[default_pool, target])

        def render(current_policy):
            return self.jinja_cfg.render_loadbalancer_obj(
                samples.sample_amphora_tuple(),
                [listener._replace(l7policies=[current_policy])], {})

        config = render(policy)
        self.assertIn('tcp-request inspect-delay 1000', config)
        self.assertIn('tcp-request content accept if { req.ssl_hello_type 1 }',
                      config)
        self.assertIn('acl route-sni req.ssl_sni -i -m str A.example.test',
                      config)
        self.assertIn(
            'use_backend sample_pool_id_2:sample_listener_id_1 if route-sni',
            config)
        self.assertIn(
            'default_backend sample_pool_id_1:sample_listener_id_1', config)
        for inactive in (
                policy._replace(enabled=False),
                policy._replace(provisioning_status=constants.PENDING_DELETE),
                policy._replace(l7rules=[]),
                policy._replace(l7rules=[rule._replace(enabled=False)]),
                policy._replace(l7rules=[rule._replace(type='HOST_NAME')]),
                policy._replace(redirect_pool=None)):
            with self.subTest(policy=inactive):
                config = render(inactive)
                self.assertNotIn('use_backend', config)
                self.assertNotIn('req.ssl_', config)
                self.assertIn(
                    'default_backend sample_pool_id_1:sample_listener_id_1',
                    config)

    def test_render_tcp_sni_policy_specificity_and_position(self):
        samples = sample_configs_combined
        pool = samples.sample_pool_tuple(proto='TCP', persistence=False)
        broad = samples.sample_l7rule_tuple(
            'broad', type='TLS_SNI', compare_type='ENDS_WITH',
            value='*.example.test')
        narrow = broad._replace(id='narrow', value='*.a.example.test')
        first = narrow._replace(id='first')
        conjoined = broad._replace(id='conjoined')
        exact = broad._replace(id='exact', compare_type='EQUAL_TO',
                               value='one.a.example.test')
        policies = [
            samples.sample_l7policy_tuple(rules[-1].id)._replace(
                redirect_pool=pool, l7rules=rules)
            for rules in ([broad], [first], [conjoined, narrow], [exact])]
        listener = samples.sample_listener_tuple(
            proto='TCP', persistence=False)._replace(
                pools=[pool], l7policies=policies)

        config = self.jinja_cfg.render_loadbalancer_obj(
            samples.sample_amphora_tuple(), [listener], {})

        self.assertIn('acl broad req.ssl_sni -i -m end .example.test', config)
        self.assertEqual(
            ['exact', 'first', 'conjoined narrow', 'broad'],
            [line.split(' if ')[1] for line in config.splitlines()
             if line.strip().startswith('use_backend ')])

    def test_render_template_l7policies(self):
        fe = ("frontend sample_listener_id_1\n"
              "    maxconn {maxconn}\n"
              "    bind 10.0.0.2:80\n"
              "    mode http\n"
              "        acl sample_l7rule_id_1 path -m beg -- /api\n"
              "    use_backend sample_pool_id_2:sample_listener_id_1"
              " if sample_l7rule_id_1\n"
              "        acl sample_l7rule_id_2 req.hdr(Some-header) -m sub -- "
              "This\\ string\\\\\\ with\\ stuff\n"
              "        acl sample_l7rule_id_3 req.cook(some-cookie) -m reg -- "
              "this.*|that\n"
              "    redirect code 302 location http://www.example.com if "
              "!sample_l7rule_id_2 sample_l7rule_id_3\n"
              "        acl sample_l7rule_id_4 path_end  -- jpg\n"
              "        acl sample_l7rule_id_5 req.hdr(host) -i -m end -- "
              ".example.com\n"
              "    http-request deny if sample_l7rule_id_4 "
              "sample_l7rule_id_5\n"
              "        acl sample_l7rule_id_2 req.hdr(Some-header) -m sub -- "
              "This\\ string\\\\\\ with\\ stuff\n"
              "        acl sample_l7rule_id_3 req.cook(some-cookie) -m reg -- "
              "this.*|that\n"
              "    redirect code 302 prefix https://example.com if "
              "!sample_l7rule_id_2 sample_l7rule_id_3\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_2\n"
              "\n"
              "backend sample_pool_id_2:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /healthmon.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_3 10.0.0.97:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_3\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(l7=True)])
        self.assertEqual(sample_configs_combined.sample_base_expected_config(
            frontend=fe, backend=be), rendered_obj)

    def test_haproxy_version_check_ignores_unrendered_fixed_responses(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        policy = listener.l7policies[0]._replace(
            action=constants.L7POLICY_ACTION_FIXED_RESPONSE,
            redirect_pool=None, fixed_response={'status_code': 500})
        listener = listener._replace(l7policies=[policy])
        old_version = ['2', '1', '1']
        with self.assertRaises(driver_except.AmpVersionUnsupported):
            self.jinja_cfg.build_config(
                amp, [listener], None, haproxy_versions=old_version,
                amp_details=None)
        rendered = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)
        self.assertIn('http-request return status 500', rendered)

        for unrendered_policy in (
                policy._replace(provisioning_status=constants.PENDING_DELETE),
                policy._replace(enabled=False),
                policy._replace(l7rules=[policy.l7rules[0]._replace(
                    provisioning_status=constants.PENDING_DELETE)])):
            with self.subTest(policy=unrendered_policy):
                rendered = self.jinja_cfg.build_config(
                    amp, [listener._replace(l7policies=[unrendered_policy])],
                    None, haproxy_versions=old_version, amp_details=None)
                self.assertNotIn('http-request return status 500', rendered)

    def test_weighted_policy_routes_nonzero_targets_in_policy_order(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        listener_id = listener.id
        first_pool, second_pool = listener.pools
        policy = listener.l7policies[0]
        rule = policy.l7rules[0]
        earlier = policy._replace(
            id='earlier', l7rules=[rule._replace(id='earlier_rule',
                                                 value='/api/specific')])
        weighted = policy._replace(
            id='weighted', action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None,
            targets=[
                {'weight': 1, 'pool_id': first_pool.id},
                {'weight': 0, 'fixed_response': {'status_code': 404}},
                {'weight': 2, 'pool_id': second_pool.id},
                {'weight': 7, 'fixed_response': {'status_code': 500}},
            ])
        later = policy._replace(
            id='later', action=constants.L7POLICY_ACTION_FIXED_RESPONSE,
            l7rules=[rule._replace(id='later_rule')], redirect_pool=None,
            fixed_response={'status_code': 404})
        listener = listener._replace(l7policies=[earlier, weighted, later])

        rendered = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)

        self.assertEqual(1, rendered.count('rand(10)'))
        self.assertIn(
            'http-request set-var(txn.octavia_l7_policy) str(earlier) '
            'if !{ var(txn.octavia_l7_policy) -m found } earlier_rule',
            rendered)
        self.assertIn(
            'http-request set-var(txn.octavia_l7_policy) str(weighted) '
            'if !{ var(txn.octavia_l7_policy) -m found } sample_l7rule_id_1',
            rendered)
        self.assertIn(
            'rand(10) if { var(txn.octavia_l7_policy) -m str weighted }',
            rendered)
        backend_prefix = constants.HAPROXY_FIXED_RESPONSE_BACKEND_PREFIX
        routes = [line.strip() for line in rendered.splitlines()
                  if line.lstrip().startswith('use_backend ')]
        self.assertEqual([
            f'use_backend {second_pool.id}:{listener_id} if earlier_rule',
            f'use_backend {first_pool.id}:{listener_id} '
            'if { var(txn.octavia_l7_policy) -m str weighted } '
            '{ var(txn.octavia_weighted_draw) -m int 0:0 }',
            f'use_backend {second_pool.id}:{listener_id} '
            'if { var(txn.octavia_l7_policy) -m str weighted } '
            '{ var(txn.octavia_weighted_draw) -m int 1:2 }',
            f'use_backend {backend_prefix}{listener_id}-weighted-500 '
            'if { var(txn.octavia_l7_policy) -m str weighted } '
            '{ var(txn.octavia_weighted_draw) -m int 3:9 }',
            f'use_backend {backend_prefix}{listener_id}-later if later_rule',
        ], routes)

    def test_http_method_and_path_rules_share_policy_condition(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        rule = sample_configs_combined.sample_l7rule_tuple
        for protocol in ('HTTP', 'TERMINATED_HTTPS'):
            with self.subTest(protocol=protocol):
                listener = sample_configs_combined.sample_listener_tuple(
                    l7=True, proto=protocol)
                policy = listener.l7policies[0]._replace(l7rules=[
                    rule('catalog', type='PATH', compare_type='EQUAL_TO',
                         value='/catalog'),
                    rule('read', type='HTTP_METHOD', compare_type='EQUAL_TO',
                         value='GET'),
                ])
                listener = listener._replace(l7policies=[policy])
                rendered = self.jinja_cfg.build_config(
                    amp, [listener], None, haproxy_versions=['3', '0', '19'],
                    amp_details=None)
                self.assertIn('acl read method GET\n', rendered)
                self.assertIn('acl catalog path -m str -- /catalog\n',
                              rendered)
                self.assertIn('if catalog read\n', rendered)

    def test_full_header_rule_and_legacy_header_acl(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        policy = listener.l7policies[0]
        rule = sample_configs_combined.sample_l7rule_tuple
        policy = policy._replace(l7rules=[
            rule('full', type='HTTP_HEADER_EXACT', compare_type='EQUAL_TO',
                 key="X-Color#'Tag", value='one, "two"'),
            rule('legacy', type='HEADER', compare_type='EQUAL_TO',
                 key='X-Color', value='one'),
        ])
        listener = listener._replace(l7policies=[policy])
        rendered = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)
        self.assertIn(
            r'acl full req.fhdr(\"X-Color\x23\x27Tag\") -m bin '
            '6f6e652c202274776f22', rendered)
        self.assertIn('acl legacy req.hdr(X-Color) -m str -- one', rendered)

    def test_query_param_rule_and_inversion_share_policy_condition(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        rule = sample_configs_combined.sample_l7rule_tuple
        for protocol in ('HTTP', 'TERMINATED_HTTPS'):
            with self.subTest(protocol=protocol):
                listener = sample_configs_combined.sample_listener_tuple(
                    l7=True, proto=protocol)
                policy = listener.l7policies[0]._replace(l7rules=[
                    rule('catalog', type='PATH', compare_type='EQUAL_TO',
                         value='/catalog'),
                    rule('query', type='HTTP_QUERY_PARAM_EXACT',
                         compare_type='EQUAL_TO', key='X&', invert=True,
                         value='é\r\n'),
                ])
                listener = listener._replace(l7policies=[policy])
                rendered = self.jinja_cfg.build_config(
                    amp, [listener], None, haproxy_versions=['3', '0', '19'],
                    amp_details=None)
                self.assertIn(
                    r"""acl query 'query,regsub("(^|&)(?:\x58|(?i:%58))"""
                    r"""(?i:%26)(?==|&|$)","\1%58%26"),param(%58%26),"""
                    "url_dec(1)' -m bin c3a90d0a\n", rendered)
                self.assertIn('if catalog !query\n', rendered)

    def test_request_headers_use_selected_policy_in_shared_backend(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        ordinary = listener.l7policies[0]
        modified = ordinary._replace(
            id='modified',
            l7rules=[sample_configs_combined.sample_l7rule_tuple(
                'modified-rule', value='/specific')],
            request_header_operations=[
                {'operation': 'SET', 'name': 'x-color', 'value': '%[path]'},
                {'operation': 'ADD', 'name': 'x-extra', 'value': ''},
                {'operation': 'REMOVE', 'name': 'x-old'},
            ])
        listener = listener._replace(l7policies=[modified, ordinary])
        rendered = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)
        frontend, backends = rendered.split('\nbackend ', 1)
        self.assertIn(
            'str(modified) if !{ var(txn.octavia_l7_policy) -m found } '
            'modified-rule', frontend)
        self.assertNotIn('set-header "x-color"', frontend)
        guard = 'if { var(txn.octavia_l7_policy) -m str modified }'
        for action in ('set-header "x-color" "%%[path]"',
                       'add-header "x-extra" "%[str()]"',
                       'del-header "x-old"'):
            self.assertIn(f'http-request {action} {guard}', backends)
        self.assertEqual(3, backends.count(guard))

    def test_response_headers_follow_policy_to_pool_or_fixed_response(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        ordinary = listener.l7policies[0]
        pool = ordinary.redirect_pool
        modified = ordinary._replace(
            id='modified', action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None,
            targets=[{'weight': 3, 'pool_id': pool.id},
                     {'weight': 1, 'fixed_response': {'status_code': 500}}],
            response_header_operations=[
                {'operation': 'ADD', 'name': 'X-Tag', 'value': '%[path]'}])
        listener = listener._replace(l7policies=[modified, ordinary])
        config = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)
        frontend, *backends = config.split('\nbackend ')
        line = ('http-after-response add-header "x-tag" "%%[path]" '
                'if { var(txn.octavia_l7_policy) -m str modified }')
        self.assertNotIn(line, frontend)
        self.assertEqual(
            {f'{pool.id}:{listener.id}',
             f'{constants.HAPROXY_FIXED_RESPONSE_BACKEND_PREFIX}'
             f'{listener.id}-weighted-500'},
            {backend.splitlines()[0] for backend in backends
             if line in (entry.strip() for entry in backend.splitlines())})

    def test_weighted_policy_keeps_unavailable_targets_in_its_range(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        first_pool, second_pool = listener.pools
        weighted = listener.l7policies[0]._replace(
            action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None,
            targets=[
                {'weight': 2, 'pool_id': first_pool.id},
                {'weight': 3, 'pool_id': second_pool.id},
            ])
        listener = listener._replace(l7policies=[weighted], pools=[
            first_pool._replace(enabled=False),
            second_pool._replace(provisioning_status=constants.PENDING_DELETE),
        ])

        rendered = self.jinja_cfg.build_config(
            amp, [listener], None, haproxy_versions=['3', '0', '19'],
            amp_details=None)

        backend = (f'{constants.HAPROXY_FIXED_RESPONSE_BACKEND_PREFIX}'
                   f'{listener.id}-weighted-503')
        self.assertIn('rand(5)', rendered)
        self.assertIn(f'backend {backend}\n'
                      '    mode http\n'
                      '    http-request return status 503', rendered)
        routes = [line.strip() for line in rendered.splitlines()
                  if line.lstrip().startswith('use_backend ')]
        self.assertEqual([
            f'use_backend {backend} '
            'if { var(txn.octavia_l7_policy) -m str sample_l7policy_id_1 } '
            '{ var(txn.octavia_weighted_draw) -m int 0:1 }',
            f'use_backend {backend} '
            'if { var(txn.octavia_l7_policy) -m str sample_l7policy_id_1 } '
            '{ var(txn.octavia_weighted_draw) -m int 2:4 }',
        ], routes)

    def test_weighted_policy_requires_supported_haproxy(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        weighted = listener.l7policies[0]._replace(
            action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None,
            targets=[{'weight': 1, 'fixed_response': {'status_code': 404}}])
        old_version = ['2', '1', '1']
        with self.assertRaises(driver_except.AmpVersionUnsupported):
            self.jinja_cfg.build_config(
                amp, [listener._replace(l7policies=[weighted])], None,
                haproxy_versions=old_version, amp_details=None)

        rendered = self.jinja_cfg.build_config(
            amp, [listener._replace(l7policies=[
                weighted._replace(enabled=False)])], None,
            haproxy_versions=old_version, amp_details=None)
        self.assertNotIn('rand(', rendered)

    def test_weighted_policy_requires_representable_total_weight(self):
        amp = sample_configs_combined.sample_amphora_tuple()
        listener = sample_configs_combined.sample_listener_tuple(l7=True)
        policy = listener.l7policies[0]._replace(
            action=constants.L7POLICY_ACTION_WEIGHTED_TARGETS,
            redirect_pool=None)
        for weight in (0, 2**32 + 1):
            weighted = policy._replace(targets=[
                {'weight': weight, 'pool_id': listener.pools[0].id}])
            with self.subTest(weight=weight), self.assertRaises(
                    exceptions.InvalidL7PolicyArgs):
                self.jinja_cfg.render_loadbalancer_obj(
                    amp, [listener._replace(l7policies=[weighted])])

    def test_render_template_http_xff(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    option forwardfor\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                insert_headers={'X-Forwarded-For': 'true'})])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_http_xff_xfport(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              "    option forwardfor\n"
              "    http-request set-header X-Forwarded-Port %[dst_port]\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                insert_headers={'X-Forwarded-For': 'true',
                                'X-Forwarded-Port': 'true'})])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_proxy_protocol(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1 send-proxy\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2 send-proxy\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(be_proto='PROXY')])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_cert(self):
        feature_compatibility = {constants.POOL_ALPN: True}
        cert_file_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                      'sample_listener_id_1', 'fake path')
        opts = (f"ssl crt {cert_file_path} verify none sni ssl_fc_sni "
                f"ciphers {self.DEFAULT_TLS_CIPHERS} "
                f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
                f"no-sslv3 no-tlsv10 no-tlsv11")
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_1 {opts} alpn {alpn}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_2 {opts} alpn {alpn}\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, tls_enabled=True,
                backend_tls_ciphers=constants.CIPHERS_OWASP_SUITE_B)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': cert_file_path,
                     'ca_cert': None, 'crl': None}},
            feature_compatibility=feature_compatibility)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_cert_no_alpn(self):
        feature_compatibility = {constants.POOL_ALPN: False}
        cert_file_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                      'sample_listener_id_1', 'fake path')
        opts = (f"ssl crt {cert_file_path} verify none sni ssl_fc_sni "
                f"ciphers {self.DEFAULT_TLS_CIPHERS} "
                f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
                f"no-sslv3 no-tlsv10 no-tlsv11")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_1 "
              f"{opts}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_2 "
              f"{opts}\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, tls_enabled=True,
                backend_tls_ciphers=constants.CIPHERS_OWASP_SUITE_B)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': cert_file_path,
                     'ca_cert': None, 'crl': None}},
            feature_compatibility=feature_compatibility)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_cert_no_versions(self):
        feature_compatibility = {constants.POOL_ALPN: True}
        cert_file_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                      'sample_listener_id_1', 'fake path')
        opts = (f"ssl crt {cert_file_path} verify none sni ssl_fc_sni "
                f"ciphers {self.DEFAULT_TLS_CIPHERS} "
                f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES}")
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_1 {opts} alpn {alpn}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_2 {opts} alpn {alpn}\n\n"
              )
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, tls_enabled=True,
                backend_tls_ciphers=constants.CIPHERS_OWASP_SUITE_B,
                backend_tls_versions=None)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': cert_file_path,
                     'ca_cert': None, 'crl': None}},
            feature_compatibility=feature_compatibility)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_cert_no_ciphers(self):
        feature_compatibility = {constants.POOL_ALPN: True}
        cert_file_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                      'sample_listener_id_1', 'fake path')
        opts = (f"ssl crt {cert_file_path} verify none sni ssl_fc_sni "
                f"no-sslv3 no-tlsv10 no-tlsv11")
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_1 {opts} alpn {alpn}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_2 {opts} alpn {alpn}\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, tls_enabled=True)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': cert_file_path,
                     'ca_cert': None, 'crl': None}},
            feature_compatibility=feature_compatibility)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_cert_no_ciphers_or_versions_or_alpn(self):
        cert_file_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                      'sample_listener_id_1', 'fake path')
        opts = f"ssl crt {cert_file_path} verify none sni ssl_fc_sni"
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_1 "
              f"{opts}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_2 "
              f"{opts}\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, tls_enabled=True, backend_tls_versions=None,
                backend_alpn_protocols=None)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': cert_file_path,
                     'ca_cert': None, 'crl': None}})
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_pool_no_alpn(self):
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              "check inter 30s fall 3 rise 2 cookie sample_member_id_2"
              "\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                backend_alpn_protocols=None)])
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_render_template_with_full_pool_cert(self):
        feature_compatibility = {constants.POOL_ALPN: True}
        pool_client_cert = '/foo/cert.pem'
        pool_ca_cert = '/foo/ca.pem'
        pool_crl = '/foo/crl.pem'
        opts = (f"ssl crt {pool_client_cert} ca-file {pool_ca_cert} "
                f"crl-file {pool_crl} verify required sni ssl_fc_sni "
                f"no-sslv3 no-tlsv10 no-tlsv11")
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_1 {opts} alpn {alpn}\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 "
              f"check check-alpn {alpn} inter 30s fall 3 rise 2 cookie "
              f"sample_member_id_2 {opts} alpn {alpn}\n\n")
        rendered_obj = self.jinja_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple(
                pool_cert=True, pool_ca_cert=True, pool_crl=True,
                tls_enabled=True)],
            tls_certs={
                'sample_pool_id_1':
                    {'client_cert': pool_client_cert,
                     'ca_cert': pool_ca_cert,
                     'crl': pool_crl}},
            feature_compatibility=feature_compatibility)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_transform_session_persistence(self):
        in_persistence = (
            sample_configs_combined.sample_session_persistence_tuple())
        ret = self.jinja_cfg._transform_session_persistence(
            in_persistence, {})
        self.assertEqual(sample_configs_combined.RET_PERSISTENCE, ret)

    def test_transform_health_monitor(self):
        in_persistence = sample_configs_combined.sample_health_monitor_tuple()
        ret = self.jinja_cfg._transform_health_monitor(in_persistence, {})
        self.assertEqual(sample_configs_combined.RET_MONITOR_1, ret)

    def test_transform_member(self):
        in_member = sample_configs_combined.sample_member_tuple(
            'sample_member_id_1', '10.0.0.99')
        ret = self.jinja_cfg._transform_member(in_member, {})
        self.assertEqual(sample_configs_combined.RET_MEMBER_1, ret)

    def test_transform_pool(self):
        in_pool = sample_configs_combined.sample_pool_tuple()
        ret = self.jinja_cfg._transform_pool(in_pool, {}, False)
        self.assertEqual(sample_configs_combined.RET_POOL_1, ret)

    def test_transform_pool_2(self):
        in_pool = sample_configs_combined.sample_pool_tuple(sample_pool=2)
        ret = self.jinja_cfg._transform_pool(in_pool, {}, False)
        self.assertEqual(sample_configs_combined.RET_POOL_2, ret)

    def test_transform_pool_http_reuse(self):
        in_pool = sample_configs_combined.sample_pool_tuple(sample_pool=2)
        ret = self.jinja_cfg._transform_pool(
            in_pool, {constants.HTTP_REUSE: True}, False)
        expected_config = copy.copy(sample_configs_combined.RET_POOL_2)
        expected_config[constants.HTTP_REUSE] = True
        self.assertEqual(expected_config, ret)

    def test_transform_pool_cert(self):
        in_pool = sample_configs_combined.sample_pool_tuple(pool_cert=True)
        cert_path = os.path.join(self.jinja_cfg.base_crt_dir,
                                 'test_listener_id', 'pool_cert.pem')
        ret = self.jinja_cfg._transform_pool(
            in_pool, {}, False, pool_tls_certs={'client_cert': cert_path})
        expected_config = copy.copy(sample_configs_combined.RET_POOL_1)
        expected_config['client_cert'] = cert_path
        self.assertEqual(expected_config, ret)

    def test_transform_listener(self):
        in_listener = sample_configs_combined.sample_listener_tuple()
        ret = self.jinja_cfg._transform_listener(in_listener, None, {},
                                                 in_listener.load_balancer)
        self.assertEqual(sample_configs_combined.RET_LISTENER, ret)

    def test_transform_listener_with_l7(self):
        in_listener = sample_configs_combined.sample_listener_tuple(l7=True)
        ret = self.jinja_cfg._transform_listener(in_listener, None, {},
                                                 in_listener.load_balancer)
        self.assertEqual(sample_configs_combined.RET_LISTENER_L7, ret)

    def test_transform_listener_PROMETHEUS(self):
        in_listener = sample_configs_combined.sample_listener_tuple()
        ret = self.jinja_cfg._transform_listener(
            in_listener, None, {lib_consts.PROTOCOL_PROMETHEUS: True},
            in_listener.load_balancer)
        expected_config = copy.copy(sample_configs_combined.RET_LISTENER)
        expected_config[lib_consts.PROTOCOL_PROMETHEUS] = True
        self.assertEqual(expected_config, ret)

    def test_transform_loadbalancer(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()
        in_listener = sample_configs_combined.sample_listener_tuple()
        ret = self.jinja_cfg._transform_loadbalancer(
            in_amphora, in_listener.load_balancer, [in_listener], None, {})
        self.assertEqual(sample_configs_combined.RET_LB, ret)

    def test_transform_two_loadbalancers(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()
        in_listener1 = sample_configs_combined.sample_listener_tuple()
        in_listener2 = sample_configs_combined.sample_listener_tuple()

        ret = self.jinja_cfg._transform_loadbalancer(
            in_amphora, in_listener1.load_balancer,
            [in_listener1, in_listener2], None, {})
        self.assertEqual(ret['global_connection_limit'],
                         constants.HAPROXY_DEFAULT_MAXCONN +
                         constants.HAPROXY_DEFAULT_MAXCONN)

    def test_transform_many_loadbalancers(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()

        in_listeners = []

        # Create many listeners, until the sum of connection_limits
        # is greater than MAX_MAXCONN
        connection_limit_sum = 0
        while connection_limit_sum <= constants.HAPROXY_MAX_MAXCONN:
            in_listener = (
                sample_configs_combined.sample_listener_tuple())
            connection_limit_sum += constants.HAPROXY_DEFAULT_MAXCONN

            in_listeners.append(in_listener)

        ret = self.jinja_cfg._transform_loadbalancer(
            in_amphora, in_listeners[0].load_balancer,
            in_listeners, None, {})
        self.assertEqual(ret['global_connection_limit'],
                         constants.HAPROXY_MAX_MAXCONN)
        self.assertLess(ret['global_connection_limit'],
                        connection_limit_sum)

    def test_transform_with_disabled_listeners(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()

        in_listeners = []

        connection_limit_sum = 0

        in_listener = (
            sample_configs_combined.sample_listener_tuple())
        connection_limit_sum += constants.HAPROXY_DEFAULT_MAXCONN
        in_listeners.append(in_listener)

        disabled_listener = (
            sample_configs_combined.sample_listener_tuple(enabled=False))
        in_listeners.append(disabled_listener)

        ret = self.jinja_cfg._transform_loadbalancer(
            in_amphora, in_listeners[0].load_balancer,
            in_listeners, None, {})
        self.assertEqual(ret['global_connection_limit'],
                         connection_limit_sum)

    def test_transform_amphora(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()
        ret = self.jinja_cfg._transform_amphora(in_amphora, {})
        self.assertEqual(sample_configs_combined.RET_AMPHORA, ret)

    def test_transform_loadbalancer_with_l7(self):
        in_amphora = sample_configs_combined.sample_amphora_tuple()
        in_listener = sample_configs_combined.sample_listener_tuple(l7=True)
        ret = self.jinja_cfg._transform_loadbalancer(
            in_amphora, in_listener.load_balancer, [in_listener], None, {})
        self.assertEqual(sample_configs_combined.RET_LB_L7, ret)

    def test_transform_l7policy(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_1')
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertEqual(sample_configs_combined.RET_L7POLICY_1, ret)

    def test_transform_l7policy_2_8(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_2', sample_policy=2)
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertEqual(sample_configs_combined.RET_L7POLICY_2, ret)

        # test invalid action without redirect_http_code
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_8', sample_policy=2, redirect_http_code=None)
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertEqual(sample_configs_combined.RET_L7POLICY_8, ret)

    def test_transform_l7policy_disabled_rule(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_6', sample_policy=6)
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertEqual(sample_configs_combined.RET_L7POLICY_6, ret)

    def test_transform_l7policy_redirect_url_injection(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_2', sample_policy=2)
        # Replace redirect_url with a tainted value
        in_l7policy = in_l7policy._replace(
            redirect_url='https://example.com/\ncheck')
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertIsNone(ret['redirect_url'])

    def test_transform_l7policy_redirect_prefix_injection(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_2', sample_policy=2)
        in_l7policy = in_l7policy._replace(
            redirect_prefix='https://example.com/\ncheck',
            redirect_url=None)
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertIsNone(ret['redirect_prefix'])

    def test_transform_l7policy_redirect_url_valid(self):
        in_l7policy = sample_configs_combined.sample_l7policy_tuple(
            'sample_l7policy_id_2', sample_policy=2)
        ret = self.jinja_cfg._transform_l7policy(in_l7policy, {}, False)
        self.assertEqual('http://www.example.com', ret['redirect_url'])

    def test_escape_haproxy_config_string(self):
        self.assertEqual(self.jinja_cfg._escape_haproxy_config_string(
            'string_with_none'), 'string_with_none')
        self.assertEqual(self.jinja_cfg._escape_haproxy_config_string(
            'string with spaces'), 'string\\ with\\ spaces')
        self.assertEqual(self.jinja_cfg._escape_haproxy_config_string(
            'string\\with\\backslashes'), 'string\\\\with\\\\backslashes')
        self.assertEqual(self.jinja_cfg._escape_haproxy_config_string(
            'string\\ with\\ all'), 'string\\\\\\ with\\\\\\ all')

    def test_render_template_no_log(self):
        j_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs',
            connection_logging=False)
        defaults = ("defaults\n"
                    "    no log\n"
                    "    retries 3\n"
                    "    option redispatch\n"
                    "    option splice-request\n"
                    "    option splice-response\n"
                    "    option http-keep-alive\n\n\n")
        rendered_obj = j_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple()]
        )
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                defaults=defaults, logging="\n"),
            rendered_obj)

    def test_render_template_amp_details(self):
        j_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs',
            connection_logging=False)
        rendered_obj = j_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple()],
            amp_details={"cpu_count": 7,
                         "active_tuned_profiles": 'virtual-guest '
                                                  'optimize-serial-console '
                                                  'amphora'}
        )
        defaults = ("defaults\n"
                    "    no log\n"
                    "    retries 3\n"
                    "    option redispatch\n"
                    "    option splice-request\n"
                    "    option splice-response\n"
                    "    option http-keep-alive\n\n\n")
        global_opts = ("    maxconn 50000\n"
                       "    nbthread 6\n"
                       "    cpu-map auto:1/1-6 1-6\n"
                       "\n")
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                defaults=defaults, logging="\n", global_opts=global_opts),
            rendered_obj)

    def test_render_template_amp_details_cpu_count_none(self):
        j_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs',
            connection_logging=False)
        rendered_obj = j_cfg.render_loadbalancer_obj(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_configs_combined.sample_listener_tuple()],
            amp_details={"cpu_count": None},
        )
        defaults = ("defaults\n"
                    "    no log\n"
                    "    retries 3\n"
                    "    option redispatch\n"
                    "    option splice-request\n"
                    "    option splice-response\n"
                    "    option http-keep-alive\n\n\n")
        global_opts = "    maxconn 50000\n\n"
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                defaults=defaults, logging="\n", global_opts=global_opts),
            rendered_obj)

    def test_haproxy_cfg_1_8_vs_1_5(self):
        j_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs')

        sample_amphora = sample_configs_combined.sample_amphora_tuple()
        sample_proxy_listener = sample_configs_combined.sample_listener_tuple(
            be_proto='PROXY')
        # With http-reuse and server-state-file
        go = (
            "    server-state-file /var/lib/octavia/sample_loadbalancer_id_1/"
            "servers-state\n"
            "    maxconn {maxconn}\n\n").format(
            maxconn=constants.HAPROXY_DEFAULT_MAXCONN)
        be = (f"backend {sample_proxy_listener.default_pool.id}:"
              f"{sample_proxy_listener.id}\n"
              "    mode http\n"
              "    http-reuse safe\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    load-server-state-from-file global\n"
              "    timeout check 31s\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1 send-proxy\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2 send-proxy\n\n")
        rendered_obj = j_cfg.build_config(
            sample_amphora,
            [sample_proxy_listener],
            tls_certs=None,
            haproxy_versions=("1", "8", "1"),
            amp_details=None)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                global_opts=go, backend=be),
            rendered_obj)

        # Without http-reuse and server-state-file
        be = (f"backend {sample_proxy_listener.default_pool.id}:"
              f"{sample_proxy_listener.id}\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_1 send-proxy\n"
              "    server sample_member_id_2 10.0.0.98:82 "
              "weight 13 check inter 30s fall 3 rise 2 "
              "cookie sample_member_id_2 send-proxy\n\n")
        rendered_obj = j_cfg.build_config(
            sample_amphora,
            [sample_proxy_listener],
            tls_certs=None,
            haproxy_versions=("1", "5", "18"),
            amp_details=None)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(backend=be),
            rendered_obj)

    def test_ssl_types_l7rules(self):
        j_cfg = jinja_cfg.JinjaTemplater(
            base_amp_path='/var/lib/octavia',
            base_crt_dir='/var/lib/octavia/certs')
        alpn = ",".join(constants.AMPHORA_SUPPORTED_ALPN_PROTOCOLS)
        fe = ("frontend sample_listener_id_1\n"
              f"    maxconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    redirect scheme https if !{ ssl_fc }\n"
              "    http-response set-header Strict-Transport-Security "
              "\"max-age=10000000; includeSubDomains; preload;\"\n"
              "    bind 10.0.0.2:443 "
              f"ciphers {self.DEFAULT_TLS_CIPHERS} "
              f"ciphersuites {self.DEFAULT_TLS_CIPHERSUITES} "
              f"no-sslv3 no-tlsv10 no-tlsv11 alpn {alpn}\n"
              "    mode http\n"
              "        acl sample_l7rule_id_1 path -m beg -- /api\n"
              "    use_backend sample_pool_id_2:sample_listener_id_1"
              " if sample_l7rule_id_1\n"
              "        acl sample_l7rule_id_2 req.hdr(Some-header) -m sub -- "
              "This\\ string\\\\\\ with\\ stuff\n"
              "        acl sample_l7rule_id_3 req.cook(some-cookie) -m reg -- "
              "this.*|that\n"
              "    redirect code 302 location http://www.example.com "
              "if !sample_l7rule_id_2 sample_l7rule_id_3\n"
              "        acl sample_l7rule_id_4 path_end  -- jpg\n"
              "        acl sample_l7rule_id_5 req.hdr(host) -i -m end -- "
              ".example.com\n"
              "    http-request deny "
              "if sample_l7rule_id_4 sample_l7rule_id_5\n"
              "        acl sample_l7rule_id_2 req.hdr(Some-header) -m sub -- "
              "This\\ string\\\\\\ with\\ stuff\n"
              "        acl sample_l7rule_id_3 req.cook(some-cookie) -m reg -- "
              "this.*|that\n"
              "    redirect code 302 prefix https://example.com "
              "if !sample_l7rule_id_2 sample_l7rule_id_3\n"
              "        acl sample_l7rule_id_7 ssl_c_used\n"
              "        acl sample_l7rule_id_8 ssl_c_verify eq 1\n"
              "        acl sample_l7rule_id_9 ssl_c_s_dn(STREET) -m reg -- "
              "^STREET.*NO\\\\.$\n"
              "        acl sample_l7rule_id_10 ssl_c_s_dn(OU-3) -m beg -- "
              "Orgnization\\ Bala\n"
              "        acl sample_l7rule_id_11 path -m beg -- /api\n"
              "    redirect code 302 location "
              "http://www.ssl-type-l7rule-test.com "
              "if sample_l7rule_id_7 !sample_l7rule_id_8 !sample_l7rule_id_9 "
              "!sample_l7rule_id_10 sample_l7rule_id_11\n"
              "    default_backend sample_pool_id_1:sample_listener_id_1\n"
              "    timeout client 50000\n")
        be = ("backend sample_pool_id_1:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /index.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_1 10.0.0.99:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_1\n"
              "    server sample_member_id_2 10.0.0.98:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_2\n\n"
              "backend sample_pool_id_2:sample_listener_id_1\n"
              "    mode http\n"
              "    balance roundrobin\n"
              "    cookie SRV insert indirect nocache\n"
              "    timeout check 31s\n"
              "    option httpchk GET /healthmon.html HTTP/1.0\n"
              "    http-check expect rstatus 418\n"
              f"    fullconn {constants.HAPROXY_DEFAULT_MAXCONN}\n"
              "    option allbackups\n"
              "    timeout connect 5000\n"
              "    timeout server 50000\n"
              "    server sample_member_id_3 10.0.0.97:82 weight 13 check "
              "inter 30s fall 3 rise 2 cookie sample_member_id_3\n\n")
        sample_listener = sample_configs_combined.sample_listener_tuple(
            proto=constants.PROTOCOL_TERMINATED_HTTPS, l7=True,
            ssl_type_l7=True)
        rendered_obj = j_cfg.build_config(
            sample_configs_combined.sample_amphora_tuple(),
            [sample_listener],
            tls_certs=None,
            haproxy_versions=("1", "5", "18"),
            amp_details=None)
        self.assertEqual(
            sample_configs_combined.sample_base_expected_config(
                frontend=fe, backend=be),
            rendered_obj)

    @mock.patch("octavia.common.jinja.haproxy.combined_listeners.jinja_cfg."
                "JinjaTemplater.render_loadbalancer_obj")
    def test_build_config(self, mock_render_loadbalancer_obj):
        mock_amp = mock.Mock()
        mock_listeners = mock.Mock()
        mock_tls_certs = mock.Mock()
        mock_socket_path = mock.Mock()

        j_cfg = jinja_cfg.JinjaTemplater()
        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("0", "7", "0"),
                           socket_path=mock_socket_path, amp_details=None)

        expected_fc = {}
        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="0.7.0")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("1", "6", "0"),
                           socket_path=mock_socket_path, amp_details=None)

        expected_fc = {
            constants.HTTP_REUSE: True,
            constants.SERVER_STATE_FILE: True
        }
        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="1.6.0")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("1", "9", "0"),
                           socket_path=mock_socket_path, amp_details=None)

        expected_fc = {
            constants.HTTP_REUSE: True,
            constants.POOL_ALPN: True,
            constants.SERVER_STATE_FILE: True
        }
        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="1.9.0")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("2", "1", "1"),
                           socket_path=mock_socket_path, amp_details=None)

        expected_fc = {
            constants.HTTP_REUSE: True,
            constants.POOL_ALPN: True,
            lib_consts.PROTOCOL_PROMETHEUS: True,
            constants.SERVER_STATE_FILE: True
        }
        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="2.1.1")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("2", "2", "1"), amp_details=None,
                           socket_path=mock_socket_path)

        expected_fc = {
            constants.HTTP_REUSE: True,
            constants.POOL_ALPN: True,
            lib_consts.PROTOCOL_PROMETHEUS: True,
            constants.INSECURE_FORK: True,
            constants.SERVER_STATE_FILE: True
        }
        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="2.2.1")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("2", "4", "0"),
                           socket_path=mock_socket_path, amp_details=None)

        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="2.4.0")

        mock_render_loadbalancer_obj.reset_mock()

        j_cfg.build_config(mock_amp, mock_listeners, mock_tls_certs,
                           haproxy_versions=("3", "1", "0"),
                           socket_path=mock_socket_path, amp_details=None)

        mock_render_loadbalancer_obj.assert_called_once_with(
            mock_amp, mock_listeners, tls_certs=mock_tls_certs,
            socket_path=mock_socket_path, amp_details=None,
            feature_compatibility=expected_fc, haproxy_version="3.1.0")

    def test_transform_listener_tls_ciphers_injection_fallback(self):
        tainted = 'ECDHE-RSA-AES128-GCM-SHA256\ncheck'
        in_listener = sample_configs_combined.sample_listener_tuple(
            proto='TERMINATED_HTTPS', tls=True,
            tls_ciphers=tainted)
        ret = self.jinja_cfg._transform_listener(
            in_listener, None, {}, in_listener.load_balancer)
        # Should fall back to default, not use the tainted value
        self.assertEqual(self.DEFAULT_TLS_CIPHERS, ret['tls_ciphers'])
        self.assertEqual(
            self.DEFAULT_TLS_CIPHERSUITES, ret['tlsv1_3_ciphers'])

    def test_transform_listener_tls_ciphers_valid(self):
        valid = 'ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA'
        in_listener = sample_configs_combined.sample_listener_tuple(
            proto='TERMINATED_HTTPS', tls=True,
            tls_ciphers=valid)
        ret = self.jinja_cfg._transform_listener(
            in_listener, None, {}, in_listener.load_balancer)
        expected = ":".join(sorted(set(valid.split(":"))))
        self.assertEqual(expected, ret['tls_ciphers'])

    def test_transform_pool_tls_ciphers_injection_fallback(self):
        tainted = 'AES128-SHA\ncheck'
        in_pool = sample_configs_combined.sample_pool_tuple(
            tls_enabled=True, tls_ciphers=tainted)
        ret = self.jinja_cfg._transform_pool(in_pool, {}, False)
        self.assertEqual(self.DEFAULT_TLS_CIPHERS, ret['tls_ciphers'])
        self.assertEqual(
            self.DEFAULT_TLS_CIPHERSUITES, ret['tlsv1_3_ciphers'])

    def test_transform_pool_tls_ciphers_valid(self):
        valid = 'ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA'
        in_pool = sample_configs_combined.sample_pool_tuple(
            tls_enabled=True, tls_ciphers=valid)
        ret = self.jinja_cfg._transform_pool(in_pool, {}, False)
        expected = ":".join(sorted(set(valid.split(":"))))
        self.assertEqual(expected, ret['tls_ciphers'])
