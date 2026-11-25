# Copyright 2015 Hewlett Packard Enterprise Development Company LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
from pathlib import Path
import stat
import subprocess
from unittest import mock

import fixtures
import flask

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.amphorae.backends.agent.api_server import keepalivedlvs
from octavia.amphorae.backends.agent.api_server import server
from octavia.amphorae.backends.agent.api_server import udp_guard
from octavia.amphorae.backends.agent.api_server import util
from octavia.common import constants as consts
from octavia.tests.common import utils as test_utils
from octavia.tests.unit import base


class KeepalivedLvsTestCase(base.TestCase):
    FAKE_ID = uuidutils.generate_uuid()
    LISTENER_ID = 'listener-1111-1111-1111-listenerid00'
    POOL_ID = 'poolpool-1111-1111-1111-poolid000000'
    MEMBER_ID1 = 'memberid-1111-1111-1111-memberid1111'
    MEMBER_ID2 = 'memberid-2222-2222-2222-memberid2222'
    HEALTHMONITOR_ID = 'hmidhmid-1111-1111-1111-healthmonito'
    NORMAL_CFG_CONTENT = (
        "# Configuration for Listener %(listener_id)s\n\n"
        "net_namespace haproxy-amphora\n\n"
        "virtual_server 10.0.0.2 80 {\n"
        "    lb_algo rr\n"
        "    lb_kind NAT\n"
        "    protocol udp\n"
        "    delay_loop 30\n"
        "    delay_before_retry 31\n"
        "    retry 3\n\n\n"
        "    # Configuration for Pool %(pool_id)s\n"
        "    # Configuration for HealthMonitor %(hm_id)s\n"
        "    # Configuration for Member %(member1_id)s\n"
        "    real_server 10.0.0.99 82 {\n"
        "        weight 13\n"
        "        inhibit_on_failure\n"
        "        uthreshold 98\n"
        "        persistence_timeout 33\n"
        "        persistence_granularity 255.255.0.0\n"
        "        delay_before_retry 31\n"
        "        retry 3\n"
        "        MISC_CHECK {\n"
        "            misc_path \"/var/lib/octavia/lvs/check/"
        "udp_check.sh 10.0.0.99 82\"\n"
        "            misc_timeout 30\n"
        "            misc_dynamic\n"
        "        }\n"
        "    }\n\n"
        "    # Configuration for Member %(member2_id)s\n"
        "    real_server 10.0.0.98 82 {\n"
        "        weight 13\n"
        "        inhibit_on_failure\n"
        "        uthreshold 98\n"
        "        persistence_timeout 33\n"
        "        persistence_granularity 255.255.0.0\n"
        "        delay_before_retry 31\n"
        "        retry 3\n"
        "        MISC_CHECK {\n"
        "            misc_path \"/var/lib/octavia/lvs/check/"
        "udp_check.sh 10.0.0.98 82\"\n"
        "            misc_timeout 30\n"
        "            misc_dynamic\n"
        "        }\n"
        "    }\n\n"
        "}\n\n") % {'listener_id': LISTENER_ID, 'pool_id': POOL_ID,
                    'hm_id': HEALTHMONITOR_ID, 'member1_id': MEMBER_ID1,
                    'member2_id': MEMBER_ID2}
    PROC_CONTENT = (
        "IP Virtual Server version 1.2.1 (size=4096)\n"
        "Prot LocalAddress:Port Scheduler Flags\n"
        "  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\n"
        "UDP  0A000002:0050 sh\n"
        "  -> 0A000063:0052      Masq    13     1          0\n"
        "  -> 0A000062:0052      Masq    13     1          0\n"
    )
    NORMAL_PID_CONTENT = "1988"
    TEST_URL = server.PATH_PREFIX + '/listeners/%s/%s/udp_listener'

    def setUp(self):
        super().setUp()
        self.app = flask.Flask(__name__)
        self.client = self.app.test_client()
        self._ctx = self.app.test_request_context()
        self._ctx.push()
        self.test_keepalivedlvs = keepalivedlvs.KeepalivedLvs()
        self.app.add_url_rule(
            rule=self.TEST_URL % ('<amphora_id>', '<listener_id>'),
            view_func=(lambda amphora_id, listener_id:
                       self.test_keepalivedlvs.upload_lvs_listener_config(
                           listener_id)),
            methods=['PUT'])

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'run_systemctl_command')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'install_netns_systemd_service')
    @mock.patch('pyroute2.NetNS', create=True)
    @mock.patch('shutil.copy2')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    @mock.patch('os.makedirs')
    @mock.patch('os.remove')
    @mock.patch('subprocess.check_output')
    def test_upload_lvs_listener_config_no_vrrp_check_dir(
            self, m_check_output, m_os_rm, m_os_mkdir, m_exists, m_os_chmod,
            m_copy2, mock_netns, mock_install_netns, mock_systemctl):
        m_exists.side_effect = [False, False, True, True, False, False]
        cfg_path = util.keepalived_lvs_cfg_path(self.FAKE_ID)
        m = self.useFixture(test_utils.OpenFixture(cfg_path)).mock_open

        with mock.patch('os.open') as m_open, mock.patch.object(os,
                                                                'fdopen',
                                                                m) as m_fdopen:
            m_open.side_effect = ['TEST-WRITE-CFG',
                                  'TEST-WRITE-SYSINIT']

            res = self.client.put(self.TEST_URL % ('123', self.FAKE_ID),
                                  data=self.NORMAL_CFG_CONTENT)

            mock_install_netns.assert_called_once()
            systemctl_calls = [
                mock.call(consts.ENABLE,
                          consts.AMP_NETNS_SVC_PREFIX, False),
                mock.call(
                    consts.ENABLE,
                    'octavia-keepalivedlvs-%s.service' % self.FAKE_ID),
            ]
            mock_systemctl.assert_has_calls(systemctl_calls)
            os_mkdir_calls = [
                mock.call(util.keepalived_lvs_dir()),
                mock.call(util.keepalived_backend_check_script_dir())
            ]
            m_os_mkdir.assert_has_calls(os_mkdir_calls)

            m_os_chmod.assert_called_with(
                util.keepalived_backend_check_script_path(), stat.S_IEXEC)

            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            systemd_cfg_path = util.keepalived_lvs_init_path(self.FAKE_ID)

            m_open_calls = [
                mock.call(cfg_path, flags, mode),
                mock.call(systemd_cfg_path, flags, mode)
            ]
            m_open.assert_has_calls(m_open_calls)
            m_fdopen.assert_any_call('TEST-WRITE-CFG', 'wb')
            m_fdopen.assert_any_call('TEST-WRITE-SYSINIT', 'w')
            self.assertEqual(200, res.status_code)

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_lvs_listeners')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_loadbalancers')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'run_systemctl_command')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'install_netns_systemd_service')
    @mock.patch('pyroute2.NetNS', create=True)
    @mock.patch('shutil.copy2')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    @mock.patch('os.makedirs')
    @mock.patch('os.remove')
    @mock.patch('subprocess.check_output')
    def test_upload_lvs_listener_config_with_vrrp_check_dir(
            self, m_check_output, m_os_rm, m_os_mkdir, m_exists, m_os_chmod,
            m_copy2, mock_netns, mock_install_netns, mock_systemctl,
            mock_get_lbs, mock_get_lvs_listeners):
        m_exists.side_effect = [False, False, True, True, False, False, False]
        mock_get_lbs.return_value = []
        mock_get_lvs_listeners.return_value = [self.FAKE_ID]
        cfg_path = util.keepalived_lvs_cfg_path(self.FAKE_ID)
        m = self.useFixture(test_utils.OpenFixture(cfg_path)).mock_open

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='controller_worker',
                    loadbalancer_topology=consts.TOPOLOGY_ACTIVE_STANDBY)

        with mock.patch('os.open') as m_open, mock.patch.object(os,
                                                                'fdopen',
                                                                m) as m_fdopen:
            m_open.side_effect = ['TEST-WRITE-CFG',
                                  'TEST-WRITE-SYSINIT',
                                  'TEST-WRITE-UDP-VRRP-CHECK']
            res = self.client.put(self.TEST_URL % ('123', self.FAKE_ID),
                                  data=self.NORMAL_CFG_CONTENT)
            os_mkdir_calls = [
                mock.call(util.keepalived_lvs_dir()),
                mock.call(util.keepalived_backend_check_script_dir())
            ]
            m_os_mkdir.assert_has_calls(os_mkdir_calls)

            mock_install_netns.assert_called_once()
            systemctl_calls = [
                mock.call(consts.ENABLE,
                          consts.AMP_NETNS_SVC_PREFIX, False),
                mock.call(
                    consts.ENABLE,
                    'octavia-keepalivedlvs-%s.service' % self.FAKE_ID)
            ]
            mock_systemctl.assert_has_calls(systemctl_calls)

            m_os_chmod.assert_called_with(
                util.keepalived_backend_check_script_path(), stat.S_IEXEC)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            systemd_cfg_path = util.keepalived_lvs_init_path(self.FAKE_ID)
            script_path = os.path.join(
                util.keepalived_check_scripts_dir(),
                keepalivedlvs.KEEPALIVED_CHECK_SCRIPT_NAME)
            m_open_calls = [
                mock.call(cfg_path, flags, mode),
                mock.call(systemd_cfg_path, flags, mode),
                mock.call(script_path, flags, stat.S_IEXEC)
            ]
            m_open.assert_has_calls(m_open_calls)
            m_fdopen.assert_any_call('TEST-WRITE-CFG', 'wb')
            m_fdopen.assert_any_call('TEST-WRITE-SYSINIT', 'w')
            m_fdopen.assert_any_call('TEST-WRITE-UDP-VRRP-CHECK', 'w')

            m_os_rm.assert_called_once_with(util.haproxy_check_script_path())
            self.assertEqual(200, res.status_code)

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'run_systemctl_command')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'install_netns_systemd_service')
    @mock.patch('shutil.copy2')
    @mock.patch('os.chmod')
    @mock.patch('os.path.exists')
    @mock.patch('os.makedirs')
    @mock.patch('os.remove')
    @mock.patch('subprocess.check_output')
    def test_upload_lvs_listener_config_start_service_failure(
            self, m_check_output, m_os_rm, m_os_mkdir, m_exists, m_os_chmod,
            m_copy2, mock_install_netns, mock_systemctl):
        m_exists.side_effect = [False, False, True, True, False]
        cfg_path = util.keepalived_lvs_cfg_path(self.FAKE_ID)
        m = self.useFixture(test_utils.OpenFixture(cfg_path)).mock_open
        mock_systemctl.side_effect = [mock.DEFAULT, Exception('boom')]

        with mock.patch('os.open') as m_open, mock.patch.object(os,
                                                                'fdopen',
                                                                m) as m_fdopen:
            m_open.side_effect = ['TEST-WRITE-CFG',
                                  'TEST-WRITE-SYSINIT']
            res = self.client.put(self.TEST_URL % ('123', self.FAKE_ID),
                                  data=self.NORMAL_CFG_CONTENT)
            os_mkdir_calls = [
                mock.call(util.keepalived_lvs_dir()),
                mock.call(util.keepalived_backend_check_script_dir())
            ]
            m_os_mkdir.assert_has_calls(os_mkdir_calls)

            mock_install_netns.assert_called_once()
            systemctl_calls = [
                mock.call(consts.ENABLE,
                          consts.AMP_NETNS_SVC_PREFIX, False),
                mock.call(
                    consts.ENABLE,
                    'octavia-keepalivedlvs-%s.service' % self.FAKE_ID)
            ]
            mock_systemctl.assert_has_calls(systemctl_calls)

            m_os_chmod.assert_called_with(
                util.keepalived_backend_check_script_path(), stat.S_IEXEC)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            systemd_cfg_path = util.keepalived_lvs_init_path(self.FAKE_ID)
            m_open_calls = [
                mock.call(cfg_path, flags, mode),
                mock.call(systemd_cfg_path, flags, mode)
            ]
            m_open.assert_has_calls(m_open_calls)
            m_fdopen.assert_any_call('TEST-WRITE-CFG', 'wb')
            m_fdopen.assert_any_call('TEST-WRITE-SYSINIT', 'w')
            self.assertEqual(500, res.status_code)

    @mock.patch('subprocess.check_output')
    @mock.patch('octavia.amphorae.backends.agent.api_server.'
                'keepalivedlvs.KeepalivedLvs.'
                '_check_lvs_listener_exists')
    def test_manage_lvs_listener(self, mock_lvs_exist, mock_check_output):
        res = self.test_keepalivedlvs.manage_lvs_listener(self.FAKE_ID,
                                                          'start')
        cmd = f"systemctl start octavia-keepalivedlvs-{self.FAKE_ID}.service"
        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        self.assertEqual(202, res.status_code)

        res = self.test_keepalivedlvs.manage_lvs_listener(self.FAKE_ID,
                                                          'restart')
        self.assertEqual(400, res.status_code)

        mock_check_output.side_effect = subprocess.CalledProcessError(1,
                                                                      'blah!')

        res = self.test_keepalivedlvs.manage_lvs_listener(self.FAKE_ID,
                                                          'start')
        self.assertEqual(500, res.status_code)

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_lvs_listeners', return_value=[LISTENER_ID])
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_keepalivedlvs_pid', return_value="12345")
    @mock.patch('subprocess.check_output')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    def test_delete_lvs_listener(self, m_exist, m_remove, m_check_output,
                                 mget_pid, mget_lvs_listeners):
        m_exist.return_value = True
        res = self.test_keepalivedlvs.delete_lvs_listener(self.FAKE_ID)

        cmd1 = f"systemctl stop octavia-keepalivedlvs-{self.FAKE_ID}.service"
        cmd2 = ("systemctl disable "
                f"octavia-keepalivedlvs-{self.FAKE_ID}.service")
        calls = [
            mock.call(cmd1.split(), stderr=subprocess.STDOUT,
                      encoding='utf-8'),
            mock.call(cmd2.split(), stderr=subprocess.STDOUT,
                      encoding='utf-8')
        ]
        m_check_output.assert_has_calls(calls)
        self.assertEqual(200, res.status_code)

    @mock.patch.object(keepalivedlvs, "webob")
    @mock.patch('os.path.exists')
    def test_delete_lvs_listener_not_exist(self, m_exist, m_webob):
        m_exist.return_value = False
        self.test_keepalivedlvs.delete_lvs_listener(self.FAKE_ID)
        calls = [
            mock.call(
                json=dict(
                    message='UDP Listener Not Found',
                    details=f"No UDP listener with UUID: {self.FAKE_ID}"
                ), status=404),
            mock.call(json={'message': 'OK'})
        ]
        m_webob.Response.assert_has_calls(calls)

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_keepalivedlvs_pid', return_value="12345")
    @mock.patch('subprocess.check_output')
    @mock.patch('os.path.exists')
    def test_delete_lvs_listener_stop_service_fail(self, m_exist,
                                                   m_check_output, mget_pid):
        m_exist.return_value = True
        m_check_output.side_effect = subprocess.CalledProcessError(1,
                                                                   'Woops!')
        res = self.test_keepalivedlvs.delete_lvs_listener(self.FAKE_ID)
        self.assertEqual(500, res.status_code)
        self.assertEqual({'message': 'Error stopping keepalivedlvs',
                          'details': None}, res.json)

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_keepalivedlvs_pid', return_value="12345")
    @mock.patch('subprocess.check_output')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    def test_delete_lvs_listener_disable_service_fail(self, m_exist, m_remove,
                                                      m_check_output,
                                                      mget_pid):
        m_exist.return_value = True
        m_check_output.side_effect = [True,
                                      subprocess.CalledProcessError(
                                          1, 'Woops!')]
        res = self.test_keepalivedlvs.delete_lvs_listener(self.FAKE_ID)
        self.assertEqual(500, res.status_code)
        self.assertEqual({
            'message': f'Error disabling octavia-keepalivedlvs-{self.FAKE_ID} '
                       f'service',
            'details': None}, res.json)


class GuardedKeepalivedLvsTestCase(base.TestCase):
    IPVS_HEADER = (
        'IP Virtual Server version 1.2.1 (size=256)\n'
        'Prot LocalAddress:Port Scheduler Flags\n'
        '  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\n')

    def setUp(self):
        super().setUp()
        self.listener_id = uuidutils.generate_uuid()
        directory = Path(self.useFixture(fixtures.TempDir()).path)
        self.useFixture(oslo_fixture.Config(cfg.CONF)).config(
            group='haproxy_amphora', base_path=str(directory))
        self.useFixture(fixtures.MockPatchObject(
            consts, 'SYSTEMD_DIR', str(directory)))
        self.useFixture(fixtures.MockPatch(
            'octavia.amphorae.backends.agent.api_server.plug.Plug.plug_lo'))
        self.systemctl = self.useFixture(fixtures.MockPatchObject(
            util, 'run_systemctl_command')).mock
        self.useFixture(fixtures.MockPatchObject(
            util, 'send_vip_advertisements'))
        self.useFixture(fixtures.MockPatchObject(
            keepalivedlvs.KeepalivedLvs, '_guard_command',
            return_value='/usr/bin/amphora-udp-guard'))
        self.nft = self.useFixture(fixtures.MockPatchObject(
            udp_guard, '_in_namespace')).mock
        self.nft.return_value.stdout = '1\n'
        self.ipvs = self.useFixture(fixtures.MockPatchObject(
            udp_guard.keepalivedlvs_query, 'read_kernel_file')).mock
        self.client = server.Server(mock.Mock()).app.test_client()
        self.listener_url = (server.PATH_PREFIX +
                             f'/listeners/{self.listener_id}')
        self.reload_url = (server.PATH_PREFIX +
                           f'/loadbalancer/{self.listener_id}/reload')
        self.guard = udp_guard.Guard(self.listener_id)
        self.candidate = {
            'configuration': 'net_namespace amphora-haproxy\n',
            'guard': {
                'vip': '192.0.2.30', 'port': 18053, 'has_service': True,
                'fraction': {'numerator': 1, 'denominator': 4},
                'destinations': [{'address': '198.51.100.11', 'port': 15001,
                                  'weight': 3}], 'retiring': False,
            },
        }

    def _last_rules(self):
        return [call.kwargs['input'] for call in self.nft.call_args_list
                if 'input' in call.kwargs][-1]

    def test_failed_restart_keeps_listener_closed_until_ipvs_matches(self):
        response = self.client.put(self.listener_url + '/udp_guard',
                                   json=self.candidate)
        self.assertEqual(200, response.status_code)
        self.systemctl.side_effect = subprocess.CalledProcessError(
            1, 'systemctl', 'restart failed')
        self.assertEqual(500, self.client.put(self.reload_url).status_code)
        self.assertFalse(self.guard.read()['committed'])
        self.assertIn('ip daddr 192.0.2.30 udp dport 18053 counter drop',
                      self._last_rules())
        self.assertNotIn('numgen', self._last_rules())
        self.assertNotIn('192.0.2.31', self._last_rules())
        self.assertNotIn('18054', self._last_rules())

        self.systemctl.side_effect = None
        neighboring_service = ('UDP C000021E:4686 wrr\n'
                               ' -> C633640C:3A9A Masq 1 0 0\n')
        wrong_destination = ('UDP C000021E:4685 wrr\n'
                             ' -> C633640C:3A9A Masq 1 0 0\n')
        self.ipvs.return_value = (self.IPVS_HEADER + neighboring_service +
                                  wrong_destination)
        with mock.patch.object(udp_guard, 'CONVERGENCE_TIMEOUT', 0):
            self.assertEqual(500, self.client.put(self.reload_url).status_code)
        self.assertFalse(self.guard.read()['committed'])
        self.assertNotIn('numgen', self._last_rules())

        self.ipvs.return_value = (self.IPVS_HEADER + neighboring_service +
                                  'UDP C000021E:4685 wrr\n'
                                  ' -> C633640B:3A99 Masq 3 0 0\n')
        response = self.client.put(self.reload_url)
        self.assertEqual(202, response.status_code)
        self.assertEqual('1', response.headers[udp_guard.CONFIRMATION_HEADER])
        self.assertTrue(self.guard.read()['committed'])
        self.assertIn('ip daddr 192.0.2.30 udp dport 18053 '
                      'numgen inc mod 4 < 1 counter drop', self._last_rules())

    def test_stale_zero_weight_or_persistent_service_keeps_guard_closed(self):
        response = self.client.put(self.listener_url + '/udp_guard',
                                   json=self.candidate)
        self.assertEqual(200, response.status_code)
        expected = ' -> C633640B:3A99 Masq 3 0 0\n'
        stale = ' -> C633640C:3A9A Masq 0 1 0\n'
        with mock.patch.object(udp_guard, 'CONVERGENCE_TIMEOUT', 0):
            self.ipvs.return_value = (self.IPVS_HEADER +
                                      'UDP C000021E:4685 wrr\n' +
                                      expected + stale)
            self.assertEqual(500, self.client.put(self.reload_url).status_code)
            self.ipvs.return_value = (
                self.IPVS_HEADER +
                'UDP C000021E:4685 wrr persistent 300 FFFFFFFF\n' + expected)
            self.assertEqual(500, self.client.put(self.reload_url).status_code)
        self.assertFalse(self.guard.read()['committed'])
        self.assertNotIn('numgen', self._last_rules())

    def test_remove_pool_retires_only_its_guard(self):
        response = self.client.put(self.listener_url + '/udp_guard',
                                   json=self.candidate)
        self.assertEqual(200, response.status_code)
        self.candidate['guard'].update(has_service=False, retiring=True,
                                       destinations=[])
        response = self.client.put(self.listener_url + '/udp_guard',
                                   json=self.candidate)
        self.assertEqual(200, response.status_code)
        self.ipvs.return_value = self.IPVS_HEADER + 'UDP C000021E:4686 wrr\n'
        self.assertEqual(202, self.client.put(self.reload_url).status_code)
        self.assertFalse(self.guard.path.exists())
        self.assertEqual(f'table ip {self.guard.table} {{}}\n'
                         f'delete table ip {self.guard.table}\n',
                         self._last_rules())

    def test_compatible_listener_delete_reestablishes_proof_on_retry(self):
        self.candidate['guard'].update(has_service=False, retiring=True,
                                       destinations=[])
        self.ipvs.return_value = self.IPVS_HEADER + 'UDP C000021E:4686 wrr\n'
        for attempt in range(2):
            response = self.client.put(self.listener_url + '/udp_guard',
                                       json=self.candidate)
            self.assertEqual(200, response.status_code)
            response = self.client.delete(self.listener_url)
            self.assertEqual(200, response.status_code)
            self.assertEqual('1', response.headers[
                udp_guard.CONFIRMATION_HEADER])
            self.assertFalse(self.guard.path.exists())
            self.assertFalse(os.path.exists(
                util.keepalived_lvs_cfg_path(self.listener_id)))
            self.assertEqual(f'table ip {self.guard.table} {{}}\n'
                             f'delete table ip {self.guard.table}\n',
                             self._last_rules())
        self.assertEqual(2, self.ipvs.call_count)
        self.assertNotIn(mock.call(consts.AMP_ACTION_RESTART, mock.ANY),
                         self.systemctl.call_args_list)

    def test_listener_delete_removes_guard_and_blocks_legacy_upload(self):
        response = self.client.put(self.listener_url + '/udp_guard',
                                   json=self.candidate)
        self.assertEqual(200, response.status_code)
        stock_url = (server.PATH_PREFIX +
                     f'/listeners/amp/{self.listener_id}/udp_listener')
        response = self.client.put(stock_url, data='old worker')
        self.assertEqual(409, response.status_code)
        self.ipvs.return_value = self.IPVS_HEADER + 'UDP C000021E:4686 wrr\n'
        response = self.client.delete(self.listener_url)
        self.assertEqual(200, response.status_code)
        self.assertFalse(self.guard.path.exists())
        self.assertIn(f'delete table ip {self.guard.table}',
                      self._last_rules())
