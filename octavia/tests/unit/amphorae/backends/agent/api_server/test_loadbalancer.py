# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
import hashlib
from pathlib import Path
import socket
import subprocess
import tempfile
from unittest import mock

import flask
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.amphorae.backends.agent.api_server import loadbalancer
from octavia.amphorae.backends.agent.api_server import util as agent_util
from octavia.common import constants as consts
from octavia.common import utils
from octavia.tests.common import sample_certs
from octavia.tests.common import utils as test_utils
import octavia.tests.unit.base as base

CONF = cfg.CONF
LISTENER_ID1 = uuidutils.generate_uuid()
LB_ID1 = uuidutils.generate_uuid()


class ListenerTestCase(base.TestCase):
    def setUp(self):
        super().setUp()
        self.mock_platform = mock.patch("distro.id").start()
        self.mock_platform.return_value = "ubuntu"
        self.test_loadbalancer = loadbalancer.Loadbalancer()

    def test_system_ca_stages_immutable_local_image_bundle(self):
        app = flask.Flask(__name__)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'system-ca.pem'
            pem = sample_certs.X509_CA_CERT
            source.write_bytes(pem)
            digest = hashlib.sha256(pem).hexdigest()
            config = self.useFixture(oslo_fixture.Config(CONF))
            config.config(group='haproxy_amphora', base_path=directory)
            request = {'path': str(source), 'sha256': digest}
            with app.test_request_context(json=request):
                stage = self.test_loadbalancer.stage_backend_tls_system_ca
                response = stage(LB_ID1)
                self.assertEqual(201, response.status_code)
                self.assertEqual({'sha256': digest}, response.json)
                self.assertEqual(201, stage(LB_ID1).status_code)
                snapshot = (root / LB_ID1 /
                            consts.HAPROXY_SYSTEM_CA_DIRECTORY /
                            f'{digest}.pem')
                self.assertEqual(pem, snapshot.read_bytes())

                source.write_bytes(b'')
                self.assertEqual(409, stage(LB_ID1).status_code)
                source.write_bytes(b'not a certificate')
                self.assertEqual(409, stage(LB_ID1).status_code)
                source.unlink()
                self.assertEqual(400, stage(LB_ID1).status_code)
                self.assertEqual(pem, snapshot.read_bytes())

            invalid = b'invalid with matching digest'
            source.write_bytes(invalid)
            request['sha256'] = hashlib.sha256(invalid).hexdigest()
            with app.test_request_context(json=request):
                self.assertEqual(400, stage(LB_ID1).status_code)

    def test_reload_acknowledges_only_the_running_config(self):
        for header, prefix in (
                (consts.HAPROXY_OTLP_PUBLICATION_HEADER, 'octavia-otlp'),
                (consts.HAPROXY_CONFIG_PUBLICATION_HEADER, 'octavia-config')):
            with self.subTest(header=header):
                self._check_reload_publication(header, prefix)

    def test_otlp_export_headers_are_redacted_from_agent_responses(self):
        label = 'cHJvYmU='
        config = ('listen private-otlp-collector\n'
                  f'    lua-load octavia.lua id sock service span '
                  f'export_headers={label}'
                  f'{consts.HAPROXY_OTLP_EXPORT_HEADER_MARKER}\n')
        app = flask.Flask(__name__)
        load_balancer = self.test_loadbalancer
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.useFixture(oslo_fixture.Config(CONF))
            fixture.config(group='haproxy_amphora', base_path=directory)
            target = Path(agent_util.config_path(LB_ID1))
            target.parent.mkdir()
            target.write_text(config)
            with mock.patch.object(load_balancer, '_check_lb_exists'):
                response = load_balancer.get_haproxy_config(LB_ID1)
            self.assertIn('listen private-otlp-collector', response.text)
            self.assertNotIn(label, response.text)
            self.assertEqual(config, target.read_text())

            error = subprocess.CalledProcessError(
                1, 'haproxy', output=f'invalid token near {label}')
            with (app.test_request_context(data=config),
                  mock.patch.object(loadbalancer.haproxy_compatibility,
                                    'process_cfg_for_version_compat',
                                    side_effect=lambda configuration:
                                    configuration),
                  mock.patch.object(loadbalancer.subprocess, 'check_output',
                                    side_effect=error),
                  mock.patch.object(loadbalancer.LOG, 'error') as log):
                response = load_balancer.upload_haproxy_config(
                    LISTENER_ID1, LB_ID1)
            self.assertEqual(400, response.status_code)
            self.assertNotIn(label, response.text)
            self.assertNotIn(label, str(log.call_args))

    def test_prunes_retired_otlp_sockets_after_publication(self):
        publication = '1' * 32
        description = f'octavia-otlp-{publication}'
        other_lb = uuidutils.generate_uuid()
        app = flask.Flask(__name__)
        agent = self.test_loadbalancer
        fixture = self.useFixture(oslo_fixture.Config(CONF))
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(consts, 'HAPROXY_OTLP_TRACING_SOCKET_DIR',
                              directory),
            mock.patch.object(agent, '_check_lb_exists'),
            mock.patch.object(agent, '_check_haproxy_status',
                              return_value=consts.ACTIVE),
            mock.patch.object(agent_util, 'run_systemctl_command'),
            mock.patch.object(agent_util, 'send_vip_advertisements'),
            mock.patch.object(loadbalancer.time, 'sleep'),
            mock.patch.object(loadbalancer.haproxy_query,
                              'HAProxyQuery') as query,
            socket.socket(socket.AF_UNIX) as previous,
            socket.socket(socket.AF_UNIX) as current,
            socket.socket(socket.AF_UNIX) as unrelated,
        ):
            fixture.config(group='haproxy_amphora', base_path=directory)
            prefix = utils.haproxy_otlp_export_socket_prefix(LB_ID1)
            old_path = Path(directory, prefix + 'a' * 32 + '.sock')
            new_path = Path(directory, prefix + 'b' * 32 + '.sock')
            other = utils.haproxy_otlp_export_socket_prefix(other_lb)
            other_path = Path(directory, other + 'a' * 32 + '.sock')
            previous.bind(str(old_path))
            previous.listen()
            current.bind(str(new_path))
            current.listen()
            unrelated.bind(str(other_path))
            unrelated.close()

            cfg = Path(agent_util.config_path(LB_ID1))
            cfg.parent.mkdir()
            cfg.write_text(
                f'global\n    description {description}\n'
                f'listen exporter\n    bind {new_path} mode 600\n')
            info = query.return_value.show_info
            with app.test_request_context(headers={
                    consts.HAPROXY_OTLP_PUBLICATION_HEADER: publication}):
                info.return_value = {'description': 'old', 'Stopping': '0'}
                self.assertEqual(503, agent.start_stop_lb(
                    LB_ID1, consts.AMP_ACTION_RELOAD).status_code)
                self.assertTrue(old_path.exists())
                # Even a confirmed reload permits an outgoing process
                # to finish draining an existing socket.
                info.return_value = {'description': description,
                                     'Stopping': '0'}
                self.assertEqual(202, agent.start_stop_lb(
                    LB_ID1, consts.AMP_ACTION_RELOAD).status_code)
                self.assertTrue(old_path.exists())
                previous.close()
                self.assertEqual(202, agent.start_stop_lb(
                    LB_ID1, consts.AMP_ACTION_RELOAD).status_code)
                self.assertFalse(old_path.exists())
                self.assertTrue(new_path.exists())
                self.assertTrue(other_path.exists())

            # A regular reload can remove the last exporter while serving
            # remaining application listeners.
            current.close()
            cfg.write_text('frontend app\n    bind 127.0.0.1:81\n')
            self.assertEqual(202, agent.start_stop_lb(
                LB_ID1, consts.AMP_ACTION_RELOAD).status_code)
            self.assertFalse(new_path.exists())
            self.assertTrue(other_path.exists())

            with socket.socket(socket.AF_UNIX) as retired:
                retired.bind(str(old_path))
            with (
                mock.patch.object(agent, '_cert_dir',
                                  return_value=str(cfg.parent / 'certs')),
                mock.patch.object(agent_util, 'init_path',
                                  return_value=str(cfg.parent / 'service')),
            ):
                self.assertEqual(200, agent.delete_lb(LB_ID1).status_code)
            self.assertFalse(old_path.exists())
            self.assertTrue(other_path.exists())

    def _check_reload_publication(self, header, prefix):
        publication = '1' * 32
        app = flask.Flask(__name__)
        with (
            app.test_request_context(headers={header: publication}),
            mock.patch.object(self.test_loadbalancer, '_check_lb_exists'),
            mock.patch.object(self.test_loadbalancer, '_check_haproxy_status',
                              return_value=consts.ACTIVE),
            mock.patch.object(agent_util, 'run_systemctl_command'),
            mock.patch.object(agent_util, 'send_vip_advertisements'),
            mock.patch.object(agent_util, 'vrrp_check_script_update'),
            mock.patch.object(loadbalancer.time, 'sleep'),
            mock.patch.object(loadbalancer.haproxy_query,
                              'HAProxyQuery') as query,
        ):
            info = query.return_value.show_info
            desired = f'{prefix}-{publication}'
            info.return_value = {'description': desired, 'Stopping': '1'}
            response = self.test_loadbalancer.start_stop_lb(
                LB_ID1, consts.AMP_ACTION_RELOAD)
            self.assertEqual(503, response.status_code)
            self.assertNotIn(header, response.headers)

            info.side_effect = [{'description': 'old', 'Stopping': '0'},
                                {'description': desired, 'Stopping': '0'}]
            response = self.test_loadbalancer.start_stop_lb(
                LB_ID1, consts.AMP_ACTION_RELOAD)
            self.assertEqual(202, response.status_code)
            self.assertEqual(publication, response.headers[header])

    @mock.patch('os.path.exists')
    @mock.patch('octavia.amphorae.backends.agent.api_server' +
                '.util.get_haproxy_pid')
    def test_check_haproxy_status(self, mock_pid, mock_exists):
        mock_pid.return_value = '1245'
        mock_exists.side_effect = [True, True]
        self.assertEqual(
            consts.ACTIVE,
            self.test_loadbalancer._check_haproxy_status(LISTENER_ID1))

        mock_exists.side_effect = [True, False]
        self.assertEqual(
            consts.OFFLINE,
            self.test_loadbalancer._check_haproxy_status(LISTENER_ID1))

        mock_exists.side_effect = [False]
        self.assertEqual(
            consts.OFFLINE,
            self.test_loadbalancer._check_haproxy_status(LISTENER_ID1))

    @mock.patch('time.sleep')
    @mock.patch('octavia.amphorae.backends.agent.api_server.loadbalancer.LOG')
    @mock.patch('octavia.amphorae.backends.agent.api_server.loadbalancer.'
                'Loadbalancer._check_haproxy_status')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'vrrp_check_script_update')
    @mock.patch('os.path.exists')
    @mock.patch('octavia.amphorae.backends.agent.api_server.loadbalancer.'
                'Loadbalancer._check_lb_exists')
    @mock.patch('subprocess.check_output')
    @mock.patch('octavia.amphorae.backends.utils.haproxy_query.HAProxyQuery')
    def test_start_stop_lb(self, mock_haproxy_query, mock_check_output,
                           mock_lb_exists, mock_path_exists, mock_vrrp_update,
                           mock_check_status, mock_LOG, mock_time_sleep):
        listener_id = uuidutils.generate_uuid()

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

        mock_path_exists.side_effect = [False, True, True, False, False]
        mock_check_status.side_effect = ['bogus', consts.OFFLINE]

        # Happy path - No VRRP
        cmd = "systemctl {action} haproxy-{listener_id}.service".format(
            action=consts.AMP_ACTION_START, listener_id=listener_id)

        result = self.test_loadbalancer.start_stop_lb(
            listener_id, consts.AMP_ACTION_START)

        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        mock_lb_exists.assert_called_once_with(listener_id)
        mock_vrrp_update.assert_not_called()
        self.assertEqual(202, result.status_code)
        self.assertEqual('OK', result.json['message'])
        ref_details = ('Configuration file is valid\n'
                       'haproxy daemon for {} started'.format(listener_id))
        self.assertEqual(ref_details, result.json['details'])

        # Happy path - VRRP - RELOAD
        conf.config(group="controller_worker",
                    loadbalancer_topology=consts.TOPOLOGY_ACTIVE_STANDBY)

        mock_lb_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_output.reset_mock()

        cmd = "systemctl {action} haproxy-{listener_id}.service".format(
            action=consts.AMP_ACTION_RELOAD, listener_id=listener_id)

        result = self.test_loadbalancer.start_stop_lb(
            listener_id, consts.AMP_ACTION_RELOAD)

        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        mock_lb_exists.assert_called_once_with(listener_id)
        mock_vrrp_update.assert_called_once_with(listener_id,
                                                 consts.AMP_ACTION_RELOAD)
        self.assertEqual(202, result.status_code)
        self.assertEqual('OK', result.json['message'])
        ref_details = f'Listener {listener_id} {consts.AMP_ACTION_RELOAD}ed'
        self.assertEqual(ref_details, result.json['details'])

        # Happy path - VRRP - RELOAD - OFFLINE
        mock_lb_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_output.reset_mock()

        cmd = "systemctl {action} haproxy-{listener_id}.service".format(
            action=consts.AMP_ACTION_START, listener_id=listener_id)

        result = self.test_loadbalancer.start_stop_lb(
            listener_id, consts.AMP_ACTION_RELOAD)

        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        mock_lb_exists.assert_called_once_with(listener_id)
        mock_vrrp_update.assert_called_once_with(listener_id,
                                                 consts.AMP_ACTION_RELOAD)
        self.assertEqual(202, result.status_code)
        self.assertEqual('OK', result.json['message'])
        ref_details = ('Configuration file is valid\n'
                       'haproxy daemon for {} started'.format(listener_id))
        self.assertEqual(ref_details, result.json['details'])

        # Unhappy path - Not already running
        conf.config(group="controller_worker",
                    loadbalancer_topology=consts.TOPOLOGY_SINGLE)

        mock_lb_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_output.reset_mock()

        cmd = "systemctl {action} haproxy-{listener_id}.service".format(
            action=consts.AMP_ACTION_START, listener_id=listener_id)

        mock_check_output.side_effect = subprocess.CalledProcessError(
            output='bogus', returncode=-2, cmd='sit')

        result = self.test_loadbalancer.start_stop_lb(
            listener_id, consts.AMP_ACTION_START)

        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        mock_lb_exists.assert_called_once_with(listener_id)
        mock_vrrp_update.assert_not_called()
        self.assertEqual(500, result.status_code)
        self.assertEqual(f'Error {consts.AMP_ACTION_START}ing haproxy',
                         result.json['message'])
        self.assertEqual('bogus', result.json['details'])

        # Unhappy path - Already running
        mock_lb_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_output.reset_mock()

        cmd = "systemctl {action} haproxy-{listener_id}.service".format(
            action=consts.AMP_ACTION_START, listener_id=listener_id)

        mock_check_output.side_effect = subprocess.CalledProcessError(
            output='Job is already running', returncode=-2, cmd='sit')

        result = self.test_loadbalancer.start_stop_lb(
            listener_id, consts.AMP_ACTION_START)

        mock_check_output.assert_called_once_with(cmd.split(),
                                                  stderr=subprocess.STDOUT,
                                                  encoding='utf-8')
        mock_lb_exists.assert_called_once_with(listener_id)
        mock_vrrp_update.assert_not_called()
        self.assertEqual(202, result.status_code)
        self.assertEqual('OK', result.json['message'])
        ref_details = ('Configuration file is valid\n'
                       'haproxy daemon for {} started'.format(listener_id))
        self.assertEqual(ref_details, result.json['details'])

        # Invalid action
        mock_check_output.reset_mock()
        mock_lb_exists.reset_mock()
        mock_path_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        result = self.test_loadbalancer.start_stop_lb(listener_id, 'bogus')
        self.assertEqual(400, result.status_code)
        self.assertEqual('Invalid Request', result.json['message'])
        self.assertEqual('Unknown action: bogus', result.json['details'])
        mock_lb_exists.assert_not_called()
        mock_path_exists.assert_not_called()
        mock_vrrp_update.assert_not_called()
        mock_check_output.assert_not_called()

        # haproxy error on reload
        mock_check_output.reset_mock()
        mock_lb_exists.reset_mock()
        mock_path_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_status.reset_mock()
        mock_LOG.reset_mock()

        mock_check_output.side_effect = [
            subprocess.CalledProcessError(
                output='haproxy.service is not active, cannot reload.',
                returncode=-2, cmd='service'),
            None]
        mock_check_status.return_value = 'ACTIVE'
        mock_check_status.side_effect = None

        mock_query = mock.Mock()
        mock_haproxy_query.return_value = mock_query
        mock_query.show_info.side_effect = [Exception("error"),
                                            {'Uptime_sec': 5}]

        result = self.test_loadbalancer.start_stop_lb(listener_id, 'reload')
        self.assertEqual(202, result.status_code)

        LOG_last_call = mock_LOG.mock_calls[-1]
        self.assertIn('An error occurred with haproxy', LOG_last_call[1][0])

        # haproxy error on reload - retry limit
        print("--")
        mock_check_output.reset_mock()
        mock_lb_exists.reset_mock()
        mock_path_exists.reset_mock()
        mock_vrrp_update.reset_mock()
        mock_check_status.reset_mock()
        mock_LOG.reset_mock()

        mock_check_output.side_effect = [
            subprocess.CalledProcessError(
                output='haproxy.service is not active, cannot reload.',
                returncode=-2, cmd='service'),
            subprocess.CalledProcessError(
                output='haproxy.service is not active, cannot reload.',
                returncode=-2, cmd='service'),
            subprocess.CalledProcessError(
                output='haproxy.service is not active, cannot reload.',
                returncode=-2, cmd='service')]
        mock_check_status.return_value = 'ACTIVE'
        mock_check_status.side_effect = None

        mock_query = mock.Mock()
        mock_haproxy_query.return_value = mock_query
        mock_query.show_info.side_effect = Exception("error")

        result = self.test_loadbalancer.start_stop_lb(listener_id, 'reload')
        self.assertEqual(500, result.status_code)
        self.assertEqual('Error reloading haproxy', result.json['message'])
        self.assertEqual('haproxy.service is not active, cannot reload.',
                         result.json['details'])

    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'config_path')
    @mock.patch('octavia.amphorae.backends.agent.api_server.util.'
                'get_haproxy_pid')
    @mock.patch('os.path.exists')
    def test_get_listeners_on_lb(self, mock_exists, mock_get_haproxy_pid,
                                 mock_config_path):

        fake_cfg_path = '/some/fake/cfg/file.cfg'
        mock_config_path.return_value = fake_cfg_path
        mock_get_haproxy_pid.return_value = 'fake_pid'

        # Finds two listeners
        mock_exists.side_effect = [True, True]
        fake_cfg_data = 'frontend list1\nbackend foo\nfrontend list2'
        self.useFixture(
            test_utils.OpenFixture(fake_cfg_path, fake_cfg_data)).mock_open
        result = self.test_loadbalancer._get_listeners_on_lb(LB_ID1)
        self.assertEqual(['list1', 'list2'], result)
        mock_exists.assert_has_calls([mock.call(agent_util.pid_path(LB_ID1)),
                                     mock.call('/proc/fake_pid')])

        # No PID file, no listeners
        mock_exists.reset_mock()
        mock_exists.side_effect = [False]
        result = self.test_loadbalancer._get_listeners_on_lb(LB_ID1)
        self.assertEqual([], result)
        mock_exists.assert_called_once_with(agent_util.pid_path(LB_ID1))

        # PID file, no running process, no listeners
        mock_exists.reset_mock()
        mock_exists.side_effect = [True, False]
        result = self.test_loadbalancer._get_listeners_on_lb(LB_ID1)
        self.assertEqual([], result)
        mock_exists.assert_has_calls([mock.call(agent_util.pid_path(LB_ID1)),
                                     mock.call('/proc/fake_pid')])

        # PID file, running process, no listeners
        mock_exists.reset_mock()
        mock_exists.side_effect = [True, True]
        fake_cfg_data = 'backend only'
        self.useFixture(
            test_utils.OpenFixture(fake_cfg_path, fake_cfg_data)).mock_open
        result = self.test_loadbalancer._get_listeners_on_lb(LB_ID1)
        self.assertEqual([], result)
        mock_exists.assert_has_calls([mock.call(agent_util.pid_path(LB_ID1)),
                                     mock.call('/proc/fake_pid')])
