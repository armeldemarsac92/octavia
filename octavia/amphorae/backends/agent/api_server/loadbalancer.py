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
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import errno
import hashlib
import io
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import uuid

from cryptography import x509
import flask
import jinja2
from oslo_config import cfg
from oslo_log import log as logging
import webob
from werkzeug import exceptions

from octavia.amphorae.backends.agent.api_server import haproxy_compatibility
from octavia.amphorae.backends.agent.api_server import util
from octavia.amphorae.backends.utils import haproxy_query
from octavia.common import constants as consts
from octavia.common import utils as octavia_utils
from octavia.common import validate

LOG = logging.getLogger(__name__)
BUFFER = 100
HAPROXY_RELOAD_RETRIES = 3
HAPROXY_QUERY_RETRIES = 5
SYSTEM_CA_BUNDLE_LIMIT = 8 * 1024 * 1024
SYSTEM_CA_CERTIFICATE = re.compile(
    rb'-----BEGIN CERTIFICATE-----[\r\n]+'
    rb'[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----')
OTLP_EXPORT_HEADER_LINE = re.compile(
    r'(?m)^[ \t]*lua-load [^\n]*' +
    re.escape(consts.HAPROXY_OTLP_EXPORT_HEADER_MARKER) + r'[ \t]*$')

CONF = cfg.CONF

SYSTEMD_CONF = 'systemd.conf.j2'

JINJA_ENV = jinja2.Environment(
    autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.dirname(
        os.path.realpath(__file__)
    ) + consts.AGENT_API_TEMPLATES))
SYSTEMD_TEMPLATE = JINJA_ENV.get_template(SYSTEMD_CONF)


# Wrap a stream so we can compute the md5 while reading
class Wrapped:
    def __init__(self, stream_):
        self.stream = stream_
        self.hash = hashlib.md5(usedforsecurity=False)  # nosec

    def read(self, line):
        block = self.stream.read(line)
        if block:
            self.hash.update(block)
        return block

    def get_md5(self):
        return self.hash.hexdigest()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


class Loadbalancer:

    def get_haproxy_config(self, lb_id):
        """Gets the haproxy config

        :param listener_id: the id of the listener
        """
        self._check_lb_exists(lb_id)
        with open(util.config_path(lb_id), encoding='utf-8') as file:
            cfg = OTLP_EXPORT_HEADER_LINE.sub(
                '    # OTLP export header redacted', file.read())
            resp = webob.Response(cfg, content_type='text/plain')
            resp.headers['ETag'] = (
                hashlib.md5(octavia_utils.b(cfg),
                            usedforsecurity=False).hexdigest())  # nosec
            return resp

    @staticmethod
    def stage_backend_tls_system_ca(lb_id):
        request = flask.request.get_json(silent=True)
        if not isinstance(request, dict):
            return webob.Response(status=400)
        path, digest = request.get('path'), request.get('sha256')
        try:
            if (str(uuid.UUID(lb_id)) != lb_id or
                    not validate.is_backend_tls_system_ca_profile(
                        path, digest)):
                return webob.Response(status=400)
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK),
                           'rb') as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    return webob.Response(status=400)
                pem = source.read(SYSTEM_CA_BUNDLE_LIMIT + 1)
            if (not pem or len(pem) > SYSTEM_CA_BUNDLE_LIMIT or
                    hashlib.sha256(pem).hexdigest() != digest):
                return webob.Response(status=409)
            remainder = SYSTEM_CA_CERTIFICATE.sub(b'', pem)
            if any(line.strip() and not line.lstrip().startswith(b'#')
                   for line in remainder.splitlines()):
                return webob.Response(status=400)
            certificates = x509.load_pem_x509_certificates(pem)
            if not certificates or not all(
                    cert.extensions.get_extension_for_class(
                        x509.BasicConstraints).value.ca for cert in
                    certificates):
                return webob.Response(status=400)

            directory = os.path.join(util.haproxy_dir(lb_id),
                                     consts.HAPROXY_SYSTEM_CA_DIRECTORY)
            os.makedirs(directory, mode=0o700, exist_ok=True)
            snapshot = os.path.join(directory, f'{digest}.pem')
            # Publish a complete file once. Later stages can confirm the
            # snapshot but cannot replace it while HAProxy is loading it.
            with tempfile.NamedTemporaryFile(dir=directory) as staged:
                staged.write(pem)
                staged.flush()
                try:
                    os.link(staged.name, snapshot)
                except FileExistsError:
                    with open(snapshot, 'rb') as existing:
                        if existing.read(SYSTEM_CA_BUNDLE_LIMIT + 1) != pem:
                            return webob.Response(status=409)
        except (OSError, ValueError, x509.ExtensionNotFound,
                x509.DuplicateExtension):
            return webob.Response(status=400)
        return webob.Response(json={'sha256': digest}, status=201)

    def upload_haproxy_config(self, amphora_id, lb_id):
        """Upload the haproxy config

        :param amphora_id: The id of the amphora to update
        :param lb_id: The id of the loadbalancer
        """
        stream = Wrapped(flask.request.stream)
        # We have to hash here because HAProxy has a string length limitation
        # in the configuration file "peer <peername>" lines
        peer_name = octavia_utils.base64_sha1_string(amphora_id).rstrip('=')
        if not os.path.exists(util.haproxy_dir(lb_id)):
            os.makedirs(util.haproxy_dir(lb_id))

        name = os.path.join(util.haproxy_dir(lb_id), 'haproxy.cfg.new')
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        # mode 00600
        mode = stat.S_IRUSR | stat.S_IWUSR
        b = stream.read(BUFFER)
        s_io = io.StringIO()
        while b:
            # Write haproxy configuration to StringIO
            s_io.write(b.decode('utf8'))
            b = stream.read(BUFFER)

        # Since haproxy user_group is now auto-detected by the amphora agent,
        # remove it from haproxy configuration in case it was provided
        # by an older Octavia controller. This is needed in order to prevent
        # a duplicate entry for 'group' in haproxy configuration, which will
        # result an error when haproxy starts.
        new_config = re.sub(r"(?m)^[ \t]*group[ \t]+[^\n]+\n?", "",
                            s_io.getvalue())

        # Handle any haproxy version compatibility issues
        new_config = haproxy_compatibility.process_cfg_for_version_compat(
            new_config)

        with os.fdopen(os.open(name, flags, mode), 'w') as file:
            file.write(new_config)

        # use haproxy to check the config
        cmd = [util.CONF.haproxy_amphora.haproxy_cmd, '-c', '-L', peer_name,
               '-f', name, '-f', consts.HAPROXY_USER_GROUP_CFG]

        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                    encoding='utf-8')
        except subprocess.CalledProcessError as e:
            details = e.output
            if OTLP_EXPORT_HEADER_LINE.search(new_config):
                # HAProxy can embed config fragments in diagnostics.
                details = ('HAProxy rejected a configuration with '
                           'OTLP export headers.')
            for key in re.findall(
                    r'(?m)^\s*http-request set-var'
                    r'\(txn\.octavia_cookie_signing_key\) '
                    r'str\(([A-Za-z0-9+/]{43}=)\)$', new_config):
                details = details.replace(key, '[redacted]')
            LOG.error("Failed to verify haproxy file: %s %s", e, details)
            # Save the last config that failed validation for debugging
            os.rename(name, ''.join([name, '-failed']))
            return webob.Response(
                json={'message': "Invalid request", 'details': details},
                status=400)

        # file ok - move it
        os.rename(name, util.config_path(lb_id))

        init_path = util.init_path(lb_id)

        template = SYSTEMD_TEMPLATE
        # Render and install the network namespace systemd service
        util.install_netns_systemd_service()
        util.run_systemctl_command(
            consts.ENABLE, consts.AMP_NETNS_SVC_PREFIX + '.service', False)

        # mode 00644
        mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

        hap_major, hap_minor = haproxy_compatibility.get_haproxy_versions()
        if not os.path.exists(init_path):
            with os.fdopen(os.open(init_path, flags, mode), 'w') as text_file:

                text = template.render(
                    peer_name=peer_name,
                    haproxy_pid=util.pid_path(lb_id),
                    haproxy_cmd=util.CONF.haproxy_amphora.haproxy_cmd,
                    haproxy_cfg=util.config_path(lb_id),
                    haproxy_state_file=util.state_file_path(lb_id),
                    haproxy_socket=util.haproxy_sock_path(lb_id),
                    haproxy_user_group_cfg=consts.HAPROXY_USER_GROUP_CFG,
                    amphora_netns=consts.AMP_NETNS_SVC_PREFIX,
                    amphora_nsname=consts.AMPHORA_NAMESPACE,
                    haproxy_major_version=hap_major,
                    haproxy_minor_version=hap_minor
                )
                text_file.write(text)

        # Make sure the new service is enabled on boot
        try:
            util.run_systemctl_command(
                consts.ENABLE, consts.LOADBALANCER_SYSTEMD % lb_id)
        except subprocess.CalledProcessError as e:
            return webob.Response(json={
                'message': "Error enabling octavia-keepalived service",
                'details': e.output}, status=500)

        res = webob.Response(json={'message': 'OK'}, status=202)
        res.headers['ETag'] = stream.get_md5()

        return res

    def _check_haproxy_uptime(self, lb_id):
        stat_sock_file = util.haproxy_sock_path(lb_id)
        lb_query = haproxy_query.HAProxyQuery(stat_sock_file)
        retries = HAPROXY_QUERY_RETRIES
        for idx in range(retries):
            try:
                info = lb_query.show_info()
                uptime_sec = info['Uptime_sec']
            except Exception as e:
                LOG.warning('Failed to get haproxy info: %s, retrying.', e)
                time.sleep(1)
                continue
            uptime = int(uptime_sec)
            return uptime
        LOG.error('Failed to get haproxy uptime after %d tries.', retries)
        return None

    @staticmethod
    def _prune_otlp_export_sockets(lb_id, *, keep_configured=True):
        directory = consts.HAPROXY_OTLP_TRACING_SOCKET_DIR
        try:
            prefix = octavia_utils.haproxy_otlp_export_socket_prefix(lb_id)
        except ValueError:
            return
        name = re.compile(re.escape(prefix) + r'[a-f0-9]{32}\.sock')
        try:
            with os.scandir(directory) as sockets:
                candidates = {
                    entry.path for entry in sockets
                    if name.fullmatch(entry.name) and
                    stat.S_ISSOCK(entry.stat(follow_symlinks=False).st_mode)}
            if not candidates:
                return
            keep = set()
            if keep_configured:
                with open(util.config_path(lb_id), encoding='utf-8') as cfg:
                    keep = set(re.findall(r'(?m)^[ \t]*bind[ \t]+(\S+)',
                                          cfg.read()))
            candidates -= keep
            for attempt in range(HAPROXY_QUERY_RETRIES):
                bound = set()
                for path in candidates:
                    # On Linux, probing a live stream socket with a datagram
                    # socket returns EPROTOTYPE without opening a connection.
                    with socket.socket(socket.AF_UNIX,
                                       socket.SOCK_DGRAM) as probe:
                        state = probe.connect_ex(path)
                    if state == errno.ECONNREFUSED:
                        os.unlink(path)
                    elif state == errno.EPROTOTYPE:
                        bound.add(path)
                if not bound or attempt == HAPROXY_QUERY_RETRIES - 1:
                    break
                # An asynchronous reload can return just before the outgoing
                # HAProxy unbinds its listeners.
                candidates = bound
                time.sleep(0.1)
        except FileNotFoundError:
            pass
        except OSError:
            LOG.warning('Could not remove retired OTLP sockets for %s.', lb_id)

    def start_stop_lb(self, lb_id, action):
        action = action.lower()
        if action not in [consts.AMP_ACTION_START,
                          consts.AMP_ACTION_STOP,
                          consts.AMP_ACTION_RELOAD]:
            return webob.Response(json={
                'message': 'Invalid Request',
                'details': f"Unknown action: {action}"}, status=400)

        publication = None
        header = consts.HAPROXY_OTLP_PUBLICATION_HEADER
        description_prefix = 'octavia-otlp'
        if action == consts.AMP_ACTION_RELOAD and flask.has_request_context():
            config_header = consts.HAPROXY_CONFIG_PUBLICATION_HEADER
            if config_header in flask.request.headers:
                header = config_header
                description_prefix = 'octavia-config'
            publication = flask.request.headers.get(header)
            if (publication is not None and
                    not re.fullmatch('[a-f0-9]{32}', publication)):
                return webob.Response(
                    json={'message': 'Invalid publication ID'}, status=400)

        self._check_lb_exists(lb_id)
        is_vrrp = (CONF.controller_worker.loadbalancer_topology ==
                   consts.TOPOLOGY_ACTIVE_STANDBY)

        if is_vrrp:
            util.vrrp_check_script_update(lb_id, action)

        # HAProxy does not start the process when given a reload
        # so start it if haproxy is not already running
        if action == consts.AMP_ACTION_RELOAD:
            if consts.OFFLINE == self._check_haproxy_status(lb_id):
                action = consts.AMP_ACTION_START
            else:
                # We first have to save the state when we reload
                haproxy_state_file = util.state_file_path(lb_id)
                stat_sock_file = util.haproxy_sock_path(lb_id)

                lb_query = haproxy_query.HAProxyQuery(stat_sock_file)
                if not lb_query.save_state(haproxy_state_file):
                    # We accept to reload haproxy even if the state_file is
                    # not generated, but we probably want to know about that
                    # failure!
                    LOG.warning('Failed to save haproxy-%s state!', lb_id)

        retries = (HAPROXY_RELOAD_RETRIES
                   if action == consts.AMP_ACTION_RELOAD
                   else 1)
        saved_exc = None
        for idx in range(retries):
            try:
                util.run_systemctl_command(
                    action, consts.LOADBALANCER_SYSTEMD % lb_id)
            except subprocess.CalledProcessError as e:
                # Mitigation for
                # https://bugs.launchpad.net/octavia/+bug/2054666
                if ('is not active, cannot reload.' in e.output and
                        action == consts.AMP_ACTION_RELOAD):

                    saved_exc = e

                    # Wait a few seconds and check that haproxy was restarted
                    uptime = self._check_haproxy_uptime(lb_id)
                    # If haproxy is not reachable or was restarted more than 15
                    # sec ago, let's retry (or maybe restart?)
                    if not uptime or uptime > 15:
                        continue
                    # haproxy probably crashed and was restarted, log it and
                    # continue
                    LOG.warning("An error occurred with haproxy while it "
                                "was reloaded, check the haproxy logs for "
                                "more details.")
                    break
                if 'Job is already running' not in e.output:
                    return webob.Response(json={
                        'message': f"Error {action}ing haproxy",
                        'details': e.output
                    }, status=500)
            break
        else:
            # no break, we reach the retry limit for reloads
            return webob.Response(json={
                'message': f"Error {action}ing haproxy",
                'details': saved_exc.output}, status=500)

        # If we are not in active/standby we need to send an IP
        # advertisement (GARP or NA). Keepalived handles this for
        # active/standby load balancers.
        if not is_vrrp and action in [consts.AMP_ACTION_START,
                                      consts.AMP_ACTION_RELOAD]:
            util.send_vip_advertisements(lb_id)

        if publication is not None:
            query = haproxy_query.HAProxyQuery(
                util.haproxy_sock_path(lb_id), timeout=0.3)
            description = f'{description_prefix}-{publication}'
            # systemctl only signals HAProxy. Wait for the active data-plane
            # worker to report the exact description from the uploaded config.
            for _ in range(HAPROXY_QUERY_RETRIES):
                try:
                    info = query.show_info()
                except Exception:
                    info = {}
                if (info.get('description') == description and
                        info.get('Stopping') == '0'):
                    self._prune_otlp_export_sockets(lb_id)
                    response = webob.Response(
                        json={'message': 'OK'}, status=202)
                    response.headers[header] = publication
                    return response
                time.sleep(0.1)
            return webob.Response(
                json={'message': 'HAProxy publication unconfirmed'},
                status=503)

        self._prune_otlp_export_sockets(
            lb_id, keep_configured=action != consts.AMP_ACTION_STOP)
        if action in [consts.AMP_ACTION_STOP,
                      consts.AMP_ACTION_RELOAD]:
            return webob.Response(json={
                'message': 'OK',
                'details': f'Listener {lb_id} {action}ed'}, status=202)

        details = (
            f'Configuration file is valid\nhaproxy daemon for {lb_id} started'
        )

        return webob.Response(json={'message': 'OK', 'details': details},
                              status=202)

    def delete_lb(self, lb_id):
        try:
            self._check_lb_exists(lb_id)
        except exceptions.HTTPException:
            return webob.Response(json={'message': 'OK'})

        # check if that haproxy is still running and if stop it
        if os.path.exists(util.pid_path(lb_id)) and os.path.exists(
                os.path.join('/proc', util.get_haproxy_pid(lb_id))):
            try:
                util.run_systemctl_command(
                    consts.STOP, consts.LOADBALANCER_SYSTEMD % lb_id)
            except subprocess.CalledProcessError as e:
                LOG.error("Failed to stop haproxy-%s service: %s %s",
                          lb_id, e, e.output)
                return webob.Response(json={
                    'message': "Error stopping haproxy",
                    'details': e.output}, status=500)

        # parse config and delete stats socket
        try:
            stats_socket = util.parse_haproxy_file(lb_id)[0]
            os.remove(stats_socket)
        except Exception:
            pass

        # Since this script should be deleted at LB delete time
        # we can check for this path to see if VRRP is enabled
        # on this amphora and not write the file if VRRP is not in use
        if os.path.exists(util.keepalived_check_script_path()):
            util.vrrp_check_script_update(
                lb_id, action=consts.AMP_ACTION_STOP)

        # delete the ssl files
        try:
            shutil.rmtree(self._cert_dir(lb_id))
        except Exception:
            pass

        # disable the service
        init_path = util.init_path(lb_id)

        util.run_systemctl_command(
            consts.DISABLE, consts.LOADBALANCER_SYSTEMD % lb_id, False)

        # delete the directory + init script for that listener
        self._prune_otlp_export_sockets(lb_id, keep_configured=False)
        shutil.rmtree(util.haproxy_dir(lb_id))
        if os.path.exists(init_path):
            os.remove(init_path)

        return webob.Response(json={'message': 'OK'})

    def get_all_listeners_status(self, other_listeners=None):
        """Gets the status of all listeners

        This method will not consult the stats socket
        so a listener might show as ACTIVE but still be
        in ERROR

        Currently type==SSL is also not detected
        """
        listeners = []

        for lb in util.get_loadbalancers():
            stats_socket, listeners_on_lb = util.parse_haproxy_file(lb)

            for listener_id, listener in listeners_on_lb.items():
                listeners.append({
                    'status': consts.ACTIVE,
                    'uuid': listener_id,
                    'type': listener['mode'],
                })

        if other_listeners:
            listeners = listeners + other_listeners
        return webob.Response(json=listeners, content_type='application/json')

    def upload_certificate(self, lb_id, filename):
        self._check_ssl_filename_format(filename)

        # create directory if not already there
        if not os.path.exists(self._cert_dir(lb_id)):
            os.makedirs(self._cert_dir(lb_id))

        stream = Wrapped(flask.request.stream)
        file = self._cert_file_path(lb_id, filename)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        # mode 00600
        mode = stat.S_IRUSR | stat.S_IWUSR
        with os.fdopen(os.open(file, flags, mode), 'wb') as crt_file:
            b = stream.read(BUFFER)
            while b:
                crt_file.write(b)
                b = stream.read(BUFFER)

        resp = webob.Response(json={'message': 'OK'})
        resp.headers['ETag'] = stream.get_md5()
        return resp

    def get_certificate_md5(self, lb_id, filename):
        self._check_ssl_filename_format(filename)

        cert_path = self._cert_file_path(lb_id, filename)
        path_exists = os.path.exists(cert_path)
        if not path_exists:
            return webob.Response(json={
                'message': 'Certificate Not Found',
                'details': f"No certificate with filename: {filename}"},
                status=404)

        with open(cert_path, encoding='utf-8') as crt_file:
            cert = crt_file.read()
            md5sum = hashlib.md5(octavia_utils.b(cert),
                                 usedforsecurity=False).hexdigest()  # nosec
            resp = webob.Response(json={'md5sum': md5sum})
            resp.headers['ETag'] = md5sum
            return resp

    def delete_certificate(self, lb_id, filename):
        self._check_ssl_filename_format(filename)
        if os.path.exists(self._cert_file_path(lb_id, filename)):
            os.remove(self._cert_file_path(lb_id, filename))
        return webob.Response(json={'message': 'OK'})

    def _get_listeners_on_lb(self, lb_id):
        if os.path.exists(util.pid_path(lb_id)):
            if os.path.exists(
                    os.path.join('/proc', util.get_haproxy_pid(lb_id))):
                # Check if the listener is disabled
                with open(util.config_path(lb_id), encoding='utf-8') as file:
                    cfg = file.read()
                    m = re.findall('^frontend (.*)$', cfg, re.MULTILINE)
                    return m or []
            else:  # pid file but no process...
                return []
        else:
            return []

    def _check_lb_exists(self, lb_id):
        # check if we know about that lb
        if lb_id not in util.get_loadbalancers():
            raise exceptions.HTTPException(
                response=webob.Response(json={
                    'message': 'Loadbalancer Not Found',
                    'details': f"No loadbalancer with UUID: {lb_id}"},
                    status=404))

    def _check_ssl_filename_format(self, filename):
        # check if the format is (xxx.)*xxx.pem
        if not re.search(r'(\w.)+pem', filename):
            raise exceptions.HTTPException(
                response=webob.Response(json={
                    'message': 'Filename has wrong format'}, status=400))

    def _cert_dir(self, lb_id):
        return os.path.join(util.CONF.haproxy_amphora.base_cert_dir, lb_id)

    def _cert_file_path(self, lb_id, filename):
        return os.path.join(self._cert_dir(lb_id), filename)

    def _check_haproxy_status(self, lb_id):
        if os.path.exists(util.pid_path(lb_id)):
            if os.path.exists(
                    os.path.join('/proc', util.get_haproxy_pid(lb_id))):
                return consts.ACTIVE
        return consts.OFFLINE
