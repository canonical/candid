import json
import os
import shutil
import subprocess
import tarfile
import time
import urllib.request

from charmhelpers.contrib.charmsupport.nrpe import NRPE
from charmhelpers.core import (
    hookenv,
    host,
    templating,
)
import yaml

# The port that the HTTP service listens on.
HTTP_LISTEN_PORT = 8080


def install(binary=None):
    """Install the service from the specified resource. We assume that
       the charm metadata specifies a "service" resource that is associated
       with a compressed tar archive containing the files required by the
       service, including the service binary itself.

    Parameters:
       binary - Path to the service binary within the resource tar file.
                Default is bin/<charm name>.
    """

    service = _service()
    root = _root()
    resource_path = os.path.join(root, 'service')
    if not binary:
        binary = os.path.join('bin', service)

    host.adduser(service)
    host.mkdir(root, perms=0o755)

    new_resource_path = resource_path + '.new'
    old_resource_path = resource_path + '.old'
    # Remove possible remnants of a failed install and
    # the previous previous resource directory.
    shutil.rmtree(new_resource_path, ignore_errors=True)
    shutil.rmtree(old_resource_path, ignore_errors=True)

    hookenv.status_set('maintenance', 'getting service resource')
    resource_file = hookenv.resource_get('service')
    if not resource_file:
        hookenv.status_set('blocked', 'waiting for service resource')
        return

    hookenv.status_set('maintenance', 'installing {}'.format(service))
    with tarfile.open(resource_file) as tf:
        tf.extractall(new_resource_path)
        # Change the owner/group of all extracted files to root/wheel.
        for name in tf.getnames():
            os.chown(os.path.join(new_resource_path, name), 0, 0)

    # Sanity check that at least the service binary exists in the
    # unarchived service resource.
    if not os.path.exists(os.path.join(new_resource_path, binary)):
        hookenv.status_set('blocked', 'no binary found in service resource')
        return

    # Move the old directory out of the way and the newly unarchived
    # directory to its destination path.
    if os.path.exists(resource_path):
        os.rename(resource_path, old_resource_path)
    os.rename(new_resource_path, resource_path)

    service_path = os.path.join(root, '{}.service'.format(service))
    context = {
        'resource_path': resource_path,
        'bin_path': os.path.join(resource_path, binary),
        'config_path': _config_path(),
    }
    templating.render(
        'service',
        service_path,
        context,
    )
    if not _service_enabled():
        host.service('enable', service_path)
    else:
        subprocess.check_call(('systemctl', 'daemon-reload'))

    hookenv.open_port(HTTP_LISTEN_PORT)


def stop():
    """Stop the service."""
    host.service_stop(_service())


def update_config(config):
    """Update the configuration file for the service with the
       configuration keys specified in config. If a config key has a value of
       None then that value will be removed from the configuration file.
       It reports whether the config file was changed.
    """
    path = _config_path()
    data = {}
    changed = True
    if os.path.exists(path):
        changed = False
        with open(path) as f:
            data = yaml.safe_load(f)

    for k in config:
        if config[k] is None:
            if k in data:
                changed = True
                del data[k]
            continue
        if data.get(k) == config[k]:
            continue
        data[k] = config[k]
        changed = True

    if not changed:
        return False

    host.write_file(
        path,
        yaml.safe_dump(data),
        group=_service(),
        perms=0o640,
    )
    return True


def update_config_and_restart(config):
    """Update the YAML configuration file for service with config
       (see update_config for how this argument is treated) and
       restart the service. The service will only be restarted if the
       configuration is changed or the service is already not yet running.
       """
    changed = update_config(config)
    if not _service_enabled():
        return
    service = _service()
    if _service_running():
        if not changed:
            return
        hookenv.status_set('maintenance',
                           'restarting {} service'.format(service))
        host.service_restart(service)
    else:
        hookenv.status_set('maintenance',
                           'starting {} service'.format(service))
        host.service_start(service)


def update_nrpe_config():
    """Update the NRPE configuration for the given service."""
    hookenv.log("updating NRPE checks")
    service = _service()
    nrpe = NRPE()
    nrpe.add_check(
        shortname=service,
        description='Check {} running'.format(service),
        check_cmd='check_http -w 2 -c 10 -I {} -p {} -u /debug/info'.format(
            hookenv.unit_private_ip(),
            HTTP_LISTEN_PORT,
        )
    )
    nrpe.write()


def update_status(failed_status=None):
    """Update the status message for the specified service.
       If failed_status is specified it will be called with the message
       when the service is determined to have failed. failed_status
       should return a tuple containing the status set and the message."""

    # sleep for a little bit so that we have some likelihood that
    # if the service has just been started and immediately exited,
    # we'll be able to provide immediate feedback.
    time.sleep(0.2)

    if _service_running():
        _set_active_status()
    if _service_failed():
        failed_status = failed_status or _default_failed_status
        status, msg = failed_status(_failed_msg())
        hookenv.status_set(status, msg)


def _set_active_status():
    """Set the status for a service that has been detected as active."""
    url = 'http://localhost:{}/debug/info'.format(HTTP_LISTEN_PORT)
    try:
        with urllib.request.urlopen(url) as resp:
            buf = resp.read().decode('utf-8')
            data = json.loads(buf)
    except Exception as e:
        hookenv.log('cannot get version: {}'.format(e))
        return
    hookenv.status_set('active', '')
    hookenv.application_version_set(data.get('Version', ''))


def _failed_msg():
    """Determine the reason the given service is failed by checking the
       service logs."""
    cmd = ('journalctl', '-u', _service(), '-o', 'cat', '-n', '20')
    msg = ''
    try:
        out = subprocess.check_output(cmd).decode()
        for line in out.splitlines():
            if line.startswith('START'):
                msg = ''
            if line.startswith('STOP'):
                if len(line) > 5:
                    msg = line[5:]
    except subprocess.CalledProcessError:
        pass
    return msg


def _default_failed_status(msg):
    return 'blocked', msg


def _service():
    """Return the name of the service, derived from the charm name"""
    return hookenv.metadata()['name']


def _root():
    """Return the root directory for installations for the charm."""
    return os.path.join('/srv', _service())


def _config_path():
    """Return the path to the service configuration file."""
    return os.path.join(_root(), 'config.yaml')


def _service_failed():
    """Report whether the service has failed."""
    return host.service('is-failed', _service())


def _service_enabled():
    """Report whether the service has been enabled."""
    return host.service('is-enabled', _service())


def _service_running():
    """Report whether the service is running."""
    return host.service_running(_service())
