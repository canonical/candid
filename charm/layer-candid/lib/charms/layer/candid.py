import base64
import binascii
import json
import subprocess
import urllib.request

import yaml


class IdentityProvidersParseError(Exception):
    """Error parsing identity provider configuration."""
    pass


def generate_keypair():
    """ Create a default keypair shared by all units in the application,
        if a keypair is not explicitely configured. """
    res = subprocess.run(
        ("/snap/candid/current/bin/bakery-keygen", ),
        stdout=subprocess.PIPE)
    res.check_returncode()
    return json.loads(res.stdout.decode('utf-8'))


def parse_identity_providers(idps):
    """ parse the identity-providers configuration option. """
    b64err = None
    try:
        idps = base64.b64decode(idps, validate=True)
    except binascii.Error as e:
        # Be tolerant of non-base64 values, to facilitate upgrades from
        # earlier charm versions.
        b64err = e
    try:
        return yaml.safe_load(idps)
    except yaml.YAMLError as e:
        msg = "error parsing identity-providers: {}".format(e)
        if b64err:
            msg += ", {}".format(b64err)
        raise IdentityProvidersParseError()


def update_config(file, config):
    with open(file) as f:
        appconfig = yaml.safe_load(f)
    for k, v in config.items():
        appconfig[k] = v
    with open(file, 'wb') as f:
        f.write(yaml.dump(appconfig, encoding="utf-8"))


def get_version():
    with urllib.request.urlopen('http://localhost:8081/debug/info') as resp:
        data = json.loads(resp.read().decode('utf-8'))
    return data.get('Version', '')
