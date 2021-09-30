from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.core import hookenv, host
from charms import leadership
from charms.layer import candid
from charms.reactive import (
    any_file_changed,
    clear_flag,
    endpoint_from_flag,
    hook,
    register_trigger,
    set_flag,
    when,
    when_not,
)


CONFIG_FILE = '/var/snap/candid/current/config.yaml'


register_trigger(when='candid.available', clear_flag='candid.configured')
register_trigger(when='config.changed', clear_flag='candid.configured')
register_trigger(when='leadership.set.private-key',
                 clear_flag='candid.configured')
register_trigger(when='leadership.set.public-key',
                 clear_flag='candid.configured')
register_trigger(when='postgres.master.changed',
                 clear_flag='candid.configured')


@when('snap.installed.candid')
@when('leadership.is_leader')
@when_not('leadership.set.private-key')
def create_keypair():
    hookenv.status_set('maintenance', 'Generating default keypair')
    key = candid.generate_keypair()
    leadership.leader_set({"private-key": key["private"]})
    leadership.leader_set({"public-key": key["public"]})


@when_not('candid.port_opened')
def open_port():
    hookenv.status_set('maintenance', 'Opening port')
    hookenv.open_port(8081)
    set_flag('candid.port_opened')


@when_not('candid.configured')
def write_config_file():
    cc = hookenv.config()
    lc = leadership.leader_get()
    config = {
        "api-macaroon-timeout": cc["api-macaroon-timeout"],
        "discharge-macaroon-timeout": cc["discharge-macaroon-timeout"],
        "discharge-token-timeout": cc["discharge-token-timeout"],
        "enable-email-login": cc["enable-email-login"],
        "logging-config": cc["logging-config"],
        "private-addr": hookenv.unit_private_ip(),
        "rendezvous-timeout": cc["rendezvous-timeout"],
        "skip-location-for-cookie-paths": cc["skip-location-for-cookie-paths"],
    }
    if cc["admin-agent-public-key"]:
        config["admin-agent-public-key"] = cc["admin-agent-public-key"]
    if cc["http-proxy"]:
        config["http-proxy"] = cc["http-proxy"]
        # extend no-proxy to include all candid units.
        no_proxy = [cc["no-proxy"]]
        if not no_proxy[0]:
            no_proxy = no_proxy[1:]
        ep = endpoint_from_flag('candid.connected')
        if ep:
            no_proxy.extend(ep.addresses)
        config["no-proxy"] = ",".join(no_proxy)
    if cc["identity-providers"]:
        try:
            config["identity-providers"] = \
                candid.parse_identity_providers(cc["identity-providers"])
        except candid.IdentityProvidersParseError as e:
            hookenv.log("invalid identity providers: {}".format(e),
                        level="error")
    if cc["location"]:
        config["location"] = cc["location"]
    if cc["private-key"]:
        config["private-key"] = cc["private-key"]
    elif lc.get("private-key"):
        config["private-key"] = lc["private-key"]
    if cc["public-key"]:
        config["public-key"] = cc["public-key"]
    elif lc.get("public-key"):
        config["public-key"] = lc["public-key"]
    if cc["redirect-login-trusted-urls"]:
        config["redirect-login-trusted-urls"] = \
            _parse_list(cc["redirect-login-trusted-urls"])
    if cc["redirect-login-trusted-domains"]:
        config["redirect-login-trusted-domains"] = \
            _parse_list(cc["redirect-login-trusted-domains"])
    if cc["mfa-rp-id"]:
        config["mfa-rp-id"] =  cc["mfa-rp-id"]
    if cc["mfa-rp-display-name"]:
        config["mfa-rp-display-name"] =  cc["mfa-rp-display-name"]
    if cc["mfa-rp-origin"]:
        config["mfa-rp-origin"] =  cc["mfa-rp-origin"]
    pg = endpoint_from_flag('postgres.master.available')
    if pg:
        config["storage"] = {
            "type": "postgres",
            "connection-string": str(pg.master),
        }
    else:
        config["storage"] = {"type": "memory"}

    candid.update_config(CONFIG_FILE, config)
    set_flag('candid.configured')
    set_flag('candid.restart')


@when('candid.restart')
def restart_candid():
    clear_flag('candid.restart')
    if not any_file_changed([CONFIG_FILE]):
        hookenv.log("not restarting: config file unchanged", level="info")
        return
    hookenv.status_set('maintenance', 'Restarting candid')
    host.service_restart('snap.candid.candidsrv.service')
    update_status()


@hook('update-status')
def update_status():
    try:
        hookenv.application_version_set(candid.get_version())
        hookenv.status_set('active', '')
    except Exception as e:
        hookenv.log("cannot get version: {}".format(e), level="warning")


@when('nrpe-external-master.available')
def configure_nrpe():
    nrpeconfig = nrpe.NRPE()
    nrpeconfig.add_check(
        shortname="candid",
        description='Check candid running',
        check_cmd='check_http -w 2 -c 10 -I {} -p 8081 -u /debug/info'.format(
            hookenv.unit_private_ip(),
        )
    )
    nrpeconfig.write()


@when('website.available')
def website_available():
    ep = endpoint_from_flag('website.available')
    ep.configure(8081)


def _parse_list(s):
    if not s:
        return None
    return [t.strip() for t in s.split(",")]
