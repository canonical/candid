import os

from charmhelpers.core import (
    hookenv,
    host,
)
import jaascharm

if __name__ == '__main__':
    hookenv.log('install')
    jaascharm.install(binary=os.path.join('bin', 'candidsrv'))
    host.mkdir('/var/log/candid', owner='candid', group='candid', perms=0o755)
