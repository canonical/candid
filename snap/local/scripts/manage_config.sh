#!/bin/bash

# Manages configuration for livepatchd

DEFAULT_CONFIG="$(cat <<EOF
{
  "listen-address": ":8081",
  "private-addr": "127.0.0.1",
  "location": "http://127.0.0.1:8081",
  "logging-config": "INFO",
  "access-log": "/var/snap/candid/common/logs/candid.access.log",
  "resource-path": "/snap/candid/current/www/"
}
EOF
)"

# Sets the default config in snapd and dumps the file into $SNAP/config
set_defaults() {
    echo $(
      echo $DEFAULT_CONFIG | 
      yq -o json
    ) | xargs -d'\n' -I {} snapctl set -t candid={}
    snapctl set defaults.set=true
}

# Dumps the new config in snapd, to be discovered by livepatchd
dump_new_config() {
  snapctl get -d candid | 
    yq .candid -P --prettyPrint -o yaml > $SNAP_COMMON/config.yaml
  
  # fix identity-providers
  # extract the identity-providers field and remove "
  idps=`cat $SNAP_COMMON/config.yaml | yq .identity-providers | tr -d '"'`

  # env(idps) parses the idps env variable as yaml and embeds it in-place
  idps=$idps yq e -i '.identity-providers |= env(idps)' $SNAP_COMMON/config.yaml
}
