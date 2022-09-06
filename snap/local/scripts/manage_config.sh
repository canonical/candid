#!/bin/bash

# Manages configuration for livepatchd

DEFAULT_CONFIG="$(cat <<EOF
{
  "listen-address": ":8081",
  "private-addr": "127.0.0.1",
  "location": "http://127.0.0.1:8081",
  "storage": {
    "type": "memory"
  },
  "identity-providers": [
    {
      "type": "static",
      "name": "static",
      "users": {
        "user1": {
          "name": "User One",
          "email": "user1@example.com",
          "password": "password1",
          "groups": [
            "group1",
            "group3"
          ]
        },
        "user2": {
          "name": "User Two",
          "email": "user2@example.com",
          "password": "password2",
          "groups": [
            "group2",
            "group3"
          ]
        }
      }
    }
  ],
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
  # Parses - back to _ for the keys, such that they can be read by livepatchd
  snapctl get -d candid | 
    yq .candid -P --prettyPrint -o yaml > $SNAP_COMMON/config.yaml
}