#!/bin/bash

. "$SNAP/scripts/manage_config.sh"

echo "Starting candid ..."
"$SNAP/bin/candidsrv $SNAP_COMMON/config.yaml" 