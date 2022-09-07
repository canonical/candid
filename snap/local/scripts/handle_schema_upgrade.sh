#!/bin/bash

# A simple wrapper to check for migrations before
# actively executing them
# TODO: have validation logic for the migrations & check db is actually ready

if [ -z "$1" ] ; then
    echo "Please provide a Postgresql URI and try again."
else
    $SNAP/bin/schema-upgrade upgrade $SNAP/bin/migrations --db $1
fi
