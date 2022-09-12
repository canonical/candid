#!/bin/bash 

if [ -z "$1" ] ; then
    echo "Please provide a Postgresql URI and try again."
else
    $SNAP/bin/schema-upgrade get-version --db $1
fi