#!/bin/bash

if  [ "$#" -ne 1 ]; then
	echo "Usage: $0 <IP Address>"
	exit 1
fi

export PYRO_HOST=$1

python3 controller_daemon.py
