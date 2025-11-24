#!/bin/sh
# auto restarter

while [ 1 ] ; do
    ./phoneproxy $@
    if [ $1 == "-h" ]; then
        exit
    fi
	sleep 1
done





