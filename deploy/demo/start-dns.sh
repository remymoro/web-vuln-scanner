#!/bin/sh
set -eu
if [ ! -s /zones/scanner.test.zone ]; then
    cp /etc/coredns/scanner.test.zone /zones/scanner.test.zone
fi
exec coredns "$@"
