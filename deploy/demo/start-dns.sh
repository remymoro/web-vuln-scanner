#!/bin/sh
set -eu
# Le volume /zones garde les TXT écrits par les scripts : ne copier que les zones absentes.
for zone in scanner.test juiceshop.lab; do
    if [ ! -s "/zones/$zone.zone" ]; then
        cp "/etc/coredns/$zone.zone" "/zones/$zone.zone"
    fi
done
exec coredns "$@"
