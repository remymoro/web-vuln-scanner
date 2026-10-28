#!/bin/sh
set -eu
umask 077

if [ ! -s /authority/ca.crt ] || [ ! -s /authority/ca.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj '/CN=Scanner demo CA' -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout /authority/ca.key -out /authority/ca.crt
fi
if [ ! -s /tls/server.crt ] || [ ! -s /tls/server.key ] || \
    ! openssl verify -CAfile /authority/ca.crt /tls/server.crt >/dev/null 2>&1; then
    openssl req -new -newkey rsa:2048 -nodes -subj '/CN=demo.scanner.test' \
        -keyout /tls/server.key -out /tls/server.csr
    cat > /tls/server.ext <<'EOF'
subjectAltName=DNS:demo.scanner.test
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl x509 -req -in /tls/server.csr -CA /authority/ca.crt -CAkey /authority/ca.key \
        -CAcreateserial -days 365 -extfile /tls/server.ext -out /tls/server.crt
    rm /tls/server.csr /tls/server.ext
fi
cp /authority/ca.crt /trust/ca.crt
chmod 644 /tls/server.crt /trust/ca.crt
