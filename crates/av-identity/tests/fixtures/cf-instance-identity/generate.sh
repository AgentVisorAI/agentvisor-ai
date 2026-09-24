#!/bin/sh
# Regenerate the Cloud Foundry instance-identity test fixtures.
#
# The leaf certificates mimic what Diego issues to an app instance: an RSA
# key in PKCS#1 form, CN = the instance GUID, and OU values
# `organization:<guid>`, `space:<guid>`, `app:<guid>`, with the clientAuth
# extended key usage. They are signed by an intermediate CA under a root CA,
# like the instance-identity CA chain. These keys are TEST-ONLY.
#
# Requires OpenSSL 3.4 or newer (for -not_before / -not_after).
set -eu
OPENSSL=${OPENSSL:-openssl}
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/ca.ext" <<'EXT'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
cat >"$tmp/intermediate.ext" <<'EXT'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
cat >"$tmp/leaf.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=DNS:0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3,IP:10.255.0.7
authorityKeyIdentifier=keyid
EXT

"$OPENSSL" genrsa -traditional -out "$tmp/root.key" 2048
"$OPENSSL" req -new -x509 -key "$tmp/root.key" -subj "/CN=Test Instance Identity Root CA" \
  -not_before 20240101000000Z -not_after 21240101000000Z -extensions v3_ca -out root.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

"$OPENSSL" genrsa -traditional -out "$tmp/intermediate.key" 2048
"$OPENSSL" req -new -key "$tmp/intermediate.key" -subj "/CN=Test Instance Identity Intermediate CA" \
  -out "$tmp/intermediate.csr"
"$OPENSSL" x509 -req -in "$tmp/intermediate.csr" -CA root.pem -CAkey "$tmp/root.key" -set_serial 2 \
  -not_before 20240101000000Z -not_after 21240101000000Z -extfile "$tmp/intermediate.ext" -out intermediate.pem

leaf() {
  name=$1 not_before=$2 not_after=$3 ca_cert=$4 ca_key=$5 serial=$6
  "$OPENSSL" genrsa -traditional -out "$name.key" 2048
  "$OPENSSL" req -new -key "$name.key" \
    -subj "/OU=organization:5a0b9c1d-2e3f-4051-9263-748596a7b8c9/OU=space:6b1c0d2e-3f40-4152-a364-8596a7b8c9d0/OU=app:7c2d1e3f-4051-4263-b475-96a7b8c9d0e1/CN=0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3" \
    -out "$tmp/$name.csr"
  "$OPENSSL" x509 -req -in "$tmp/$name.csr" -CA "$ca_cert" -CAkey "$ca_key" -set_serial "$serial" \
    -not_before "$not_before" -not_after "$not_after" -extfile "$tmp/leaf.ext" -out "$name.pem"
}
leaf instance 20240101000000Z 21240101000000Z intermediate.pem "$tmp/intermediate.key" 10
leaf expired 20240101000000Z 20240102000000Z intermediate.pem "$tmp/intermediate.key" 11

# A chain of the same shape under an unrelated root, which must be refused.
"$OPENSSL" genrsa -traditional -out "$tmp/rogue.key" 2048
"$OPENSSL" req -new -x509 -key "$tmp/rogue.key" -subj "/CN=Rogue Root CA" \
  -not_before 20240101000000Z -not_after 21240101000000Z -out "$tmp/rogue.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
leaf rogue 20240101000000Z 21240101000000Z "$tmp/rogue.pem" "$tmp/rogue.key" 12
