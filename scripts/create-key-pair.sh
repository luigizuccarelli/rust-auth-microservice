#!/bin/bash
#
set -exv 

ROOTCA=newRootCA
CERTS_DIR=./certs
HOSTNAME=$1
IPADDR=$2

rm -rf ${CERTS_DIR}
mkdir ${CERTS_DIR}

tee ${CERTS_DIR}/openssl.conf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${HOSTNAME}
IP.1 = ${IPADDR}
EOF

openssl genrsa -out ${CERTS_DIR}/${ROOTCA}.key 2048

openssl req -x509 -new -nodes -key ${CERTS_DIR}/${ROOTCA}.key -sha256 -days 1024 -out ${CERTS_DIR}/${ROOTCA}.pem -subj "/C=IT/ST=ANCONA/L=ANCONA/O=QUAY/OU=IT Dev/CN=${HOSTNAME}"

openssl genrsa -out ${CERTS_DIR}/ssl.key 2048

openssl req -new -key ${CERTS_DIR}/ssl.key -out ${CERTS_DIR}/ssl.csr -subj "/C=IT/ST=ANCONA/L=ANCONA/O=QUAY/OU=IT Dev/CN=${HOSTNAME}"

openssl x509 -req -in certs/ssl.csr -CA ${CERTS_DIR}/${ROOTCA}.pem -CAkey ${CERTS_DIR}/${ROOTCA}.key -CAcreateserial -out ${CERTS_DIR}/ssl.cert -days 356 -extensions v3_req -extfile ${CERTS_DIR}/openssl.conf -passin pass:""

sudo cp ${CERTS_DIR}/${ROOTCA}.pem /etc/pki/ca-trust/source/anchors/${ROOTCA}.pem

sudo update-ca-trust extract

# for the error handling this format is important
echo -e "exit => $?"
