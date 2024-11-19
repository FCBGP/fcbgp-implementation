#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2023-11-23 07:47:48
# File Name:   genkey.sh
# Version:     1.0.2
# Description:
#   1. [How do I create an ECDSA certificate with the OpenSSL command-line - Stack Overflow](https://stackoverflow.com/questions/11992036/how-do-i-create-an-ecdsa-certificate-with-the-openssl-command-line)
#   2. [Generate ECDSA keys](https://techdocs.akamai.com/iot-token-access-control/docs/generate-ecdsa-keys)


function genkey()
{
    echo "*** GEN KEY for $1 ***"
    # gen EC private key
    openssl ecparam -genkey -name prime256v1 -out $1.key

    # CRS file, including pubkey and other certificate infomation
    # openssl req -new -key $1.key -out $1.csr

    # public key
    # openssl ec -in $1.key -pubout -out $1.pem

    # self-signed certificate
    openssl req -new -x509 -key $1.key -out $1.cert -days 3650
    echo
    echo
    echo
}

if [ 0 -eq $# ]
then
    echo "USAGE: $0 <ASN list>, e.g., 10 20 30 40 50"
    exit -1
else
    for as in $@
    do
        genkey ${as}
    done
fi

