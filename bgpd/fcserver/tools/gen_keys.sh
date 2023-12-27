#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2023-11-23 07:47:48
# File Name:   genkey.sh
# Version:     1.0.0
# Description:


function genkey()
{
    echo "*** GEN KEY for $1 ***"
    # gen EC private key
    openssl ecparam -genkey -name prime256v1 -out $1.key

    # CRS file, including pubkey and other certificate infomation
    # openssl req -new -key $1.key -out $1.csr

    # self-signed certificate
    openssl req -new -x509 -key $1.key -out $1.cert -days 365
    echo
    echo
    echo
}

if [ 0 -eq $# ]
then
    echo "USAGE: $0 <ASN list>"
    exit -1
else
    for as in $@
    do
        genkey ${as}
    done
fi

