#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2024-08-29 02:31:19
# File Name:   ecdsa_sign_verify.sh
# Version:     0.0.1
# Description:

fname=$0

function sign()
{
    openssl dgst -sha256 -sign $1.key -out signature.bin $fname
    echo "sign done"
}

function verify()
{
    openssl dgst -sha256 -verify $1.pem -signature signature.bin $fname
    echo "verify done"
}

if [ 0 -eq $# ] || [ 1 -eq $# ]; then
    echo "USAGE: $0 <sign | verify | both> ASN"
    exit -1
else
    if [ "sign" == $1 ]; then
        sign $2
    elif [ "verify" == $1 ]; then
        verify $2
    elif [ "both" == $1 ]; then
        sign $2
        echo
        verify $2
    fi
fi


