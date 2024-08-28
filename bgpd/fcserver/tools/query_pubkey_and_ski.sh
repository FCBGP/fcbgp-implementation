#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2024-08-27 06:40:03
# File Name:   query_pubkey_and_ski.sh
# Version:     0.0.1
# Description:

function query()
{
    openssl x509 -in $1.cert -noout -text
}

if [ 0 -eq $# ]
then
    echo "USAGE: $0 <ASN list>"
    exit -1
else
    for asn in $@
    do
        if [ -f ${asn}.cert ]
        then
            query ${asn}
        else
            echo "No such ${asn}.cert file in current directory"
        fi
    done
fi
