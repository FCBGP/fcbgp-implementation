#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2023-10-20 09:12:46
# File Name:   gen_eckey.sh
# Version:     1.0.0
# Description: This is only for test use.
#   https://github.com/openssl/openssl/blob/master/doc/HOWTO/keys.txt
#   https://github.com/usnistgov/NIST-BGP-SRx/blob/master/srx-crypto-api/tools/qsrx-make-cert
# USAGE:    ./gen_eckey.sh 10 20 30

set -exu

function gen_eckey()
{
    # 1. params
    # openssl ecparam -name prime256v1 -out prime256v1.pem

    # 2. private key
    # openssl genpkey -paramfile prime256v1.pem -out $1.pem

    # combine step 1 & 2
    openssl ecparam -name prime256v1 -genkey -out $1.pem

    # 3. extract pubkey
    # openssl pkey -in $1.pem -pubout -out $1.pub

    # 4. gen cert
    openssl req -new -x509 -key $1.pem -out $1.cert -days 1095

    # 5. show cert
    # openssl x509 -in $1.cert -noout -text
}

echo "@ $@"
echo "# $#"
echo "# $*"

for as in $*
do
    gen_eckey $as
done

