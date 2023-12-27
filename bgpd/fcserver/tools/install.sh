#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2023-11-23 08:01:37
# File Name:   install_keys.sh
# Version:     1.0.0
# Description:

if [ 0 -eq $# ]
then
    echo "USAGE: $0 <INSTALL-LOCATION>"
else
    mv *.key *.csr *.cert $1
fi
