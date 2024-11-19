#!/usr/bin/env bash
# Author:      basilguo@163.com
# Date:        2023-09-19 07:01:59
# File Name:   run.sh
# Version:     1.0.0
# Description:

set -eux

function build()
{
    cd /usr/local/src/fcbgp-new/
    make && sudo make install
}

function run()
{
    cd /usr/local/src/fcbgp-new/bgpd
    build
    sudo .libs/bgpd -f /etc/frr/bgpd.conf --log stdout
}

function pull()
{
    cd /usr/local/src/fcbgp-new/bgpd
    if [ 0 -eq  $(ip a | grep 192.168.88.131 | wc -l) ]
    then
        scp -r basil@192.168.88.131:/usr/local/src/fcbgp-new/bgpd/* .
    fi
    build
}

function connect_vtysh()
{
    cd /usr/local/src/fcbgp-new/vtysh
    sudo .libs/vtysh
}

function help()
{
    echo "-h, --help        show this message"
    echo "-r, --run         run the bgpd"
    echo "-b, --build       build the code with make"
    echo "-p, --pull        pull code from 115"
    echo "-c, --connect     connect to vtysh"
}

function main()
{
    echo $*
    if [ -z $# ]
    then
        help
        exit
    fi
    while getopts "hrbpc" arg
    do
        case $arg in
            c)
                connect_vtysh
                ;;
            h)
                help
                exit 0
                ;;
            r)
                run
                ;;
            b)
                build
                ;;
            p)
                pull
                ;;
            *)
                help
                ;;
        esac
    done
}

main $*

