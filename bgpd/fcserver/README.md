# Requirements

## Ubuntu OS

```bash
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
```

## 3rd-party libraries

```bash
# for store Binding Messages
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# v3.x would pull out a deprecated warnning but the codes use v3.x features.
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

# for linux ACL rules
$ sudo apt install iptables nftables
$ iptables --version
iptables v1.8.7 (nf_tables)

# for netconf
# [CESNET/libnetconf2](https://github.com/CESNET/libnetconf2)
$ git clone https://github.com/CESNET/libnetconf2.git
$ mkdir build; cd build; cmake ..; make ; sudo make install

# for python & ncclient
$ sudo apt install python3.10 python3.10-dev
$ pip3 install ncclient
```

## for libs

```bash
# libdiag: log files
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# Setup

## config.json

- `local_asn`: The AS number of current bgp located.
- `log_mode`: For diaglib in fcserver. `debug`, `info`
- `clear_fc_db`: `true` or `false`. Default is `true`. Clear the fc.db before running.
- `use_data_plane`: See Section Data Plane for more information.
- `router_info_list`: All the BGP routers of current AS. used when `use-data-plane` is `h3c`
    - `bgpid`: BGP-ID.
    - `host`: ipv4/ipv6 address of an BGP router
    - `port`: netconf-over-ssh port.
    - `username`: String, username.
    - `password`: String, password.
- `as_info_list`: All the ASN in test.
    - `asn`:
    - `nics`: All the network interface card of current machine. only used when using linux to apply acl rules.
    - `acs`: AS Control Server.
        - `ipv4`: ipv4 address.
            - `ifaddr`: ipv4 address
            - `ifname`: Local port, the NIC links to the neighbor. Or where this is configed.
        - `ipv6`: ipv6 address.
            - `ifname`: Local port, the NIC links to the neighbor. Or where this is configed.

## program

BGPd:
- In `frr.conf`, every neighbor should be in separate groups.

FCServer:
- You need to modify the `local_asn` in `assets/config.json`.
- `make setup` is needed after modification.

# compile

## FCServer

```bash
$ cd {/path/to/frr}/bgpd/fcserver

# Sets the assets (only need execute once if you don't change files in assets)
$ make setup

# Run server program
$ make

# After all fcserver started, run
$ sudo systemctl start/stop/restart/ frr
```

# Data Plane

## Intro

> We will try to distinguish different data planes with different values.
> - `none`: Default. Don't generate data plane rules.
> - `linux`: nftable/iptables
> - `vpp`: FD.io VPP
> - `h3c`: For H3C, netconf

## Linux

### nftable rules management

```bash
# use the default nft tabel inet filter
$ sudo systemctl restart nftables.service

# List all tables or chains
$ nft list ruleset
$ nft list table filter

# Create an table & chain
# If you don't like to create a new table, use the default one: inet filter.
$ nft add table ip filter # create table
$ nft add chain ip filter INPUT { type filter hook input priority 0 \; } # create chain
$ nft add chain ip filter OUTPUT { type filter hook output priority 0 \; } # create chain

# Add a rule
# Please note that the matches: INPUT & iif and OUTPUT & oif.
$ nft add rule inet filter INPUT iifname e0 ip saddr 20.0.0.0/24 ip daddr 10.0.0.0/24 drop
$ nft add rule inet filter OUTPUT oifname e0 ip saddr 10.0.0.0/24 ip daddr 20.0.0.0/24 drop

# Remove one rule
$ nft -a list table filter
$ nft delete rule filter output handle 5

# Remove all rules
$ nft flush chain filter INPUT
$ nft flush table filter
```


### Reference

1. [Simple rule management - nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management)
2. [linux - nftables rule: No such file or directory error - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/537912/nftables-rule-no-such-file-or-directory-error)
3. [nftables 配置与使用记录 - StarryVoid - Blog](https://blog.starryvoid.com/archives/1045.html)

