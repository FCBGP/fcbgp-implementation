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

It also can run on Ubuntu 20.04 and CentOS 8.
Other OSes need to be tested.

## 3rd-party libraries

```bash
# Basic dependencies
$ sudo apt install -y make cmake build-essential

# For storing Binding Messages
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# v3.x would pull out a deprecated warnning but the codes use v3.x features.
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

# For linux ACL rules
$ sudo apt install iptables nftables
$ iptables --version
iptables v1.8.7 (nf_tables)

# For netconf
# [CESNET/libnetconf2](https://github.com/CESNET/libnetconf2)
# This version v3.0.17 depends libyang v2.2.8, libssh-dev, openssl3.x
$ sudo apt install -y libssh-dev libpcre2-dev  libcurl4-gnutls-dev
$ git clone https://github.com/CESNET/libyang.git
$ git checkout v2.2.8
$ mkdir build; cd build; cmake ..; make ; sudo make install
$ git clone https://github.com/CESNET/libnetconf2.git
$ git checkout v3.0.17
$ mkdir build; cd build; cmake ..; make ; sudo make install

# For python & ncclient
# This will be used in generating netconf configurations and sending them to routers.
# If your machine does't installed python3.10 but with another python version,
# don't worry! Only if you have python3.6+, you can use this python.
$ sudo apt install python3.10 python3.10-dev python3-pip
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
- `listen_port`: Optional. The listen port of FCServer. Default is `23160` if it is using wrong port or not set.
- `fc_fcs_addr_type`: Optional. The default addr type is `ipv4`. `ipv6` is also supported.
- `hash_algorithm`: Specify HASH algorithm, including `SHA256`, `SHA1`, `MD5`, `CRC32`. Default is `SHA256`.
- `log_mode`: For diaglib in fcserver. `debug`, `info`. Default is `info`.
- `clear_fc_db`: `true` or `false`. Default is `true`. Clear the fc.db before running.
- `fc_db_fname`: Specify the absolute path of fc.db. Default is `/etc/frr/assets/fc.db`.
- `use_data_plane`: See Section Data Plane for more information. Default is `none`.
- `router_info_list`: All the BGP routers of current AS. used when `use-data-plane` is `h3c`.
  - `bgpid`: BGP-ID.
  - `host`: ipv4/ipv6 address of an BGP router
  - `port`: netconf-over-ssh port.
  - `username`: String, username.
  - `password`: String, password.
  - `acl_group_start_index`: This will be incrementing from the start index. It is for h3c ACL group. The range of h3c ACL group is [1, 3999].
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

- In `frr.conf`, every neighbor should be in separate peer-groups for sending different BGP Updates.

FCServer:

- You need to modify the `local_asn` and other configurations in `assets/config.json`.
- `make setup` is needed after modification or just modified the file `/etc/frr/asssets/config.json` directly.

# compile

## FRR

We use FRR 9.0.1. Refer to the official documents to build it first.

## FCServer

```bash
$ cd {/path/to/fcbgp-projects}/fcserver

# Sets the assets (only need execute once if you don't change files in assets)
$ make setup

# Run server program
$ make

# After all fcserver started, run
$ sudo systemctl start/stop/restart/ frr
```

We have switched the build system to `CMake`, but you can still use `make` to simplify the commands for building and running `fcserver`.

If your OpenSSL library or other dependencies are installed in a non-standard location (i.e., a user-defined path), you may need to specify the path for CMake using the following command:

```sh
cmake -DCMAKE_PREFIX_PATH=/path/to/your/library ..
```

In this case, you cannot use `make` directly, but you can still run `make setup` to set the assets.

# Data Plane

## Intro

We will try to distinguish different data planes with different values.

- `none`: Default. Don't generate data plane rules. In this case, only the control plane of FC-BGP in effect.
- `linux`: nftable/iptables
- `vpp`: FD.io VPP
- `h3c`: For H3C, netconf

After discussing with design teams, we have achieved that:

1. if one node deploys fcbgp,
   1. for onpath node, traffic should be permitted only on the FC path;
   2. for offpath node, traffic should be denied globally.

This is all for the undeployed area.

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

## h3c-netconf

[deprecated: h3c-netconf-test.cn.md](./test/netconf-test/README.md)

[h3c-netconf-deny-traffic-globaly-and-permit-one.cn.md](./docs/h3c-netconf-deny-traffic-globaly-and-permit-one.cn.md)

In H3C router, ACLs are managed by ACL group, one ACL group has at most 65534(1-65534, ruleID 65535 represents ruleID generated by router.) ACL group should be applied in an interface.

### Reference

1. [Simple rule management - nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management)
2. [linux - nftables rule: No such file or directory error - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/537912/nftables-rule-no-such-file-or-directory-error)
3. [nftables 配置与使用记录 - StarryVoid - Blog](https://blog.starryvoid.com/archives/1045.html)
