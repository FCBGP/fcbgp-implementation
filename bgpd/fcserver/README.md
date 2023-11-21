# requirements

## Ubuntu OS

```bash
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.5 LTS
Release:        20.04
Codename:       focal
```

## 3rd-party libraries

```bash
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# v3.x would pull out a deprecated warnning but it uses v3.x features.
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

$ sudo apt install iptables
$ iptables --version
iptables v1.8.7 (nf_tables)

$ sudo apt install nftables
```

## for libs

```bash
# libdiag
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# SETUP

bgpd:
- In `frr.conf`, every neighbor should be in separate groups.

fcserver:
- You need to modify the `-a <ASN>` in Makefile and `assets/asnlist.json`.
- `make setup` is needed after modification.

## asnlist.json

- ifname: local port, the NIC links to the neighbor.

# compile

```bash
$ cd /path/to/frr/bgpd/fcserver
$ make setup
$ make
```

# nftable rules management

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

1. [Simple rule management - nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management)
2. [linux - nftables rule: No such file or directory error - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/537912/nftables-rule-no-such-file-or-directory-error)
3. [nftables 配置与使用记录 - StarryVoid - Blog](https://blog.starryvoid.com/archives/1045.html)

# TODO

- [ ] store prefix with `network` should also consider `no network` to remove storage.
- [ ] IPv6 features.
- [ ] Destination prefix in BGP-UPDATE is not using `MP_REACH_NLRI` to encapsulate. So there can only be one prefix each time. It means you could add with `network x.x.x.x/plen` manually. But as ipv4 uses `NLRI` which we don't want to use again, we would never change code here.
- [ ] It uses the same public key for all. SKI is reserved.

# CHANGELOG

## 2023.11.21

- [x] nft add rules.

## 2023.11.17

- [x] use peer-group to correct the FCList.
- [x] remove part of unused codes.
- [x] THIS IS NOT SOLVED BUT WOULD NEVER AFFECT THE TEST. When BGPD receives a BGP-UPDATE, it would send out this BGP-UPDATE to the origin. E.g., AS A-B-C, A would send prefix a to AS B. Then AS B would send prefix a to AS A and AS C with B added to AS-PATH. AS A would never send out this BGP-UPDATE, otherwise it would be a loop. It is not clear that this is uniquely in FRR or a feature of BGP. It can't solve with changing the FRR version. There is no such thing in QUAGGA. Currently, there is a radiculous FC: (previouse-asn=A, current-asn=B, nexthop-asn=A). There may be no relavent CMD to disable this.

## 2023.11.13

- [x] offpath nodes would only need to drop all traffic from any ports.
- [x] FC 3 ASNs.

## 2023.11.5

- [x] Linux ACL.
- [x] Maybe send to fcs when receiving an BGP-UPDATE

## 2023.10.18

- [x] BGPD: BGP-UPDATE is sent out normally with FC attribute. There is no need to negotiate the FC CAPABILITY as FC don't need peers to support FC process.
- [x] FCServer: Learn FC from BGPd and other FCServers. Verify and store to local SQLite Database. It would broadcast to onpath nodes.
- [x] IPv4 features is ready.
- [x] Prefixes are in `(struct bgp*)bm->bgp.head.data).route`. But there is no flag to indicate it is added by `network`. So we just use `network`.

## 2023.10.11

- [x] FCServer is ready
- [x] `bgp_attr_fc`
