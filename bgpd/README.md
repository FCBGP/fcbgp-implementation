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

# You'd best to use version 1.1.1, or 3.x would pull out a deprecated warnning.
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

$ sudo apt install iptables
$ iptables --version
iptables v1.8.7 (nf_tables)
```

## for libs

```bash
# libdiag
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# SETUP

fcserver:
- You need to modify the `-a <ASN>` in Makefile and `assets/asnlist.json`.
- `make setup` is needed after modification.

# compile

```bash
$ cd /path/to/frr/bgpd/fcserver
$ make setup
$ make
```

# TODO

- [ ] store prefix with `network` should also consider `no network` to remove storage.
- [ ] IPv6 features.
- [ ] When BGPD receives a BGP-UPDATE, it would send out this BGP-UPDATE to the origin. E.g., AS A-B-C, A would send prefix a to AS B. Then AS B would send prefix a to AS A and AS C with B added to AS-PATH. AS A would never send out this BGP-UPDATE, otherwise it would be a loop. It is not clear that this is uniquely in FRR or a feature of BGP. It can't solve with changing the FRR version. There is no such thing in QUAGGA. Currently, there is a radiculous FC: (previouse-asn=A, current-asn=B, nexthop-asn=A). There may be no relavent CMD to disable this.
- [ ] Destination prefix in BGP-UPDATE is not using `MP_REACH_NLRI` to encapsulate. So there can only be one prefix each time. It means you could add with `network x.x.x.x/plen` manually. But as ipv4 uses `NLRI` which we don't want to use again, we would never change code here.
- [ ] It uses the same public key for all. SKI is reserved.

# CHANGELOG

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
