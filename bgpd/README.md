# TODO

- [ ] IPv6功能待修改。
- [ ] BGPD收到BGP-UPDATE之后，会再将本机收到的原路UPDATE返回，即自治域A-B-C，A将前缀a发送给B，B则同时将前缀a发送给A和C，A收到B发来的a不会再发了（否则成环）。这是FRR这个特有的，还是BGP的特性不清楚，换FRR版本无法解决这个问题，QUAGGA的代码当时是没有的。于是目前就出现了一个奇怪的FC：（previous-asn=A，current-asn=B，nexthop-asn=A）。昨天和涛哥找BGP的配置命令，没有发现相关命令。
- [ ] UPDATE中的目的前缀，由于没有使用MP_REACH_NLRI封装，而是使用的NLRI封装，所以暂时只能添加一个前缀（多了也可以，只是只处理第一个）。由于应该需要使用MP_REACH_NLRI封装（IPv6就需要使用MP_REACH_NLRI封装），所以这一块不打算继续修改NLRI的代码。
- [ ] AS自己的源前缀没找到，于是都是临时从本地json文件读取的。所以需要启动前就规划好前缀（only 1）。
- [ ] 公钥都是使用的一套，没有传递公钥。预留了SKI。

# CHANGELOG

## 2023.10.18

- [x] BGP层面，BGP-UPDATE正常发送并携带FC。（没有采用OPEN报文去协商CAPABILITY，相关代码是有写的，但是写完发现貌似无需CAPABILITY协商。。）
- [x] FCServer层面，接受从BGPD发来的本机生成的FC，并广播给ONPATH节点，同时接受其它FCServer发来的广播FC，验证并存储到本地SQLite数据库。
- [x] IPv4基本功能已经完成。

## 2023.10.11

- [x] FCServer is ready
- [x] `bgp_attr_fc`

# requirements

```bash
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# 但是最好还是1.1.1版本的，3.x的会报错
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
```

```bash
# libdiag
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# SETUP

fcserver 需要修改Makefile中的-a <ASN>，需要修改`asnlist.json`。

# compile

```bash
$ cd /path/to/frr/bgpd/fcserver
$ make setup
$ make
```
