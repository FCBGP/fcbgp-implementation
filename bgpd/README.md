# SETUP

```bash
$ sudo cp assets/* /etc/frr/
```

# requirements

除了FRR需要的，还需要

```bash
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# 但是最好还是1.1.1版本的，3.x的会报错
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

```

```bash
# 没有使用，可以不安装
$ git clone https://github.com/Water-Melon/Melon.git
$ ./configure
$ make
$ sudo make install

# conf
$ sudo vim /etc/ld.so.conf.d/melon.conf
# 写入 /usr/local/melon/include
$ sudo ldconfig
```

```bash
# libdiag
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# compile

fcserver 需要修改Makefile中的-a <ASN>

```bash
$ cd /path/to/frr/bgpd/fcserver
$ sudo make setup
$ make
```

# CHANGELOG

## 2023.10.11

- [x] FCServer is ready
- [ ] `bgp_attr_fc`
