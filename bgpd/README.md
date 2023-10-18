# TODO

- [ ] IPv6���ܴ��޸ġ�
- [ ] BGPD�յ�BGP-UPDATE֮�󣬻��ٽ������յ���ԭ·UPDATE���أ���������A-B-C��A��ǰ׺a���͸�B��B��ͬʱ��ǰ׺a���͸�A��C��A�յ�B������a�����ٷ��ˣ�����ɻ���������FRR������еģ�����BGP�����Բ��������FRR�汾�޷����������⣬QUAGGA�Ĵ��뵱ʱ��û�еġ�����Ŀǰ�ͳ�����һ����ֵ�FC����previous-asn=A��current-asn=B��nexthop-asn=A����������θ���BGP���������û�з���������
- [ ] UPDATE�е�Ŀ��ǰ׺������û��ʹ��MP_REACH_NLRI��װ������ʹ�õ�NLRI��װ��������ʱֻ�����һ��ǰ׺������Ҳ���ԣ�ֻ��ֻ�����һ����������Ӧ����Ҫʹ��MP_REACH_NLRI��װ��IPv6����Ҫʹ��MP_REACH_NLRI��װ����������һ�鲻��������޸�NLRI�Ĵ��롣
- [ ] AS�Լ���Դǰ׺û�ҵ������Ƕ�����ʱ�ӱ���json�ļ���ȡ�ġ�������Ҫ����ǰ�͹滮��ǰ׺��only 1����
- [ ] ��Կ����ʹ�õ�һ�ף�û�д��ݹ�Կ��Ԥ����SKI��

# CHANGELOG

## 2023.10.18

- [x] BGP���棬BGP-UPDATE�������Ͳ�Я��FC����û�в���OPEN����ȥЭ��CAPABILITY����ش�������д�ģ�����д�귢��ò������CAPABILITYЭ�̡�����
- [x] FCServer���棬���ܴ�BGPD�����ı������ɵ�FC�����㲥��ONPATH�ڵ㣬ͬʱ��������FCServer�����Ĺ㲥FC����֤���洢������SQLite���ݿ⡣
- [x] IPv4���������Ѿ���ɡ�

## 2023.10.11

- [x] FCServer is ready
- [x] `bgp_attr_fc`

# requirements

```bash
$ sudo apt install sqlite3 libsqlite3-dev libjson-c-dev
$ sqlite3 -version
3.37.2 2022-01-06 13:25:41 872ba256cbf61d9290b571c0e6d82a20c224ca3ad82971edc46b29818d5dalt1

# ������û���1.1.1�汾�ģ�3.x�Ļᱨ��
$ openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
```

```bash
# libdiag
$ sudo mkdir /opt/log
$ sudo chmod 777 /opt/log
```

# SETUP

fcserver ��Ҫ�޸�Makefile�е�-a <ASN>����Ҫ�޸�`asnlist.json`��

# compile

```bash
$ cd /path/to/frr/bgpd/fcserver
$ make setup
$ make
```
