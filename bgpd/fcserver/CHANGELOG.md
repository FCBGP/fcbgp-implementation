# CHANGELOG

## 2024.10.30

- [x] publish: v0.2.7
- [x] fix: fcs addr type ipv6

## 2024.10.11

- [x] publish: v0.2.6
- [x] refactor: remove all extra `libs` using `lib` instead and delete senderd in frr/bgpd
- [x] fix: comparability and SKI obtaining for CentOS, and fclist withdrawn from ht
- [x] add: `fcs_addr_type` for fcserver configuration

## 2024.09.14

- [x] publish: v0.2.5
- [x] fix: h3c acl.
- [x] permit traffic through all on-path node. deny traffic across all off-path node.
- [x] frontend used linenoise.

## 2024.09.04

- [x] publish: v0.2.4
- [x] fix: h3c acl.
- [x] add: an router configuration named as `acl_group_start_index` and keep it incrementing. Default is 3900. H3C says its ACL index is in [1, 3999].
- [x] add: ut libs.

## 2024.09.02

- [x] v0.2.3
- [x] fix h3c netconf delivery.

## 2024.08.30

- [x] v0.2.2
- [x] clear compile warnings.

## 2024.08.30

- [x] v0.2.1
- [x] update key tools. It can gen ec public key and query the ski and public key from \*.cert
- [x] refactor the bm msg process. Divide the big function into small functions according to bm msg analysis.
- [x] fix EC Key bug. The hardcoded the EC Key has been removed. Now it uses the right EC Key for signing and verifying.

## 2024.08.02

- [x] v0.2.0
- [x] `fc_db_fname` in config.json
- [x] incrementing src prefix size in FCserver.
- [x] changing FC BM msg format.

## 2024.08.02

- [x] v0.1.7
- [x] incrementing bgpd max src prefix size.

## 2024.07.22

- [x] v0.1.6
- [x] FCServer listen TCP port 23160 => 23162
- [x] self-defined listen port
- [x] supported SHA1\MD5\CRC32 hash algorithms.

## 2024.05.23

- [x] v0.1.5
- [x] basically test fcserver version for h3c
- [x] TCP fds & config.json with aer configuration

## 2023.12.29

- [x] v0.1.4
- [x] It uses the same public key for all. SKI is reserved.
- [ ] THIS WILL NOT BE IMPLEMENTED. <s>Destination prefix in BGP-UPDATE is not using `MP_REACH_NLRI` to encapsulate. So there can only be one prefix each time. It means you could add with `network x.x.x.x/plen` manually. But as ipv4 uses `NLRI` which we don't want to use again, we would never change code here.</s>

## 2023.12.25

- [x] v0.1.3
- [x] IPv6 features. Not gracefully. `v4->v6` will use `::ffff:x.x.x.x`.

## 2023.12.19

- [x] v0.1.2.
- [x] refactore fcserver & remove asn specified in Makefile. Make the json file as the config file.

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
