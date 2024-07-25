# CHANGELOG

## 2024.07.22

- [x] v0.1.6
- [x] FCServer listen TCP port 23160 => 23162
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
