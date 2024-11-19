# h3c.acl

> **Author** Basil Guo
>
> **Date** Sep. 04, 2024
>
> **Description**

[TOC]

> deprecated: 以下内容有问题，分析和 FC-BGP 数据面的设计有偏差。请查看新的分析文档[h3c-netconf-deny-traffic-globaly-and-permit-one.cn.md](./h3c-netconf-deny-traffic-globaly-and-permit-one.cn.md)。

简单分析下以下 topo 应该有的 ACL。先考虑静态网络。

## topo

```txt
topo: 10 - 20 - 30
```

## prefix

- 10: 10.0.0.0/24
- 20: 20.0.0.0/24
- 30: 30.0.0.0/24

## acl

### AS 30

| BGP UPDATE AS_PATH | action | src | dst | direction |
| ------------------ | ------ | --- | --- | --------- |
| 10 => 20           | deny   | 20  | 10  | in out    |
| 10 => 20 => 30     | deny   | 30  | 10  | in        |
| 20 => 30           | deny   | 30  | 20  | in        |
| 20 => 10           | deny   | 10  | 20  | in out    |
| 30 => 20           | deny   | 20  | 30  | out       |
| 30 => 20 => 10     | deny   | 10  | 30  | out       |

### AS 20

| BGP UPDATE AS_PATH | action | src | dst | direction                            |
| ------------------ | ------ | --- | --- | ------------------------------------ |
| 10 => 20           | deny   | 20  | 10  | in                                   |
| 10 => 20 => 30     | deny   | 30  | 10  | <span style="color: red">none</span> |
| 20 => 30           | deny   | 30  | 20  | out                                  |
| 20 => 10           | deny   | 10  | 20  | out                                  |
| 30 => 20           | deny   | 20  | 30  | in                                   |
| 30 => 20 => 10     | deny   | 10  | 30  | <span style="color: red">none</span> |

### AS 10

| BGP UPDATE AS_PATH | action | src | dst | direction |
| ------------------ | ------ | --- | --- | --------- |
| 10 => 20           | deny   | 20  | 10  | out       |
| 10 => 20 => 30     | deny   | 30  | 10  | out       |
| 20 => 30           | deny   | 30  | 20  | in out    |
| 20 => 10           | deny   | 10  | 20  | in        |
| 30 => 20           | deny   | 20  | 30  | in out    |
| 30 => 20 => 10     | deny   | 10  | 30  | in        |
