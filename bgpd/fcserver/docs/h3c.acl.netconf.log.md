# h3c.acl.netconf.log

> **Author** Basil Guo
>
> **Date** Sep. 03, 2024
>
> **Description**

[TOC]

> this document is deprecated: [please refer this doc.](./h3c-netconf-deny-traffic-globaly-and-permit-one.cn.md)

Here we show a complete H3C ACL Netconf configuration.
It contains 3 configurations, i.e., one for ruleset, one for rule, one for interface who enables this ruleset than includes the rule.
The mask of IPv4 should be reversed. IPv6 still remains.
`255.255.255.0` should be `0.0.0.255`.

[logs.acl.log](../logs/log.acl.log)

```xml
************************* CMD *************************

    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL>
          <NamedGroups>
            <Group>
              <GroupType>2</GroupType>
              <GroupCategory>2</GroupCategory>
              <GroupIndex>3938</GroupIndex>
            </Group>
          </NamedGroups>
        </ACL>
      </top>
    </config>

************************* RET *************************
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:57014ac3-f1a0-4351-9e3e-79808134c2a8"><ok/></rpc-reply>
************************* END *************************
************************* CMD *************************

    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="merge">
          <IPv6NamedAdvanceRules>
            <Rule>
              <GroupIndex>3938</GroupIndex>
              <RuleID>65535</RuleID>
              <Action>1</Action>
              <ProtocolType>256</ProtocolType>
              <SrcAny>0</SrcAny>
              <SrcIPv6>
                <SrcIPv6Addr>20:20::</SrcIPv6Addr>
                <SrcIPv6Prefix>64</SrcIPv6Prefix>
              </SrcIPv6>
              <DstAny>0</DstAny>
              <DstIPv6>
                <DstIPv6Addr>10:10::</DstIPv6Addr>
                <DstIPv6Prefix>64</DstIPv6Prefix>
              </DstIPv6>
            </Rule>
          </IPv6NamedAdvanceRules>
        </ACL>
      </top>
    </config>

************************* RET *************************
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:16940fe1-7d8c-4a09-bed4-7c81b94c7d53"><ok/></rpc-reply>
************************* END *************************
************************* CMD *************************

    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="merge">
          <PfilterApply>
            <Pfilter>
               <AppObjType>1</AppObjType>
               <AppObjIndex>268435460</AppObjIndex>
               <AppDirection>2</AppDirection>
               <AppAclType>2</AppAclType>
               <AppAclGroup>3938</AppAclGroup>
            </Pfilter>
          </PfilterApply>
        </ACL>
      </top>
    </config>


************************* RET *************************
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="urn:uuid:e6f88ffc-a60d-4487-9e73-cb0ff978e150"><ok/></rpc-reply>
************************* END *************************
```
