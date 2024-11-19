# h3c-permit-netconf.cn

> **Author** Basil Guo
>
> **Date** Oct. 30, 2024
>
> **Description** > [TOC]

上次联调的时候发现：FC Server 收到绑定信息后，下发的 ACL 只禁用了反方向传输的流量
按照设计，流量应该是只能从指定的接口接收，其它接口接收到流量都需要 deny 掉
根据设计可以按照下面方式下发配置：

```sh
# 配置ACL，根据绑定信息指定需要过滤的流量
#
acl advanced 3900
rule 5 permit ip source 1.1.1.1 0 destination 2.2.2.2 0
#
# 配置QoS策略，匹配ACL指定流量，动作为deny
#
traffic classifier c1
if-match acl 3900#
#
traffic behavior b1
filter deny
#
qos policy p1
classifier c1 behavior b1
#
# 全局应用qos策略，定优先级为1，全局过滤ACL指定的流量
qos apply policy p1 global inbound preorder 1
# 接口下配置，指定的接口允许通过ACL指定的流量，其它接口接收到流量会按照全局策略被deny掉
packet filter 3900 inbound
```

命令行对应的 netconf 是：

```xml
//acl advanced 3900
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
                     <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                           <top xmlns="http://www.h3c.com/netconf/config:1.0">
                             <ACL>
                               <NamedGroups>
                                 <Group>
                                   <GroupType>1</GroupType>
                                   <GroupCategory>2</GroupCategory>
                                   <GroupIndex>3900</GroupIndex>
                                 </Group>
                               </NamedGroups>
                             </ACL>
                           </top>
                         </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>


//rule 5 permit ip source 1.1.1.1 0 destination 2.2.2.2 0
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
                     <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                     <top xmlns="http://www.h3c.com/netconf/config:1.0">
                        <ACL xc:operation="merge">
                          <IPv4NamedAdvanceRules>
                            <Rule>
                              <GroupIndex>3900</GroupIndex>
                              <RuleID>65535</RuleID>
                              <Action>2</Action>
                              <ProtocolType>256</ProtocolType>
                              <SrcAny>0</SrcAny>
                              <SrcIPv4>
                                   <SrcIPv4Addr>1.1.1.1</SrcIPv4Addr>
                                <SrcIPv4Wildcard>0.0.0.0</SrcIPv4Wildcard>
                              </SrcIPv4>
                              <DstAny>0</DstAny>
                              <DstIPv4>
                                <DstIPv4Addr>2.2.2.2</DstIPv4Addr>
                                <DstIPv4Wildcard>0.0.0.0</DstIPv4Wildcard>
                              </DstIPv4>
                            </Rule>
                          </IPv4NamedAdvanceRules>
                        </ACL>
                     </top>
                     </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//traffic classifier c1
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
                     <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                     <top xmlns="http://www.h3c.com/netconf/config:1.0">
                            <MQC>
                                <Classifiers>
                                  <Classifier>
                                    <Name>c1</Name>
                                    <Operator>1</Operator>
                                  </Classifier>
                                </Classifiers>
                            </MQC>
                     </top>
                     </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//if-match acl 3900
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                     <MQC>
                            <Rules>
                              <Rule>
                                <ClassName>c1</ClassName>
                                <RuleID>4294967295</RuleID>
                        <Not>false</Not>
                                <Acl>
                                  <IPv4Acl>3900</IPv4Acl>
                                </Acl>
                      </Rule>
                      </Rules>
                       </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//traffic behavior b1
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                    <MQC>
                       <Behaviors>
                       <Behavior>
                          <Name>b1</Name>
                        </Behavior>
                      </Behaviors>
                    </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//filter deny
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                     <MQC>
                           <Filter>
                           <Action>
                             <BehaviorName>b1</BehaviorName>
                             <Type>1</Type>
                           </Action>
                         </Filter>
                      </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//qos policy p1
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                     <MQC>
                           <Policies>
                               <Policy>
                                    <Name>p1</Name>
                                    <Type>0</Type>
                               </Policy>
                           </Policies>
                      </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//classifier c1 behavior b1
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                     <MQC>
                           <CBMaps>
                                <CBMap>
                                    <PolicyName>p1</PolicyName>
                                    <ClassifierName>c1</ClassifierName>
                                    <BehaviorName>b1</BehaviorName>
                                    <Mode>0</Mode>
                                 </CBMap>
                            </CBMaps>
                     </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//qos apply policy p1 global inbound preorder 1
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                    <MQC>
                          <GlobalCategoryPolicy>
                               <Application>
                                  <Direction>0</Direction>
                                  <PolicyType>0</PolicyType>
                                  <PolicyName>p1</PolicyName>
                                  <PreOrder>1</PreOrder>
                               </Application>
                           </GlobalCategoryPolicy>
                     </MQC>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
//packet-filter 3900 inbound
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:urn="urn:ietf:params:xml:ns:netconf:base:1.0">
   <env:Header>
      <auth:Authentication env:mustUnderstand="1" xmlns:auth="http://www.h3c.com/netconf/base:1.0">
         <auth:AuthInfo>1000014534b0e6077a94f20b0a3487d09d49</auth:AuthInfo>
         <auth:Language>zh-cn</auth:Language>
      </auth:Authentication>
   </env:Header>
   <env:Body>
      <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
         <edit-config>
            <target>
               <running/>
            </target>
            <config>
               <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
                  <!-- 重复创建,replace直接返回成功 -->
                     <ACL>
                       <PfilterApply>
                         <Pfilter>
                           <AppObjType>1</AppObjType>
                           <AppObjIndex>1</AppObjIndex>
                           <AppDirection>1</AppDirection>
                           <AppAclType>1</AppAclType>
                           <AppAclGroup>3900</AppAclGroup>
                         </Pfilter>
                       </PfilterApply>
                     </ACL>
               </top>
            </config>
         </edit-config>
      </rpc>
   </env:Body>
</env:Envelope>
```
