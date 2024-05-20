from ncclient import manager
import time
from lxml import etree
from lxml.builder import ElementMaker

h3c_device = {
    'host': '2001:db8::1111',
    'username': 'fc',
    'password': 'FCBGP@1234',
    'port': 830,
    'device_params': {'name': 'h3c'},
    'hostkey_verify': False,
    'look_for_keys': False,
}

def setup():
    nconn = manager.connect(**h3c_device)
    if not nconn:
        exit('Cannot connect')
    return nconn

def teardown(nconn):
    nconn.close_session()

def print_capabilities(nconn):
    print("\n******************************************************\n")
    print("server capabilities\n")
    for server_capability in nconn.server_capabilities:
        print(server_capability)
    print("\n******************************************************\n")
    print("client capabilities\n")
    for client_capability in nconn.client_capabilities:
        print(client_capability)

def nc_exec(config_xml):
    print("*" * 25, 'CMD', "*" * 25)
    print(etree.tostring(config_xml, pretty_print=True).decode())
    print("*" * 25, 'RET', "*" * 25)
    config_xml = etree.fromstring(config_xml)
    ret = nconn.edit_config(target="running", config=config_xml)
    print(ret)
    print("*" * 25, 'END', "*" * 25)


# acl ipv6 advanecd 3999
def acl_setup(nconn, group_index):
    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL>
          <NamedGroups>
            <Group>
              <GroupType>2</GroupType>
              <GroupCategory>2</GroupCategory>
              <GroupIndex>{group_index}</GroupIndex>
            </Group>
          </NamedGroups>
        </ACL>
      </top>
    </config>
    """
    nc_exec(config_xml)

# acl ipv6 rules
def acl_rule(nconn, group_index,
    srcip, srcprefixlen, dstip, dstprefixlen):
    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="merge">
          <IPv6NamedAdvanceRules>
            <Rule>
              <GroupIndex>{group_index}</GroupIndex>
              <RuleID>65535</RuleID>
              <Action>1</Action>
              <ProtocolType>256</ProtocolType>
              <SrcAny>0</SrcAny>
              <SrcIPv6>
                <SrcIPv6Addr>{srcip}</SrcIPv6Addr>
                <SrcIPv6Prefix>{srcprefixlen}</SrcIPv6Prefix>
              </SrcIPv6>
              <DstAny>0</DstAny>
              <DstIPv6>
                <DstIPv6Addr>{dstip}</DstIPv6Addr>
                <DstIPv6Prefix>{dstprefixlen}</DstIPv6Prefix>
              </DstIPv6>
            </Rule>
          </IPv6NamedAdvanceRules>
        </ACL>
      </top>
    </config>
    """
    nc_exec(config_xml)

# packet-filter ipv6 3999 inbound
def acl_apply(nconn, group_index: int, iface_index: int, direction: int):
    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="merge">
          <PfilterApply>
            <Pfilter>
               <AppObjType>1</AppObjType>
               <AppObjIndex>{iface_index}</AppObjIndex>
               <AppDirection>{direction}</AppDirection>
               <AppAclType>2</AppAclType>
               <AppAclGroup>{group_index}</AppAclGroup>
            </Pfilter>
          </PfilterApply>
        </ACL>
      </top>
    </config>

    """
    nc_exec(config_xml)


def main():
    nconn = setup()
    try:
        print_capabilities(nconn)
    finally:
        teardown(nconn)

if __name__ == '__main__':
    main()

