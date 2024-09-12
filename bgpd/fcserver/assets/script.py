from ncclient import manager
import time
from lxml import etree
from lxml.builder import ElementMaker
import logging

logging.basicConfig(filename='/opt/log/fcs.py.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

h3c_device = {
    'host': '2001:db8::1111',
    'username': 'fc',
    'password': 'FCBGP@1234',
    'port': 830,
    'device_params': {'name': 'h3c'},
    'hostkey_verify': False,
    'look_for_keys': False,
}

def setup(host,
        username='admin',
        password='admin',
        port=830):
    h3c_device['host'] = host
    h3c_device['username'] = username
    h3c_device['password'] = password
    h3c_device['port'] = port

    nconn = manager.connect(**h3c_device)
    if not nconn:
        exit('Cannot connect')
    return nconn

def teardown(nconn):
    nconn.close_session()

def print_capabilities(nconn):
    logging.info("\n******************************************************\n")
    logging.info("server capabilities\n")
    for server_capability in nconn.server_capabilities:
        logging.info(server_capability)
    logging.info("\n******************************************************\n")
    logging.info("client capabilities\n")
    for client_capability in nconn.client_capabilities:
        logging.info(client_capability)

def nc_exec(nconn, config_xml):
    logging.info("*" * 25 + ' CMD ' + "*" * 25)
    logging.info(config_xml)
    logging.info("*" * 25 + ' RET ' + "*" * 25)
    try:
      config_xml = etree.fromstring(config_xml)
      ret = nconn.edit_config(target="running", config=config_xml)
      logging.info(ret)
    except Exception as e:
      logging.error(e)
    logging.info("*" * 25 + ' END ' + "*" * 25)


# acl [ipv6] advanecd 3999
# ipversion: 1 for ipv4, 2 for ipv6
def acl_setup(nconn, group_type, group_index, operation="merge"):
    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="{operation}">
          <NamedGroups>
            <Group>
              <GroupType>{group_type}</GroupType>
              <GroupCategory>2</GroupCategory>
              <GroupIndex>{group_index}</GroupIndex>
            </Group>
          </NamedGroups>
        </ACL>
      </top>
    </config>
    """
    nc_exec(nconn, config_xml)

def ipv4_prefix_to_mask(ip: str, prefixlen: int) -> str:
    ipv4_int = sum(int(octet) * (256**(3-i)) for i,octet in enumerate(ip.split('.')))
    mask_int = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    mask_octets = []
    for _ in range(4):
        mask_octets.insert(0, str(mask_int & 0xFF))
        mask_int >>= 8
    return '.'.join(mask_octets)

def ipv4_prefix_to_reversed_mask(ip: str, prefixlen: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    inverted_mask_int = ~mask_int & 0xFFFFFFFF
    inverted_mask_octets = []
    for i in range(4):
        inverted_mask_octets.insert(0, str(inverted_mask_int & 0xFF))
        inverted_mask_int >>= 8
    return '.'.join(inverted_mask_octets)

def acl_v4_rule(nconn, group_index, rule_id, action,
        srcip, src_prefixlen, dstip, dst_prefixlen, operation="merge"):
    # As H3C says, H3C router requires reversed prefix length.
    src_mask = ipv4_prefix_to_reversed_mask(srcip, src_prefixlen)
    dst_mask = ipv4_prefix_to_reversed_mask(dstip, dst_prefixlen)
    
    action_xml = f"<Action>{action}</Action>"
    if operation == "delete":
      action_xml = ""

    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="{operation}">
          <IPv4NamedAdvanceRules>
            <Rule>
              <GroupIndex>{group_index}</GroupIndex>
              <RuleID>{rule_id}</RuleID>
              {action_xml}
              <ProtocolType>256</ProtocolType>
              <SrcAny>0</SrcAny>
              <SrcIPv4>
                <SrcIPv4Addr>{srcip}</SrcIPv4Addr>
                <SrcIPv4Wildcard>{src_mask}</SrcIPv4Wildcard>
              </SrcIPv4>
              <DstAny>0</DstAny>
              <DstIPv4>
                <DstIPv4Addr>{dstip}</DstIPv4Addr>
                <DstIPv4Wildcard>{dst_mask}</DstIPv4Wildcard>
              </DstIPv4>
            </Rule>
          </IPv4NamedAdvanceRules>
        </ACL>
      </top>
    </config>
    """
    nc_exec(nconn, config_xml)


# acl ipv6 rules
def acl_v6_rule(nconn, group_index, rule_id, action,
        srcip, src_prefixlen, dstip, dst_prefixlen, operation="merge"):
    
    action_xml = f"<Action>{action}</Action>"
    if operation == "delete":
      action_xml = ""

    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="{operation}">
          <IPv6NamedAdvanceRules>
            <Rule>
              <GroupIndex>{group_index}</GroupIndex>
              <RuleID>{rule_id}</RuleID>
              {action_xml}
              <ProtocolType>256</ProtocolType>
              <SrcAny>0</SrcAny>
              <SrcIPv6>
                <SrcIPv6Addr>{srcip}</SrcIPv6Addr>
                <SrcIPv6Prefix>{src_prefixlen}</SrcIPv6Prefix>
              </SrcIPv6>
              <DstAny>0</DstAny>
              <DstIPv6>
                <DstIPv6Addr>{dstip}</DstIPv6Addr>
                <DstIPv6Prefix>{dst_prefixlen}</DstIPv6Prefix>
              </DstIPv6>
            </Rule>
          </IPv6NamedAdvanceRules>
        </ACL>
      </top>
    </config>
    """
    nc_exec(nconn, config_xml)

def acl_rule(nconn, group_type, group_index, rule_id,
    srcip, src_prefixlen, dstip, dst_prefixlen,
    action=1, operation="merge"): # action=1 for deny
    if group_type == 1: # ipv4
        acl_v4_rule(nconn, group_index, rule_id, action,
                srcip, src_prefixlen, dstip, dst_prefixlen, operation)
    elif group_type == 2: # ipv6
        acl_v6_rule(nconn, group_index, rule_id, action,
                srcip, src_prefixlen, dstip, dst_prefixlen, operation)

# packet-filter ipv6 3999 inbound
def acl_apply(nconn, group_type: int, group_index: int, iface_index: int, 
              direction: int, operation="merge"):
    config_xml = f"""
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <ACL xc:operation="{operation}">
          <PfilterApply>
            <Pfilter>
               <AppObjType>1</AppObjType>
               <AppObjIndex>{iface_index}</AppObjIndex>
               <AppDirection>{direction}</AppDirection>
               <AppAclType>{group_type}</AppAclType>
               <AppAclGroup>{group_index}</AppAclGroup>
            </Pfilter>
          </PfilterApply>
        </ACL>
      </top>
    </config>
    """
    nc_exec(nconn, config_xml)

def main():
    nconn = setup('2001:db8::1001')
    try:
        print_capabilities(nconn)
        logging.info("*" * 50)
        mask = ipv4_prefix_to_mask("11.22.33.44", 23)
        logging.info(mask)
        acl_setup(nconn, 1, 3900)
        acl_rule(nconn, 1, 3900, 1,
                 "11.22.33.44", 24, "44.33.22.11", 24)
        acl_apply(nconn, 1, 3900, 12345678, 1)
    finally:
        teardown(nconn)

if __name__ == '__main__':
    main()
