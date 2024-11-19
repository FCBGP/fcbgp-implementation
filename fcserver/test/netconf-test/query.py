#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:      basilguo@163.com
# Date:        2024-05-16 11:54:23
# File Name:   query.py
# Version:     0.0.1
# Description:
import sys, os, warnings
warnings.simplefilter("ignore", DeprecationWarning)
from ncclient import manager
import time
def my_unknown_host_cb(host, figerprint):
    return True
def demo(host, port, user, pwd):
    with manager.connect_ssh(host=host,
        port=port,
        username=user,
        password=pwd,
        unknown_host_cb=my_unknown_host_cb,
        device_params = {'name':'h3c'}) as m:
        for c in m.server_capabilities:
            print (c)
        get_xml = """
			<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
		      <get-config>
				<source>
                  <running/>
                </source>
                <filter type="subtree">
			      <top xmlns="http://www.h3c.com/netconf/config:1.0">
			      </top>
			    </filter>
			  </get-config>
			</rpc>
        """
        print (m.get(('subtree', get_xml)))
if __name__ == '__main__':
    demo("127.0.0.1", 10000, "admin", "admin")
    print ("closed")
    time.sleep(1)
