#ifndef _LIBAPI_H_
#define _LIBAPI_H_

#define WEBD_ADDRESS "/var/run/webd.ipc"
#define GEN_ADDRD_ADDRESS "/var/run/gen_addrd.ipc"
#define NIDTGA_SNMPD_ADDRESS "/var/run/NIDTGA_snmpd.ipc"

#define GEN_ADDR_COMMAND_VERSION "/version"
#define NIDTGA_SNMP_COMMAND_VERSION "/nidversion"
#define NIDTGA_SNMP_COMMAND_DEVDESC "/snmp/devdesc"
#define NIDTGA_SNMP_COMMAND_CPU_5SEC "/cpu/usage/5sec"
#define NIDTGA_SNMP_COMMAND_CPU_1MIN "/cpu/usage/1min"
#define NIDTGA_SNMP_COMMAND_CPU_5MIN "/cpu/usage/5min"
#define NIDTGA_SNMP_COMMAND_MEM_USED "/mem/used"
#define NIDTGA_SNMP_COMMAND_MEM_FREE "/mem/free"
#define NIDTGA_SNMP_COMMAND_SYS_UPTIME "/sys/uptime"
#define NIDTGA_SNMP_COMMAND_SYS_CONTACT "/sys/contact"
#define NIDTGA_SNMP_COMMAND_SYS_NAME "/sys/name"
#define NIDTGA_SNMP_COMMAND_SYS_LOCATION "/sys/location"
#define NIDTGA_SNMP_COMMAND_IF_INFO "/if/info"

#define WEB_COMMAND_CONFIG_SHOW "/config/show"
#define WEB_COMMAND_CONFIG_RESET "/config/reset"
#define WEB_COMMAND_CONFIG_UPDATE "/config/update"

#define GEN_ADDR_COMMAND_NID_QUERY "/nid/query"
#define GEN_ADDR_COMMAND_NID_GEN "/nid/gen"
#define GEN_ADDR_COMMAND_NID_GET_BY_STUNO "/nid/getbystuno"
#define GEN_ADDR_COMMAND_NID_GET_BY_IPV6 "/nid/getbyip"
//#define GEN_ADDR_COMMAND_NID_GET_BY_MAC "/nid/getbymac"
#define GEN_ADDR_COMMAND_NID_DELETE "/nid/del"

#define GEN_ADDR_COMMAND_HISTORY "/history/get"

#define GEN_ADDR_COMMAND_CLIENT_USER_INFO "/client/user/info"
#define GEN_ADDR_COMMAND_CLIENT_USER_RECHARGE "/client/user/recharge"

#define GEN_ADDR_COMMAND_IPV6_GEN "/ipv6/gen"
#define GEN_ADDR_COMMAND_IPV6_RELEASE "/ipv6/release"
//#define GEN_ADDR_COMMAND_IPV6_QUERY "/ipv6/query"

//#define GEN_ADDR_COMMAND_STUNO_QUERY "/stuno/query"
//#define GEN_ADDR_COMMAND_STUNO_GET_BY_NID "/stuno/getbynid"
//#define GEN_ADDR_COMMAND_STUNO_GET_BY_IP "/stuno/getbyip"

#define GEN_ADDR_COMMAND_USER_ADD "/user/add"
#define GEN_ADDR_COMMAND_USER_ADD_BATCH "/user/add/batch"
#define GEN_ADDR_COMMAND_USER_DEL "/user/del"
#define GEN_ADDR_COMMAND_USER_CLEAR "/user/clear"
//#define GEN_ADDR_COMMAND_USER_MOD "/user/mod"
//#define GEN_ADDR_COMMAND_USER_LIST "/user/list"
//#define GEN_ADDR_COMMAND_GET_USER_MSG "/user/info"
//#define GEN_ADDR_COMMAND_USER_ONLINE_LIST "/user/online"
//#define GEN_ADDR_COMMAND_USER_HISTORY "/user/history"

#define WEB_COMMAND_EVENT_SEND "/web/event/send"
#define WEB_COMMAND_USER_ADD "/web/user/add"
#define WEB_COMMAND_USER_ADD_BATCH  "/web/user/add/batch"
#define WEB_COMMAND_USER_CLEAR "/web/user/clear"
#define WEB_COMMAND_KEY_UPDATE "/web/key/update"
#define WEB_COMMAND_KEY_CURRENT "/web/key/current"

#define TRACE_COMMAND_EVENT_SEND "/trace/event/send"
#define TRACE_COMMAND_DOMAIN_LIST "/domain/list"
#define TRACE_COMMAND_DOMAIN_ADD "/domain/add"
#define TRACE_COMMAND_DOMAIN_DEL "/domain/del"
#define TRACE_COMMAND_DOMAIN_MOD "/domain/mod"
#define TRACE_COMMAND_DOMAIN_SEARCH "/domain/search"
#define TRACE_COMMAND_USERINFO_GET "/trace/userinfo/get"
#define TRACE_COMMAND_NID_GET "/trace/nid/get"

#endif
