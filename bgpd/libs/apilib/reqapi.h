#ifndef _LIB_REQAPI_H_
#define _LIB_REQAPI_H_

#include "libreq.h"

/* gen_addrdreq.c */
extern req_ctx_t *g_gen_addr_req;
extern int gen_addr_req_init(void);
extern void gen_addr_req_fini(void);
extern int gen_addr_version_req(req_ctx_t *req);

extern int nid_query_req(req_ctx_t *req, char *nid);
extern int nid_gen_req(req_ctx_t *req, char *nid);
extern int nid_get_req(req_ctx_t *req, char *nid);
extern int nid_delete_req(req_ctx_t *req, char *nid);
extern int nid_get_by_addr_req(req_ctx_t *req, char *ipv6);

extern int client_user_info_req(req_ctx_t *req, char *nid, char *address);
extern int client_user_recharge_req(req_ctx_t * req, char *nid, unsigned int amount);

extern int ipv6_gen_req(req_ctx_t *req, char *nid);
extern int ipv6_get_req(req_ctx_t *req, char *nid);
extern int ipv6_release_req(req_ctx_t *req, char *ipv6);

extern int config_show_req(req_ctx_t *req);
extern int config_reset_req(req_ctx_t * req, int nidlen, int fenjie, int zuzhi, int yonghu, char *ippre);
extern int config_update_req(req_ctx_t *req);

extern int user_add_req(req_ctx_t * req, char *nid, char *stuno, char *name, char *idcode, int sex, char *tel, \
        char *phone, char *email, char *address, int onlinemax, char *passwd);
extern int user_clear_req(req_ctx_t *req);

extern int history_get_bynid_req(req_ctx_t *req, char *nid, int page, int perPage, char *start_time, char *end_time);

/* webreq.c */
extern req_ctx_t *g_web_req;
extern int web_req_init(void);
extern void web_req_fini(void);
extern int web_add_va_req(req_ctx_t *req, int state, int level, char *fmt, va_list ap);
extern int web_event_req(req_ctx_t *req, int state, int level, char *fmt, ...);
extern int web_config_show_req(req_ctx_t * req);
extern int web_config_reset_req(req_ctx_t * req, int nidlen, int fenjie, int zuzhi, int yonghu, char *ippre);
extern int web_config_update_req(req_ctx_t * req);
extern int web_user_add_req(req_ctx_t * req, char *nid, char *stuno, char *name, char *idcode, int sex, char *tel, \
                            char *phone, char *email, char *address, int onlinemax, char *passwd);
extern int web_user_clear_req(req_ctx_t * req);

extern int key_update_req(req_ctx_t * req);
extern int key_current_req(req_ctx_t * req);

extern req_ctx_t *g_NIDTGA_snmp_req;
extern int NIDTGA_snmp_req_init(void);
extern void NIDTGA_snmp_req_fini(void);
extern int NIDTGA_snmp_version_req(req_ctx_t *req);

extern int NIDTGA_snmp_devdesc_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_cpu_5sec_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_cpu_1min_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_cpu_5min_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_mem_used_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_mem_free_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_sys_uptime_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_sys_contact_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_sys_name_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_sys_location_req(req_ctx_t *req, char *ip, int port, char *comm);
extern int NIDTGA_snmp_if_info_req(req_ctx_t *req, char *ip, int port, char *comm);

/*tracereq.c*/

extern req_ctx_t *g_trace_req;
extern void trace_req_fini(void);
extern int trace_req_init(void);
extern int trace_add_va_req(req_ctx_t *req, int state, int level, char *fmt, va_list ap);
extern int trace_event_req(req_ctx_t *req, int state, int level, char *fmt, ...);

extern int domain_list_req(req_ctx_t * req, int page, int page_count);
extern int domain_add_req(req_ctx_t * req, char *ip, char *pref, int port, char *contacks, char *phone, char *position);
extern int domain_del_req(req_ctx_t * req, char *pref);
extern int domain_mod_req(req_ctx_t * req, char *ip, char *pref, int port, char *contacks, char *phone, char *position);
extern int domain_search_req(req_ctx_t * req, char *pref);

extern int userinfo_get_req(req_ctx_t * req, char *nidstr, char *remote_ip, int remote_port);
extern int get_nid_by_ipv6_req(req_ctx_t * req, char *ip, int preflen);


#endif
