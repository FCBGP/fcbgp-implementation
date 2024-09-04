/********************************************************************************
 * File Name:    fcconfig.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:55:22
 * Description:  local config
 ********************************************************************************/

#ifndef FCCONFIG_H
#define FCCONFIG_H

#include "defines.h"

#define FC_CFG_DEFAULT_LISTEN_PORT 23160
#define FC_CFG_DEFAULT_HASH_ALGO "SHA256"
#define FC_CFG_DEFAULT_HASH_ALGO_ID FC_HASH_ALGO_SHA256
#define FC_CFG_DEFAULT_LOG_LEVEL FC_LOG_LEVEL_INFO
#define FC_CFG_DEFAULT_DP_MODE "NONE"
#define FC_CFG_DEFAULT_H3C_ACL_GROUP_START_INDEX 3900
#define FC_CFG_DEFAULT_CONFIG_FNAME "/etc/frr/assets/config.json"
#define FC_CFG_DEFAULT_DB_NAME "/etc/frr/assets/fc.db"

// optional configurations which have default value
extern int fc_cfg_set_listen_port(int listen_port);
extern int fc_cfg_set_hash_algo_id(const char *const hash_algo_str);
extern int fc_cfg_set_log_mode(const char *const dp_mode_str);
extern int fc_cfg_set_db_clear(const char *const clear_fc_db_str);
extern int fc_cfg_set_dp_mode(const char *const dp_mode_str);

extern int fc_cfg_set_local_asn(uint32_t local_asn);

extern int fc_read_config(void);

#endif // FCCONFIG_H
