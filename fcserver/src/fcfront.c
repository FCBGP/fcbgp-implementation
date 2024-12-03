/**
 * @file fcfront.c
 * @author basilguo@163.com
 * @brief
 * @version 0.0.1
 * @date 2024-09-11
 *
 * @copyright Copyright (c) 2021 - 2024
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "dbutils.h"
#include "defines.h"
#include "fcserver.h"
#include "linenoise.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#define HISTORY_FILE_PATH "/opt/log/history.txt"
#define CMD_TIPS "fcs> "

    typedef struct fc_cmd_st
    {
        const char* cmd;
        const char* desc;
        const void (*func)(void);
    } fc_cmd_t;

    static fc_cmd_t cmds[] = {
        {"help", "print this message.", fc_cmd_help},
        {"acl", "show local router acls.", fc_cmd_acl},
        {"bm", "show local router bms.", fc_cmd_bm},
        {"info", "show local router info.", fc_cmd_info},
        {"link", "show local router links.", fc_cmd_link},
        {"version", "show fc server version.", fc_cmd_version},
        {"exit", "alias of quit.", fc_cmd_quit},
        {"quit", "quit the program.", fc_cmd_quit},
    };

#define FC_CMD_N_NUM (sizeof(cmds) / sizeof(fc_cmd_t))

    void fc_cmd_link(void)
    {
        FC_router_info_t* routers = g_fc_server.routers;
        printf("local asn: %u\n", g_fc_server.local_asn);
        while (routers && g_fc_server.routers_num > 0)
        {
            printf(" bgpid: %8X\n", routers->bgpid);
            printf(" acl group index: %d\n", routers->acl_group_index);
            printf(" links:\n");
            FC_router_link_info_t* link_info = routers->links;
            while (link_info)
            {
                printf("  neighbor asn: %8X\n", link_info->neighbor_asn);
                printf("  iface\n");
                FC_router_iface_info_t* iface_list = link_info->iface_list;
                while (iface_list)
                {
                    printf("   %08X\n", iface_list->iface_index);
                    iface_list = iface_list->next;
                }
                link_info = link_info->next;
            }
            routers = routers->next;
        }
    }

    static int fc_acl_rule_iterator_handler(void* key, void* val, void* udata)
    {
        u32 iface_index = *(u32*)key;
        ht_acl_group_info_t* acl_group_info = (ht_acl_group_info_t*)key;
        ht_acl_rule_info_t *acl_rule_info = NULL, *tmp = NULL;
        HASH_ITER(hh, acl_group_info->ht_acl_rule_info, acl_rule_info, tmp)
        {
            printf("group index: %u, direction(1 for in, 2 for out): %d, iface "
                   "index: "
                   "%08X\n"
                   "\tipversion: %d rule_id: %u, src prefix: %s/%d, dst "
                   "prefix: %s/%d\n",
                   acl_rule_info->acl_group_index, acl_rule_info->direction,
                   iface_index, acl_rule_info->ipversion,
                   acl_rule_info->rule_id, acl_rule_info->saddr,
                   acl_rule_info->sprefixlen, acl_rule_info->daddr,
                   acl_rule_info->dprefixlen);
        }

        printf("Press Enter to continue or q to quit...\n");

        // 0 for enter, 1 for quit
        return getchar();
    }

    void fc_cmd_acl(void)
    {
        ht_acl_group_info_t *acl_group_info = NULL, *tmp = NULL;
        HASH_ITER(hh, g_fc_server.ht_acl_group_info, acl_group_info, tmp)
        {
            int ret = fc_acl_rule_iterator_handler(&acl_group_info->iface_index,
                                                   acl_group_info, NULL);
            if (ret == 'q')
            {
                break;
            }
        }
    }

    void fc_cmd_bm(void)
    {
        int bm_nums = 0, i = 0;
        struct sockaddr_in* sockaddr = NULL;
        struct sockaddr_in6* sockaddr6 = NULL;
        FC_msg_bm_t* bm = NULL;
        FC_msg_bm_t* bms = fc_db_read_bms(&bm_nums);

        if (bm_nums == 0)
        {
            printf("There is no Binding Messages\n");
        }

        for (i = 0, bm = &bms[i]; i < bm_nums; ++i, bm = &bms[i])
        {
            printf("bm:    %d/%d\n", i + 1, bm_nums);
            printf("  ipversion: %d\n", bm->ipversion);
            printf("  flags: %02X\n", bm->flags);
            printf("  src-ip-num: %d, src-ip:\n", bm->src_ip_num);
            for (int j = 0; j < bm->src_ip_num; ++j)
            {
                char ipstr[INET6_ADDRSTRLEN] = {0};
                switch (bm->ipversion)
                {
                    case IPV4:
                        sockaddr = (struct sockaddr_in*)&bm->src_ip[j].ip;
                        inet_ntop(AF_INET, &sockaddr->sin_addr, ipstr,
                                  sizeof(struct sockaddr_in));
                        break;
                    case IPV6:
                        sockaddr6 = (struct sockaddr_in6*)&bm->src_ip[j].ip;
                        inet_ntop(AF_INET6, &sockaddr6->sin6_addr, ipstr,
                                  sizeof(struct sockaddr_in6));
                        break;
                }
                printf("    %s/%d\n", ipstr, bm->src_ip[j].prefix_length);
            }
            printf("  dst-ip-num: %d, dst-ip:\n", bm->dst_ip_num);
            for (int j = 0; j < bm->dst_ip_num; ++j)
            {
                char ipstr[INET6_ADDRSTRLEN] = {0};
                switch (bm->ipversion)
                {
                    case IPV4:
                        sockaddr = (struct sockaddr_in*)&bm->dst_ip[j].ip;
                        inet_ntop(AF_INET, &sockaddr->sin_addr, ipstr,
                                  sizeof(struct sockaddr_in));
                        break;
                    case IPV6:
                        sockaddr6 = (struct sockaddr_in6*)&bm->dst_ip[j].ip;
                        inet_ntop(AF_INET6, &sockaddr6->sin6_addr, ipstr,
                                  sizeof(struct sockaddr_in6));
                        break;
                }
                printf("    %s/%d\n", ipstr, bm->dst_ip[j].prefix_length);
            }
            printf("  fc-num: %d, fclist:\n", bm->fc_num);
            for (int j = 0; j < bm->fc_num; ++j)
            {
                printf("    3 asns: %08X %08X %08X\n",
                       bm->fclist[j].previous_asn, bm->fclist[j].current_asn,
                       bm->fclist[j].nexthop_asn);
            }

            if ((i + 1) % 2 == 0 && (i + 1) != bm_nums)
            {
                printf("Press Enter to continue or q to quit...\n");
                char ch = getchar();
                if (ch == 'q')
                {
                    break;
                }
            }
        }

        free(bms);
    }

    void fc_cmd_info(void)
    {
        printf("program name: %s\n", g_fc_server.prog_name);
        printf("program address ipv4: %s\n", g_fc_server.prog_addr4);
        printf("program address ipv6: %s\n", g_fc_server.prog_addr6);
        printf("log level: %u\n", g_fc_server.log_level);
        printf("clear fc db: %d\n", g_fc_server.clear_fc_db);
        printf("user_data_plane: %d\n", g_fc_server.use_data_plane);
        printf("local asn: %u\n", g_fc_server.local_asn);
        printf("hash algorithm: %s\n", g_fc_server.hash_algorithm);
        printf("listen port: %d\n", g_fc_server.listen_port);

        switch (g_fc_server.fcs_addr_type)
        {
            case FC_FCS_ADDR_TYPE_V4:
                printf("fcs addr type: ipv4\n");
                break;
            case FC_FCS_ADDR_TYPE_V6:
                printf("fcs addr type: ipv6\n");
                break;
        }

        printf("ASNs:\n");
        for (int i = 0; i < g_fc_server.asns_num; ++i)
        {
            printf("  asn: %u\n", g_fc_server.asns[i]);
        }
        printf("db file name: %s\n", g_fc_server.fc_db_fname);
        printf("config file name: %s\n", g_fc_server.config_fname);
        printf("prikey file name: %s\n", g_fc_server.prikey_fname);
        printf("certs location: %s\n", g_fc_server.certs_location);
        printf("local ski: ");
        for (int i = 0; i < FC_SKI_LENGTH; ++i)
        {
            printf("%02X", g_fc_server.ski[i]);
        }
        printf("\n");
        printf("NICs:\n");
        for (int i = 0; i < g_fc_server.nics_num; ++i)
        {
            printf(" nic: %s\n", g_fc_server.nics[i]);
        }
    }

    static inline void fc_print_char_line(char ch, char* string)
    {
        int i = 0, line_len = 78, ln = 0, rn = 0, string_len = 0;

        string_len = strlen(string);
        ln = (line_len - string_len) / 2;
        rn = line_len - string_len - ln;

        printf("*");
        for (i = 0; i < ln; ++i)
            printf("%c", ch);
        printf("%s", string);
        for (i = 0; i < rn; ++i)
            printf("%c", ch);
        printf("*\n");
    }

    void fc_cmd_version(void)
    {
        fc_print_char_line('*', "");
        fc_print_char_line(' ', FC_VERSION_STR);
        fc_print_char_line(
            ' ', "Home page: <https://gitee.com/basil1728/fcbgp-new>");
        fc_print_char_line(
            ' ', "A private repository. Not avaliable without permission.");
        fc_print_char_line(
            ' ',
            "Need help or report bugs please mailto: guoyangfei@zgclab.edu.cn");
        fc_print_char_line(' ',
                           "OPENSSL_VERSION needed: " OPENSSL_VERSION_NEEDED);
        fc_print_char_line(' ',
                           "OPENSSL_VERSION current: " OPENSSL_VERSION_TEXT);
        fc_print_char_line('*', "");
    }

    void fc_cmd_quit(void) { fc_server_destroy(SIGUSR1); }

    void fc_cmd_help(void)
    {
        for (int i = 0; i < FC_CMD_N_NUM; ++i)
            printf("%8s\t\t%s\n", cmds[i].cmd, cmds[i].desc);
    }

    void completion(const char* buf, linenoiseCompletions* lc)
    {
        for (int i = 0; i < FC_CMD_N_NUM; ++i)
        {
            if (buf[0] == cmds[i].cmd[0])
            {
                linenoiseAddCompletion(lc, cmds[i].cmd);
            }
        }
    }

    char* hints_cb(const char* buf, int* color, int* bold)
    {
        for (int i = 0; i < FC_CMD_N_NUM; ++i)
        {
            if (buf[0] == cmds[i].cmd[0] && strcasecmp(buf, cmds[i].cmd) != 0)
            {
                char* hint = strdup(cmds[i].cmd);
                *color = 35;
                *bold = 0;
                return hint + strlen(buf);
            }
        }
        return NULL;
    }

    void hints_free(void* data) { free(data); }

    void* fc_main_front(void* args)
    {
        (void)args;

        char* line;
        /* Set the completion callback. This will be called every time the
         * user uses the <tab> key. */
        linenoiseSetCompletionCallback(completion);
        linenoiseSetHintsCallback(hints_cb);
        linenoiseFreeHintsCallback(hints_free);

        /* Load history from file. The history file is just a plain text file
         * where entries are separated by newlines. */
        linenoiseHistoryLoad(
            HISTORY_FILE_PATH); /* Load the history at startup */

        /* Now this is the main loop of the typical linenoise-based application.
         * The call to linenoise() will block as long as the user types
         * something and presses enter.
         *
         * The typed string is returned as a malloc() allocated string by
         * linenoise, so the user needs to free() it. */

        while (1)
        {
            int flag = 1;
            line = linenoise(CMD_TIPS);
            if (line == NULL)
                break;

            /* Do something with the string. */
            if (line[0] != '\0' && line[0] != '/')
            {
                for (int i = 0; i < FC_CMD_N_NUM; ++i)
                {
                    if (!strcmp(cmds[i].cmd, line))
                    {
                        flag = 0;
                        cmds[i].func();
                    }
                }
                if (flag)
                {
                    printf("Sorry, no such command: %s\n", line);
                    fc_cmd_help();
                }
                else
                {
                    linenoiseHistoryAdd(line); /* Add to the history. */
                    linenoiseHistorySave(
                        HISTORY_FILE_PATH); /* Save the history on disk. */
                }
            }
            else if (!strncmp(line, "/historylen", 11))
            {
                /* The "/historylen" command will change the history len. */
                int len = atoi(line + 11);
                linenoiseHistorySetMaxLen(len);
            }
            else if (!strncmp(line, "/mask", 5))
            {
                linenoiseMaskModeEnable();
            }
            else if (!strncmp(line, "/unmask", 7))
            {
                linenoiseMaskModeDisable();
            }
            else if (line[0] == '/')
            {
                printf("Unreconized command: %s\n", line);
            }
            free(line);
        }

        return NULL;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
