/********************************************************************************
 * File Name:    dbutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:45:44
 * Description:  SQLITE3 DATABASE UTILS
 ********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "dbutils.h"

    int
fc_db_open(sqlite3 **db, const char *dbname)
{
    if (sqlite3_open(dbname, db) != SQLITE_OK)
    {
        printf("Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(0);
    }
    else
    {
        printf("Opened database successfully\n");
    }

    return 0;
}

    int
fc_db_store_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

    int
fc_db_select_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

/* Execute SQL statement */
    int
fc_db_exec(sqlite3 *db, const char *sql,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name),
        void *data)
{
    char *zErrMsg = 0;
    int rc;
    rc = sqlite3_exec(db, sql, cb, data, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        printf("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
    else
    {
        printf("Operation done successfully\n");
    }

    return 0;
}

    int
fc_db_write_bm(const FC_msg_bm_t *bm)
{
    char sql[BUFSIZ] = {0};
    // base64 encode
    char buff_src_ip[FC_BUFF_SIZE] = {0};
    char buff_dst_ip[FC_BUFF_SIZE] = {0};
    char buff_fclist[FC_BUFF_SIZE] = {0};
    char buff_ski[FC_BUFF_SIZE256] = {0};
    char buff_signature[FC_BUFF_SIZE] = {0};
    // char buff[BUFSIZ] = {0};
    int cur = 0, i = 0;
    socklen_t socklen;
    struct sockaddr_in *sin = NULL;
    struct sockaddr_in6 *sin6 = NULL;

    if (bm->ipversion == IPV4)
    {
        socklen = sizeof(struct sockaddr_in);
    } else if (bm->ipversion == IPV6)
    {
        socklen = sizeof(struct sockaddr_in6);
        printf("THIS IS NOT supported: %d!\n", bm->ipversion);
        return 0;
    } else
    {
        printf("THIS IS NOT supported: %d!\n", bm->ipversion);
        return -1;
    }

    // use , to split strings
    // base64 encode src_ip
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->src_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_src_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_src_ip+cur, socklen);
        }
        cur += strlen(buff_src_ip+cur);
        snprintf(buff_src_ip+cur, FC_BUFF_SIZE, "/%d,",
                bm->src_ip[i].prefix_length);
        cur += strlen(buff_src_ip+cur);
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    printf("src-ip: %s\n", buff_src_ip);

    // fc_base64_encode(buff, cur, buff_src_ip);

    // base64 encode dst_ip
    cur = 0;
    // memset(buff_dst_ip, 0, BUFSIZ);
    for (i=0; i<bm->dst_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_dst_ip+cur, socklen);
        } else {
            sin6 = (struct sockaddr_in6 *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin6->sin6_addr, buff_dst_ip+cur, socklen);
        }
        cur += strlen(buff_dst_ip+cur);
        snprintf(buff_dst_ip+cur, FC_BUFF_SIZE,
                "/%d,", bm->dst_ip[i].prefix_length);
        cur += strlen(buff_dst_ip+cur);
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    printf("dst-ip: %s\n", buff_dst_ip);
    // fc_base64_encode(buff, cur, buff_dst_ip);

    // base64 encode fclist
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i=0; i<bm->fc_num; ++i)
    {
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, "%08X-%08X-%08X-",
                bm->fclist[i].previous_asn,
                bm->fclist[i].current_asn,
                bm->fclist[i].nexthop_asn);
        cur += 8*3 + 3;
        for (int j=0; j<20; ++j)
        {
            snprintf(buff_fclist+cur, BUFSIZ, "%02X",
                    bm->fclist[i].ski[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, "-%02X-%02X-%04X-",
                bm->fclist[i].algo_id,
                bm->fclist[i].flags, bm->fclist[i].siglen);
        cur += 8 + 4;

        for (int j=0; j<bm->fclist[i].siglen; ++j)
        {
            snprintf(buff_fclist+cur, FC_BUFF_SIZE, "%02X",
                    bm->fclist[i].sig[j]);
            cur += 2;
        }
        snprintf(buff_fclist+cur, FC_BUFF_SIZE, ",");
        cur += 1;
        // printf("i: %d, curlen: %d, fclist: %s\n", i, cur, buff_fclist);
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    // fc_base64_encode(buff, cur, buff_fclist);

    /*
       printf("buff-srcip: %s\n", buff_src_ip);
       printf("buff-dstip: %s\n", buff_dst_ip);
       printf("buff-fclist: %s\n", buff_fclist);
       */

    // ski
    cur = 0;
    for (int j=0; j<20; ++j)
    {
        snprintf(buff_ski+cur, FC_BUFF_SIZE256, "%02X",
                bm->fclist[i].ski[j]);
        cur += 2;
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE256);
    }
    // signature
    cur = 0;
    for (int j = 0; j < bm->siglen; ++j)
    {
        snprintf(buff_signature+cur, FC_BUFF_SIZE, "%02X",
                bm->signature[j]);
        cur += 2;
        FC_MEM_CHECK(cur >= FC_BUFF_SIZE);
    }
    printf("signature: %s\n", buff_signature);
    snprintf(sql, BUFSIZ,
            "INSERT INTO fcs VALUES(%u, %u, %u, %u, %u, %u, %u, %u, %u, "
            "%u, '%s', '%s', '%s', '%s', '%s')",
            bm->ipversion, bm->type, bm->action, bm->fc_num,
            bm->src_ip_num, bm->dst_ip_num, bm->siglen, bm->local_asn,
            bm->version, bm->subversion, buff_src_ip, buff_dst_ip,
            buff_fclist, buff_ski, buff_signature);
    printf("SQL: %s\n", sql);
    fc_db_exec(g_fc_server.db, sql, fc_db_store_bm_handler, NULL);

    return 0;
}

    int
fc_db_close(sqlite3 *db)
{
    sqlite3_close(db);
    return 0;
}

    void
fc_db_init(sqlite3 **db)
{
    char sql[BUFSIZ];

    fc_db_open(db, FC_DB_NAME);

    if (g_fc_server.clear_fc_db)
    {
        bzero(sql, BUFSIZ);
        sprintf(sql, "DROP TABLE IF EXISTS fcs;");
        printf("sql: %s\n", sql);
        fc_db_exec(*db, sql, NULL, NULL);
    }

    bzero(sql, BUFSIZ);
    sprintf(sql, "CREATE TABLE fcs("
            "ipversion INT NOT NULL,"
            "type INT NOT NULL,"
            "action INT NOT NULL,"
            "fc_num INT NOT NULL,"
            "src_ip_num INT NOT NULL,"
            "dst_ip_num INT NOT NULL,"
            "siglen INT NOT NULL,"
            "local_asn INT NOT NULL,"
            "version INT NOT NULL,"
            "subversion INT NOT NULL,"
            "src_ip CHAR(1024) NOT NULL,"
            "dst_ip CHAR(1024) NOT NULL,"
            "fclist CHAR(2048) NOT NULL,"
            "ski CHAR(20) NOT NULL,"
            "signature CHAR(1024) NOT NULL)"
           );
    printf("sql: %s\n", sql);
    fc_db_exec(*db, sql, NULL, NULL);
    // bzero(sql, 1024);
    // sprintf(sql, "DELETE FROM relation WHERE asn = %u", asn);
    // fc_db_exec(*db, sql, NULL, NULL);
}

