/********************************************************************************
 * File Name:    dbutils.c
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:45:44
 * Description:  SQLITE3 DATABASE UTILS
 ********************************************************************************/

#include "dbutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fc_db_open(sqlite3 **db, const char *dbname)
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

int fc_db_store_bm_handler(void *data, int argc, char **argv,
                           char **az_col_name)
{
    return 0;
}

int fc_db_select_bm_handler(void *data, int argc, char **argv,
                            char **az_col_name)
{
    return 0;
}

/* Execute SQL statement */
int fc_db_exec(sqlite3 *db, const char *sql,
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

static int fc_db_total_bm_num = 0;
static FC_msg_bm_t *fc_db_bm_ptr = NULL;

static int
fc_db_cb_get_cnt(void *data, int argc, char **argv, char **azColName)
{
    if (argv[0])
    {
        fc_db_total_bm_num = atoi(argv[0]);
    }
    else
    {
        fc_db_total_bm_num = 0;
    }

    printf("total fc stored in db: %d\n", fc_db_total_bm_num);

    return 0;
}

static int
fc_db_cb_get_one_bm(void *data, int argc, char **argv, char **azColName)
{
    (void)argc;
    (void)azColName;
    int i = 0;
    char *token = NULL;
    char *outer_delim = ",";
    char *inner_delim = "/";
    char *asn_delim = "-";
    // not all data are needed.
    fc_db_bm_ptr->bmversion = atoi(argv[0]);
    fc_db_bm_ptr->ipversion = atoi(argv[1]);
    fc_db_bm_ptr->flags = atoi(argv[2]);
    fc_db_bm_ptr->algoid = atoi(argv[3]);
    fc_db_bm_ptr->src_ip_num = atoi(argv[4]);
    fc_db_bm_ptr->dst_ip_num = atoi(argv[5]);
    fc_db_bm_ptr->fc_num = atoi(argv[6]);
    fc_db_bm_ptr->siglen = atoi(argv[7]);
    fc_db_bm_ptr->local_asn = atoi(argv[8]);
    fc_db_bm_ptr->version = atoi(argv[9]);
    fc_db_bm_ptr->subversion = atoi(argv[10]);

    char *src_ip_prefix_str = argv[11];
    for (token = strtok(src_ip_prefix_str, outer_delim), i = 0;
         token != NULL;
         token = strtok(NULL, outer_delim), i++)
    {
        char *src_ip = strtok(token, inner_delim);
        char *prefixlen = strtok(NULL, inner_delim);
        switch (fc_db_bm_ptr->ipversion)
        {
        case IPV4:
            struct sockaddr_in *sockaddr =
                (struct sockaddr_in *)&fc_db_bm_ptr->src_ip[i].ip;
            inet_pton(AF_INET, src_ip, &sockaddr->sin_addr);
            break;
        case IPV6:
            struct sockaddr_in6 *sockaddr6 =
                (struct sockaddr_in6 *)&fc_db_bm_ptr->src_ip[i].ip;
            inet_pton(AF_INET6, src_ip, &sockaddr6->sin6_addr);
            break;
        }
        fc_db_bm_ptr->src_ip[i].prefix_length = atoi(prefixlen);
    }

    char *dst_ip_prefix_str = argv[12];
    for (token = strtok(dst_ip_prefix_str, outer_delim), i = 0;
         token != NULL;
         token = strtok(NULL, outer_delim), i++)
    {
        char *dst_ip = strtok(token, inner_delim);
        char *prefixlen = strtok(NULL, inner_delim);
        switch (fc_db_bm_ptr->ipversion)
        {
        case IPV4:
            struct sockaddr_in *sockaddr =
                (struct sockaddr_in *)&fc_db_bm_ptr->dst_ip[i].ip;
            inet_pton(AF_INET, dst_ip, &sockaddr->sin_addr);
            break;
        case IPV6:
            struct sockaddr_in6 *sockaddr6 =
                (struct sockaddr_in6 *)&fc_db_bm_ptr->dst_ip[i].ip;
            inet_pton(AF_INET6, dst_ip, &sockaddr6->sin6_addr);
            break;
        }
        fc_db_bm_ptr->dst_ip[i].prefix_length = atoi(prefixlen);
    }

    char *fclist_str = argv[13];
    for (token = strtok(fclist_str, outer_delim), i = 0;
         token != NULL;
         token = strtok(NULL, outer_delim), i++)
    {
        char *pasn = strtok(token, asn_delim);
        char *casn = strtok(NULL, asn_delim);
        char *nasn = strtok(NULL, asn_delim);
        fc_db_bm_ptr->fclist[i].previous_asn = atoi(pasn);
        fc_db_bm_ptr->fclist[i].current_asn = atoi(casn);
        fc_db_bm_ptr->fclist[i].nexthop_asn = atoi(nasn);
    }

    return 0;
}

int fc_db_read_bm(FC_msg_bm_t **bm, int *bmnum)
{
    TXTRED("### READ FROM DB START ###\n");
    int rc = 0;
    char *errMsg = NULL;
    const char *sql_cnt = "SELECT COUNT(*) FROM fcs;";
    const char *sql_template = "SELECT * FROM fcs LIMIT 1 OFFSET %d;";

    rc = sqlite3_exec(g_fc_server.db, sql_cnt, fc_db_cb_get_cnt, 0, &errMsg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    *bmnum = fc_db_total_bm_num;
    *bm = malloc(sizeof(FC_msg_bm_t) * fc_db_total_bm_num);
    memset(*bm, 0, sizeof(FC_msg_bm_t) * fc_db_total_bm_num);

    while (fc_db_total_bm_num-- > 0)
    {
        fc_db_bm_ptr = bm[fc_db_total_bm_num];
        char sql[1024] = {0};
        sprintf(sql, sql_template, fc_db_total_bm_num);
        rc = sqlite3_exec(g_fc_server.db, sql, fc_db_cb_get_one_bm, 0, &errMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", errMsg);
            sqlite3_free(errMsg);
        }
    }

    TXTRED("### READ FROM DB ENDED ###\n");

    return 0;
}

int fc_db_write_bm(const FC_msg_bm_t *bm)
{
    TXTRED("### WRITE TO DB START ###\n");
    char *sql = calloc(FC_BUFF_SIZE, sizeof(char));
    // base64 encode
    char *buff_src_ip = calloc(FC_BUFF_SIZE, sizeof(char));
    char *buff_dst_ip = calloc(FC_BUFF_SIZE, sizeof(char));
    char *buff_fclist = calloc(FC_BUFF_SIZE, sizeof(char));
    char buff_ski[FC_BUFF_SIZE256] = {0};
    char buff_signature[BUFSIZ] = {0};
    // char buff[BUFSIZ] = {0};
    int cur = 0, i = 0;
    socklen_t socklen;
    struct sockaddr_in *sin = NULL;
    struct sockaddr_in6 *sin6 = NULL;

    if (bm->ipversion == IPV4)
    {
        socklen = sizeof(struct sockaddr_in);
    }
    else if (bm->ipversion == IPV6)
    {
        socklen = sizeof(struct sockaddr_in6);
    }
    else
    {
        printf("THIS IS NOT supported: %d!\n", bm->ipversion);
        return -1;
    }

    // use , to split strings
    // base64 encode src_ip
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i = 0; i < bm->src_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_src_ip + cur, socklen);
        }
        else
        {
            sin6 = (struct sockaddr_in6 *)&(bm->src_ip[i].ip);
            inet_ntop(AF_INET6, &sin6->sin6_addr, buff_src_ip + cur, socklen);
        }
        cur += strlen(buff_src_ip + cur);
        snprintf(buff_src_ip + cur, FC_BUFF_SIZE, "/%d,",
                 bm->src_ip[i].prefix_length);
        cur += strlen(buff_src_ip + cur);
        FC_MEM_CHECK(cur < FC_BUFF_SIZE);
    }
    printf("src-ip: %s\n", buff_src_ip);

    // fc_base64_encode(buff, cur, buff_src_ip);

    // base64 encode dst_ip
    cur = 0;
    for (i = 0; i < bm->dst_ip_num; ++i)
    {
        if (bm->ipversion == IPV4)
        {
            sin = (struct sockaddr_in *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET, &sin->sin_addr, buff_dst_ip + cur, socklen);
        }
        else
        {
            sin6 = (struct sockaddr_in6 *)&(bm->dst_ip[i].ip);
            inet_ntop(AF_INET6, &sin6->sin6_addr, buff_dst_ip + cur, socklen);
        }
        cur += strlen(buff_dst_ip + cur);
        snprintf(buff_dst_ip + cur, FC_BUFF_SIZE,
                 "/%d,", bm->dst_ip[i].prefix_length);
        cur += strlen(buff_dst_ip + cur);
        FC_MEM_CHECK(cur < FC_BUFF_SIZE);
    }
    printf("dst-ip: %s\n", buff_dst_ip);
    // fc_base64_encode(buff, cur, buff_dst_ip);

    // base64 encode fclist
    cur = 0;
    // memset(buff, 0, BUFSIZ);
    for (i = 0; i < bm->fc_num; ++i)
    {
        snprintf(buff_fclist + cur, FC_BUFF_SIZE, "%08X-%08X-%08X-",
                 bm->fclist[i].previous_asn,
                 bm->fclist[i].current_asn,
                 bm->fclist[i].nexthop_asn);
        cur += 8 * 3 + 3;
        for (int j = 0; j < 20; ++j)
        {
            snprintf(buff_fclist + cur, FC_BUFF_SIZE, "%02X",
                     bm->fclist[i].ski[j]);
            cur += 2;
        }
        snprintf(buff_fclist + cur, FC_BUFF_SIZE, "-%02X-%02X-%04X-",
                 bm->fclist[i].algo_id,
                 bm->fclist[i].flags, bm->fclist[i].siglen);
        cur += 8 + 4;

        for (int j = 0; j < bm->fclist[i].siglen; ++j)
        {
            snprintf(buff_fclist + cur, FC_BUFF_SIZE, "%02X",
                     bm->fclist[i].sig[j]);
            cur += 2;
        }
        snprintf(buff_fclist + cur, FC_BUFF_SIZE, ",");
        cur += 1;
        // printf("i: %d, curlen: %d, fclist: %s\n", i, cur, buff_fclist);
        FC_MEM_CHECK(cur < FC_BUFF_SIZE);
    }
    // fc_base64_encode(buff, cur, buff_fclist);

    /*
       printf("buff-srcip: %s\n", buff_src_ip);
       printf("buff-dstip: %s\n", buff_dst_ip);
       printf("buff-fclist: %s\n", buff_fclist);
       */

    // ski
    cur = 0;
    for (int j = 0; j < 20; ++j)
    {
        snprintf(buff_ski + cur, FC_BUFF_SIZE256, "%02X",
                 bm->ski[j]);
        cur += 2;
        FC_MEM_CHECK(cur < FC_BUFF_SIZE256);
    }
    // signature
    cur = 0;
    for (int j = 0; j < bm->siglen; ++j)
    {
        snprintf(buff_signature + cur, BUFSIZ, "%02X",
                 bm->signature[j]);
        cur += 2;
        FC_MEM_CHECK(cur < BUFSIZ);
    }
    printf("signature: %s\n", buff_signature);
    /*
                 "bmversion INT NOT NULL,"
                 "ipversion INT NOT NULL,"
                 "flags INT NOT NULL,"
                 "algoid INT NOT NULL,"
                 "src_ip_num INT NOT NULL,"
                 "dst_ip_num INT NOT NULL,"
                 "fc_num INT NOT NULL,"
                 "siglen INT NOT NULL,"
                 "local_asn INT NOT NULL,"
                 "version INT NOT NULL,"
                 "subversion INT NOT NULL,"
                 "src_ip VARCHAR NOT NULL,"
                 "dst_ip VARCHAR NOT NULL,"
                 "fclist VARCHAR NOT NULL,"
                 "ski CHAR(20) NOT NULL,"
                 "signature VARCHAR NOT NULL)");
                 */
    snprintf(sql, FC_BUFF_SIZE,
             "INSERT INTO fcs (bmversion, ipversion, flags, algoid, "
             "src_ip_num, dst_ip_num, fc_num, siglen, "
             "local_asn, version, subversion, "
             "src_ip, dst_ip, "
             "fclist, ski, signature)"
             "VALUES(%u, %u, %u, %u, "
             "%u, %u, %u, %u, "
             "%u, %u, %u, "
             "'%s', '%s', "
             "'%s', '%s', '%s')",
             bm->bmversion, bm->ipversion, bm->flags, bm->algoid,
             bm->src_ip_num, bm->dst_ip_num, bm->fc_num, bm->siglen,
             bm->local_asn, bm->version, bm->subversion,
             buff_src_ip, buff_dst_ip,
             buff_fclist, buff_ski, buff_signature);
    printf("SQL: %s\n", sql);
    fc_db_exec(g_fc_server.db, sql, fc_db_store_bm_handler, NULL);

    FC_MEM_FREE(sql);
    FC_MEM_FREE(buff_src_ip);
    FC_MEM_FREE(buff_dst_ip);
    FC_MEM_FREE(buff_fclist);

    TXTRED("### WRITE TO DB END ###\n");
    return 0;
}

int fc_db_close(sqlite3 *db)
{
    sqlite3_close(db);
    return 0;
}

void fc_db_init(sqlite3 **db)
{
    char sql[BUFSIZ];

    fc_db_open(db, g_fc_server.fc_db_fname);

    if (g_fc_server.clear_fc_db)
    {
        bzero(sql, BUFSIZ);
        sprintf(sql, "DROP TABLE IF EXISTS fcs;");
        printf("sql: %s\n", sql);
        fc_db_exec(*db, sql, NULL, NULL);
    }

    bzero(sql, BUFSIZ);
    sprintf(sql, "CREATE TABLE fcs("
                 "bmversion INT NOT NULL,"
                 "ipversion INT NOT NULL,"
                 "flags INT NOT NULL,"
                 "algoid INT NOT NULL,"
                 "src_ip_num INT NOT NULL,"
                 "dst_ip_num INT NOT NULL,"
                 "fc_num INT NOT NULL,"
                 "siglen INT NOT NULL,"
                 "local_asn INT NOT NULL,"
                 "version INT NOT NULL,"
                 "subversion INT NOT NULL,"
                 "src_ip VARCHAR NOT NULL,"
                 "dst_ip VARCHAR NOT NULL,"
                 "fclist VARCHAR NOT NULL,"
                 "ski CHAR(20) NOT NULL,"
                 "signature VARCHAR NOT NULL)");
    printf("sql: %s\n", sql);
    fc_db_exec(*db, sql, NULL, NULL);
    // bzero(sql, 1024);
    // sprintf(sql, "DELETE FROM relation WHERE asn = %u", asn);
    // fc_db_exec(*db, sql, NULL, NULL);
}
