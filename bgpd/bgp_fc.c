/********************************************************************************
* File Name:    bgp_fc.c
* Author:       basilguo@163.com
* Created Time: 2023-09-25 10:09:53
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "lib/zlog.h"
#include "bgp_fc.h"

int select_cb(void *args, int argc, char **argv, char **az_col_name)
{
    return 0;
}

sqlite3* open_db()
{
    sqlite3 *db = NULL;
    int ret = 0;

    ret = sqlite3_open("fc.db", &db);
    if (ret != SQLITE_OK)
    {
        zlog_err("ERROR! Cannot open db: %s\n", sqlite3_errmsg(db));
    }

    return ret;
}

int create_table()
{
    sqlite3* db = NULL;
    char *err_msg = NULL;
    char *sql = "DROP TABLE IF EXISTS fcs;"
        "CREATE TABLE fcs(id INT PRIMARY KEY NOT NULL,"
        "asn INT NOT NULL,"
        "action INT NOT NULL,"
        "ip_version INT NOT NULL,"
        "src_size INT NOT NULL,"
        "dst_size INT NOT NULL,"
        "fc_size INT NOT NULL,"
        "version INT NOT NULL,"
        "sub_version INT NOT NULL,"
        "as_path CHAR(1024) NOT NULL,"
        "src_ip CHAR(1024) NOT NULL,"
        "dst_ip CHAR(1024) NOT NULL,"
        "fc_list CHAR(2048) NOT NULL,"
        "signature_n CHAR(1024) NOT NULL,"
        "new_fc_size INT,"
        "new_asn INT,"
        "new_fc_list CHAR(1024),"
        "new_sig CHAR(1024));";

    ret = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (ret != SQLITE_OK)
    {
        zlog_err("SQL error:%s\n", err_msg);
        goto cleanup;
    }
}

int insert_fc(sqlite3* db, FCList_t *fclist)
{
    return 0;
}

void close_db(sqlite3* db, char *err_msg)
{
    if (err_msg != NULL)
    {
        sqlite3_free(err_msg);
        err_msg = NULL;
    }

    sqlite3_close(db);
    db = NULL;
}

int send_to_node()
{
    return 0;
}
