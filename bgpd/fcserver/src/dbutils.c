/**
 * @file dbutils.c
 * @author basilguo@163.com
 * @brief
 * @version 0.1
 * @date 2023-01-18
 *
 * @copyright Copyright (c) 2021 - 2023
 *
 */

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include "libdiag.h"
#include "utils.h"
#include "dbutils.h"

/************ DB start *************/
/* Open database */
int db_open(sqlite3 **db, const char *dbname)
{
    if (sqlite3_open(dbname, db) != SQLITE_OK)
    {
        DIAG_ERROR("Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(0);
    }
    else
    {
        DIAG_DEBUG("Opened database successfully\n");
    }

    return 0;
}

int db_store_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

int db_select_bm_handler(void *data, int argc, char **argv,
        char **az_col_name)
{
    return 0;
}

/* Execute SQL statement */
int db_exec(sqlite3 *db, const char *sql,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name),
        void *data)
{
    char *zErrMsg = 0;
    int rc;
    rc = sqlite3_exec(db, sql, cb, data, &zErrMsg);
    if (rc != SQLITE_OK)
    {
        DIAG_ERROR("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
    else
    {
        DIAG_DEBUG("Operation done successfully\n");
    }

    return 0;
}

/* Close DB */
int db_close(sqlite3 *db)
{
    sqlite3_close(db);
    return 0;
}

void init_db(sqlite3 **db)
{
    char sql[BUFSIZ];

    db_open(db, DB_NAME);
    bzero(sql, BUFSIZ);
    sprintf(sql, "DROP TABLE IF EXISTS fcs;");
    DIAG_DEBUG("sql: %s\n", sql);
    db_exec(*db, sql, NULL, NULL);

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
            "signature CHAR(1024) NOT NULL,"
           );
    DIAG_DEBUG("sql: %s\n", sql);
    db_exec(*db, sql, NULL, NULL);
    // bzero(sql, 1024);
    // sprintf(sql, "DELETE FROM relation WHERE asn = %u", asn);
    // db_exec(*db, sql, NULL, NULL);
}
