#ifndef DBUTILS_H
#define DBUTILS_H
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

#define DB_NAME "assets/fc.db"

/* Open database */
int db_open(sqlite3 **db, const char *dbname);

/* db handler/callback */
int db_store_bm_handler(void *data, int argc, char **argv,
        char **az_col_name);
int db_select_bm_handler(void *data, int argc, char **argv,
        char **az_col_name);
/* Execute SQL statement */
int db_exec(sqlite3 *db, const char *sql,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name),
        void *data);
/* Close DB */
int db_close(sqlite3 *db);
void init_db(sqlite3 **db);
#endif // DBUTILS_H
