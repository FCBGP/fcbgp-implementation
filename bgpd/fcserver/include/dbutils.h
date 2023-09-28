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

/* Open database */
int db_open(sqlite3 **db, const char *dbname);
/* Execute SQL statement */
int db_exec(sqlite3 *db, const char *sql, void *data,
        int (*cb)(void *data, int argc, char **argv, char **az_col_name));
/* Close DB */
int db_close(sqlite3 *db);
void init_db();
#endif // DBUTILS_H
