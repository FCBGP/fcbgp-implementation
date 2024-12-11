/**
 * @file test-read.c
 * @author basilguo@163.com
 * @brief select * from fcs;
 * @version 0.0.1
 * @date 2024-09-02
 *
 * @copyright Copyright (c) 2021 - 2024
 */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include "defines.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

    static int setup(sqlite3** db)
    {
        int rc = sqlite3_open("/etc/frr/assets/fc.db", db);
        if (rc)
        {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
            return 1;
        }
        return 0;
    }

    static void teardown(sqlite3* db) { sqlite3_close(db); }

    static int total_num = 0;

    static int cb_get_cnt(void* data, int argc, char** argv, char** azColName)
    {
        for (int i = 0; i < argc; i++)
        {
            if (argv[i])
            {
                printf("%s = %s\n", azColName[i], argv[i]);
                total_num = atoi(argv[0]);
            }
            else
            {
                printf("%s = %s\n", azColName[i], "NULL");
                total_num = 0;
            }
        }
        printf("\n");

        return 0;
    }

    static int cb_get_one_bm(void* data, int argc, char** argv,
                             char** azColName)
    {
        for (int i = 0; i < argc; i++)
        {
            printf("i: %d %s = %s\n", i, azColName[i],
                   argv[i] ? argv[i] : "NULL");
        }
        printf("\n");

        return 0;
    }

    static int test01(sqlite3* db)
    {
        int rc = 0;
        char* errMsg = NULL;
        const char* sql_cnt = "SELECT COUNT(*) FROM fcs;";
        const char* sql_template = "SELECT * FROM fcs LIMIT 1 OFFSET %d;";

        rc = sqlite3_exec(db, sql_cnt, cb_get_cnt, 0, &errMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", errMsg);
            sqlite3_free(errMsg);
        }

        while (total_num-- > 0)
        {
            char sql[1024] = {0};
            sprintf(sql, sql_template, total_num);
            printf("idx: %d, sql: %s\n", total_num, sql);
            rc = sqlite3_exec(db, sql, cb_get_one_bm, 0, &errMsg);
            if (rc != SQLITE_OK)
            {
                fprintf(stderr, "SQL error: %s\n", errMsg);
                sqlite3_free(errMsg);
            }
        }

        return 0;
    }

    int main(void)
    {

        sqlite3* db;
        setup(&db);
        test01(db);
        teardown(db);

        return 0;
    }

#ifdef __cplusplus
}
#endif /* __cplusplus */
