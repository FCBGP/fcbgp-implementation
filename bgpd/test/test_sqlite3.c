/********************************************************************************
* File Name:    test_sqlite3.c
* Author:       basilguo@163.com
* Created Time: 2023-09-25 09:28:57
* Description:
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

int insert_cb(void* msg, int argc, char **argv, char **az_col_name)
{
    printf("msg: %s\n", (char*)msg);
    return 0;
}

int select_cb(void* msg, int argc, char **argv, char **az_col_name)
{
    int i = 0;

    printf("msg: %s\n", (char*)msg);
    for (i=0; i<argc; i++)
    {
        printf("%s = %s\n", az_col_name[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");

    return 0;
}

int main(int argc, char *argv[])
{
    // 1. open db
    sqlite3 *db = NULL;
    char *err_msg = NULL;
    char *msg = "hello world";
    int ret = 0;

    if ((ret = sqlite3_open("test.db", &db)) != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open db:%s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    // 2. create table
    // 3. insert
    char *sql = "DROP TABLE IF EXISTS Cars;"
        "CREATE TABLE Cars(Id INT, Name TEXT, Price INT);"
        "INSERT INTO Cars VALUES(1, 'Audi', 52642);"
        "INSERT INTO Cars VALUES(2, 'Mercedes', 57127);"
        "INSERT INTO Cars VALUES(3, 'Skoda', 9000);"
        "INSERT INTO Cars VALUES(4, 'Volvo', 29000);"
        "INSERT INTO Cars VALUES(5, 'Bentley', 350000);"
        "INSERT INTO Cars VALUES(6, 'Citroen', 21000);"
        "INSERT INTO Cars VALUES(7, 'Hummer', 41400);"
        "INSERT INTO Cars VALUES(8, 'Volkswagen', 21600);";
    ret = sqlite3_exec(db, sql, insert_cb, msg, &err_msg);
    if (ret != SQLITE_OK)
    {
        fprintf(stderr, "SQL error:%s\n", err_msg);
        goto cleanup;
    }

    // 4. select
    sql = "SELECT * FROM Cars";
    ret = sqlite3_exec(db, sql, select_cb, msg, &err_msg);
    if (ret != SQLITE_OK)
    {
        fprintf(stderr, "SQL error:%s\n", err_msg);
        goto cleanup;
    }

    // 5. close db
cleanup:
    if (err_msg != NULL)
    {
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);

    return ret;
}
