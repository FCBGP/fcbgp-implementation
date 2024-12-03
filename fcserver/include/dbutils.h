/********************************************************************************
 * File Name:    dbutils.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 08:47:56
 * Description:  DB UTILS
 ********************************************************************************/

#ifndef DBUTILS_H
#define DBUTILS_H

#include "defines.h"
#include "libdiag.h"
#include <sqlite3.h>

extern int fc_db_open(sqlite3** db, const char* dbname);
extern int fc_db_close(sqlite3* db);
extern void fc_db_init(sqlite3** db);
extern int fc_db_store_bm_handler(void* data, int argc, char** argv,
                                  char** az_col_name);
extern int fc_db_select_bm_handler(void* data, int argc, char** argv,
                                   char** az_col_name);
extern int fc_db_write_bm(const FC_msg_bm_t* bm);
extern int fc_db_exec(sqlite3* db, const char* sql,
                      int (*cb)(void* data, int argc, char** argv,
                                char** az_col_name),
                      void* data);
extern FC_msg_bm_t* fc_db_read_bms(int* bmnum);

#endif // DBUTILS_H
