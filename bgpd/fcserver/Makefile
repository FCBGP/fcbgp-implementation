INC_DIR = -Iinclude -I..
LIBS_DIR = $(shell ls ../libs | grep -v Makefile)
LIB_DIR += $(foreach i,$(LIBS_DIR),../libs/$(i))
INC_DIR += $(foreach i,$(LIB_DIR),-I$(i))
LFLAGS += -Llib

CFLAGS += -g -Wall

TRD_PARTY_LIB += lib/libcJSON.so lib/libncs.so lib/libdiag.so
TRD_PARTY_LIB += lib/libhtable.so

TRD_PARTY_LIBARY += -lcJSON -lncs -lm -ldiag -lhtable -lsqlite3 -lpthread
TRD_PARTY_LIBARY += -lcrypto

SERVER_SRCS += src/main.c src/json_utils.c src/hashtable_utils.c
SERVER_SRCS += src/dbutils.c src/sigutils.c src/server_utils.c
SERVER_SRCS += src/bc_server_utils.c src/bgpd_server_utils.c

all: bin/server
	./bin/server -a 10

bin/test_send_fclist: src/test_send_fclist.c
	mkdir -p bin/
	gcc $(CFLAGS) -o $@ $? -Iinclude $(LFLAGS)

bin/server: $(SERVER_SRCS) $(TRD_PARTY_LIB)
	mkdir -p bin/
	gcc $(CFLAGS) -o $@ $? $(INC_DIR) $(LFLAGS) $(TRD_PARTY_LIBARY)

bin/test_ht: src/test_ht.c $(TRD_PARTY_LIB)
	mkdir -p bin/
	gcc $(CFLAGS) -o $@ $? $(INC_DIR) $(LFLAGS) $(TRD_PARTY_LIBARY)

bin/test_ht2: src/hashtable_utils.c $(TRD_PARTY_LIB)
	mkdir -p bin/
	gcc $(CFLAGS) -DTEST_MAIN -o $@ $? $(INC_DIR) $(LFLAGS) $(TRD_PARTY_LIBARY)

lib/libcJSON.so: ../libs/cJSONlib/cJSON.c
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

lib/libncs.so: ../libs/ncslib/libncs.c
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

lib/libdiag.so: ../libs/diaglib/libdiag.c ../libs/baselib/libstring.c
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

lib/libhtable.so: ../libs/htablelib/libhtable.c ../libs/baselib/liblist.c
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

clean:
	@rm -rf bin/*
	@rm -rf lib/*

.PHONY: clean distclean
