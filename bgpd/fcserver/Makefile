INC_DIR = -Iinclude -I/usr/local/melon/include
LIBS_DIR = $(shell ls ../libs | grep -v Makefile)
LIB_DIR += $(foreach i,$(LIBS_DIR),../libs/$(i))
INC_DIR += $(foreach i,$(LIB_DIR),-I$(i))
LFLAGS += -Llib -L/usr/local/melon/lib

CFLAGS += -g -Wall

TRD_PARTY_LIB += lib/libcJSON.so lib/libncs.so lib/libdiag.so
TRD_PARTY_LIBARY += -lcJSON -lncs -lmelon -lm -ldiag

bin/server: src/server.c src/json_utils.c $(TRD_PARTY_LIB)
	mkdir -p bin/
	gcc $(CFLAGS) -o $@ $? $(INC_DIR) $(LFLAGS) $(TRD_PARTY_LIBARY)

lib/libcJSON.so: ../libs/cJSONlib/cJSON.c
	mkdir -p lib/
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

lib/libncs.so: ../libs/ncslib/libncs.c
	mkdir -p lib
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

lib/libdiag.so: ../libs/diaglib/libdiag.c ../libs/baselib/libstring.c
	mkdir -p lib
	gcc $(CFLAGS) -o $@ -fPIC -shared $? $(INC_DIR)

clean:
	@rm -rf bin/*
	@rm -rf lib

.PHONY: clean distclean
