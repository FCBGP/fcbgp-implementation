LIBSDIR = $(shell ls libs | grep -v Makefile)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))

SRCs  = fcserver.c fcconfig.c dbutils.c sigutils.c hashutils.c

SRC_libs  = libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/cJSONlib/cJSON.c libs/ncslib/libncs.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR) -I. -I../ -I../.. -I../lib
LFLAGS += -lcrypto -lsqlite3 -lm

all: server
	sudo bin/server

server:
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$(@) $(SRCs) $(SRC_libs) $(LFLAGS)

setup:
	@sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets

clean:
	@rm -f bin/*

