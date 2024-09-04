LIBSDIR = $(shell cd libs; /bin/ls -d */)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))
INCS_DIR += -Iinclude -I/usr/include/python3.10
INCS_DIR += -I/usr/local/melon/include/

SRC_fcs  = fcserver.c fcconfig.c dbutils.c sigutils.c hashutils.c pyutils.c strutils.c
SRC_DIR = $(foreach i,$(SRC_fcs),src/$(i))

SRC_libs  = libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/cJSONlib/cJSON.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c
SRC_libs += libs/baselib/libcrc32.c
CC := gcc

CFLAGS += -L/usr/lib/python3.10/config-3.10-x86_64-linux-gnu -L/usr/local/melon/lib/
CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR) -Wno-deprecated-declarations
LDFLAGS_fcs += -lcrypto -lsqlite3 -lm -lpython3.10 -lmelon

all: server
	sudo bin/server

server: $(SRC_DIR)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$@ $(SRC_DIR) $(SRC_libs) $(LFLAGS) $(LDFLAGS_fcs)

setup:
	sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets
	sudo chmod +r /etc/frr/assets/*.key

clean:
	@rm -f bin/*

.PHONY: clean all setup
