LIBSDIR = $(shell cd libs; /bin/ls -d */)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))

SRC_fcs  = fcserver.c fcconfig.c dbutils.c sigutils.c hashutils.c

SRC_libs  = libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/cJSONlib/cJSON.c libs/ncs6lib/libncs6.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c
CC := gcc

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR)
LFLAGS_fcs += -lcrypto -lsqlite3 -lm

all: server
	sudo bin/server

server: $(SRC_fcs)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$@ $(SRC_fcs) $(SRC_libs) $(LFLAGS) $(LFLAGS_fcs)

setup:
	@sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets

clean:
	@rm -f bin/*

.PHONY: clean all setup
