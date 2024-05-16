LIBSDIR = $(shell cd libs; /bin/ls -d */)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))
INCS_DIR += -Iinclude -I/usr/include/python3.10

SRC_fcs  = fcserver.c fcconfig.c dbutils.c sigutils.c hashutils.c
SRC_DIR = $(foreach i,$(SRC_fcs),src/$(i))

SRC_libs  = libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/cJSONlib/cJSON.c libs/ncs6lib/libncs6.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c
CC := gcc

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR)
LFLAGS_fcs += -lcrypto -lsqlite3 -lm -lpython3.10

all: server
	sudo bin/server

server: $(SRC_DIR)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$@ $(SRC_DIR) $(SRC_libs) $(LFLAGS) $(LFLAGS_fcs)

setup:
	sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets
	sudo chmod +r /etc/frr/assets/*.key

clean:
	@rm -f bin/*

.PHONY: clean all setup
