LIBSDIR := $(shell cd libs; /bin/ls -d */)
LIBS_DIR := $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR := $(foreach i,$(LIBS_DIR),-I$(i))
INCS_DIR += -Iinclude $(shell pkg-config --cflags python3)

SRC_fcs := fcserver.c fcfront.c fcconfig.c
SRC_messages := keyinfo.c bm.c topo.c acl.c
SRC_utils := dbutils.c sigutils.c hashutils.c pyutils.c strutils.c
SRC_DIR_fcs := $(foreach i,$(SRC_fcs),src/$(i))
SRC_DIR_messages := $(foreach i,$(SRC_messages), src/messages/$(i))
SRC_DIR_utils := $(foreach i,$(SRC_utils), src/utils/$(i))
SRC_DIR := $(SRC_DIR_fcs) $(SRC_DIR_messages) $(SRC_DIR_utils)

SRC_libs := libs/linenoise/linenoise.c
SRC_libs += libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/cJSONlib/cJSON.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c
SRC_libs += libs/baselib/libcrc32.c
CC := gcc

CFLAGS += $(shell pkg-config --libs python3)
CFLAGS += -g -Wall $(INCS_DIR) -Wno-deprecated-declarations
LDFLAGS_fcs += -lcrypto -lsqlite3 -lm -lpython3.10 -lpthread

all: server
	sudo bin/server

run:
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
