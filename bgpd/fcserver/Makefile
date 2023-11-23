LIBSDIR = $(shell cd libs; /bin/ls -d */)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))

SRC_libs = libs/diaglib/libdiag.c libs/baselib/libstring.c
SRC_libs += libs/htablelib/libhtable.c libs/baselib/liblist.c
SRC_libs += libs/cJSONlib/cJSON.c libs/ncslib/libncs.c

SRC_fcs  = fcserver.c

CC := gcc

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR)
LFLAGS_fcs += -lcrypto -lsqlite3 -lm

all: fcserver
	sudo bin/fcserver

fcserver: $(SRC_fcs)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$@ $(SRC_fcs) $(SRC_libs) $(LFLAGS) $(LFLAGS_fcs)

setup:
	@mkdir -p /etc/frr/assets
	sudo cp -r assets /etc/frr

clean:
	@rm -f bin/*

.PHONY: clean all setup
