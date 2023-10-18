LIBSDIR = $(shell ls libs | grep -v Makefile)
LIBS_DIR = $(foreach i,$(LIBSDIR),libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))
SRCs  = fcserver.c libs/diaglib/libdiag.c libs/baselib/libstring.c
SRCs += libs/cJSONlib/cJSON.c libs/ncslib/libncs.c
SRCs += libs/htablelib/libhtable.c libs/baselib/liblist.c
# SRCs += libjhash.c

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR) -I. -I../ -I../.. -I../lib
LFLAGS += -lcrypto -lsqlite3 -lm

all: server
	sudo bin/server -a 10

server:
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$(@) $(SRCs) $(LFLAGS)

setup:
	@mkdir /etc/frr
	sudo cp -r assets/* /etc/frr

clean:
	@rm -f bin/*

