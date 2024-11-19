LIBSDIR = $(shell ls ../../libs | grep -v Makefile)
LIBS_DIR = $(foreach i,$(LIBSDIR),../../libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))

SRC_libs  = ../../libs/diaglib/libdiag.c ../../libs/baselib/libstring.c
SRC_libs += ../../libs/ncs6lib/libncs6.c

CFLAGS += -DTEST_MAIN
CFLAGS += -g -Wall $(INCS_DIR) -I. -I../ -I../.. -I../lib
LFLAGS += -lcrypto -lsqlite3 -lm

all: client server server64

server: server.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$(@) $< $(SRC_libs) $(LFLAGS)


server64: server46.c
	@mkdir -p bin
	gcc -g -o bin/$@ $<

client: client.c
	@mkdir -p bin
	gcc -g -o bin/$@ $<

