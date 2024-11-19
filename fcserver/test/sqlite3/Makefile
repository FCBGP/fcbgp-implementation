LIBSDIR = $(shell cd ../../libs; /bin/ls -d */)
LIBS_DIR = $(foreach i,$(LIBSDIR),../../libs/$(i))
INCS_DIR = $(foreach i,$(LIBS_DIR),-I$(i))

INCS_DIR += -I../../include
INCS_DIR += $(shell pkg-config --cflags sqlite3)
INCS_DIR += $(shell pkg-config --cflags python3-embed)

CFLAGS += -g -O0 -ggdb -Wall ${INCS_DIR}

LDFLAGS += $(shell pkg-config --libs sqlite3)
LDFLAGS += $(shell pkg-config --libs python3-embed)



test-read: test-read.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$@ $? $(LDFLAGS) $(LDLIBS)
