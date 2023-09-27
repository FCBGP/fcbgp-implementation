TARGET=bin/test_sha256 bin/test_ecdsa bin/test_sqlite3
TARGET+=bin/test_melon bin/test_libhtable
TARGET+=bin/read_asn


all: $(TARGET)

run: $(TARGET)
	for prog in $(TARGET); do \
   		$${prog}; \
	   	echo "==================";\
	done


bin/test_sha256: test_sha256.c
	mkdir -p bin
	gcc -g -o $@ $? -lssl -lcrypto

bin/test_ecdsa: test_ecdsa.c
	mkdir -p bin
	gcc -g -o $@ $? -lssl -lcrypto

bin/test_sqlite3: test_sqlite3.c
	mkdir -p bin
	gcc -g -o $@ $? -lsqlite3

bin/read_asn: read_asn.c
	mkdir -p bin
	gcc -g -o $@ $? ../libs/cJSONlib/cJSON.c -I../libs/cJSONlib -lm \
		-I/usr/local/melon/include -L/usr/local/melon/lib -lmelon

bin/test_melon: test_melon.c
	mkdir -p bin
	gcc -g -o $@ $? -I/usr/local/melon/include -L /usr/local/melon/lib -lmelon

bin/test_libhtable: test_libhtable.c
	mkdir -p bin
	gcc -g -o $@ $? ../libs/cJSONlib/cJSON.c -I../libs/cJSONlib -lm \
		../libs/htablelib/libhtable.c -I../libs/htablelib \
		-I../libs/baselib \

clean:
	-rm bin/*
