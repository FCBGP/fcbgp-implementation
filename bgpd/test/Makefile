all: bin/test_sha256 bin/test_ecdsa

run: bin/test_sha256 bin/test_ecdsa
	./bin/test_sha256
	@echo "============================================================================="
	./bin/test_ecdsa


bin/%: %.c
	mkdir -p bin
	gcc -g -o $@ $? -lssl -lcrypto

clean:
	-rm bin/*
