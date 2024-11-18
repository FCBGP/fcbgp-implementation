all: build
	sudo build/fcserver

build: CMakeLists.txt
	cmake -S . -B build
	cmake --build build

run:
	sudo build/fcserver

setup:
	sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets
	sudo chmod +r /etc/frr/assets/*.key

clean:
	@rm -f bin/*

.PHONY: clean all build run setup
