all: build
	sudo build/fcserver

build: CMakeLists.txt
	cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build
	cmake --build build

release: CMakeLists.txt
	cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
	cmake --build build

run:
	sudo build/fcserver

setup:
	sudo mkdir -p /etc/frr/assets
	sudo cp -r assets/* /etc/frr/assets
	sudo chmod +r /etc/frr/assets/*.key

clean:
	@rm -rf build

.PHONY: clean all build run setup
