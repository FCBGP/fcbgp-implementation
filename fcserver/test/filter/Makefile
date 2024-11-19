filter: filter.c
	@mkdir -p bin
	gcc -g -o bin/filter filter.c -lnftnl -lmnl
	sudo bin/filter ip filter OUTPUT; sudo iptables -t filter -L -v
	sudo iptables -t filter -D OUTPUT 1

clean:
	-rm -rf bin/*
