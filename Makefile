FCSDIR ?= $(shell pwd)/fcserver
FRRDIR ?= $(shell pwd)/frr

all: fcs-build frr-build

frr-bootstrap:
	cd ${FRRDIR}; ./bootstrap.sh

frr-config:
	cd ${FRRDIR}; ./configure \
		--prefix=/usr \
		--includedir=\${prefix}/include \
		--bindir=\${prefix}/bin \
		--sbindir=\${prefix}/lib/frr \
		--libdir=\${prefix}/lib/frr \
		--libexecdir=\${prefix}/lib/frr \
		--localstatedir=/var/run/frr \
		--sysconfdir=/etc/frr \
		--with-moduledir=\${prefix}/lib/frr/modules \
		--enable-configfile-mask=0640 \
		--enable-logfile-mask=0640 \
		--enable-snmp=agentx \
		--enable-multipath=64 \
		--enable-user=frr \
		--enable-group=frr \
		--enable-vty-group=frrvty \
		--enable-dev-build \
		--disable-babeld \
		--disable-doc \
		--disable-mpls \
		--disable-eigrpd \
		--disable-fabricd \
		--disable-isisd \
		--disable-ldpd \
		--disable-ospfd \
		--disable-ospf6d \
		--disable-ospfapi \
		--disable-ospfclient \
		--disable-pimd \
		--disable-ripd \
		--disable-ripngd \
		--with-pkg-git-version \
		--with-crypto=openssl \
		--with-pkg-extra-version=-FCBGPVersion

frr-build:
	cd ${FRRDIR}; make

frr-install:
	cd ${FRRDIR}; make install; ldconfig

frr-install-configurations:
	install -m 775 -o frr -g frr -d /var/log/frr
	install -m 775 -o frr -g frrvty -d /usr/local/etc
	install -m 640 -o frr -g frrvty ${FRRDIR}/tools/etc/frr/vtysh.conf /usr/local/etc/vtysh.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/frr.conf /usr/local/etc/frr.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/daemons.conf /usr/local/etc/daemons.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/daemons /usr/local/etc/daemons
	install -m 644 ${FRRDIR}/tools/frr.service /etc/systemd/system/frr.service

fcs-build:
	cd ${FCSDIR}; make build

fcs-setup:
	mkdir -p /etc/frr/assets
	cp -r ${FCSDIR}/assets/* /etc/frr/assets
	chmod +r /etc/frr/assets/*.key

fcs-clean:
	@rm -f ${FCSDIR}/build/*

fcs-run:
	${FCSDIR}/build/fcserver

.PHONY: all
.PHONY: fcs-build fcs-setup fcs-clean fcs-run
.PHONY: frr-bootstrap frr-config frr-build frr-install frr-install-configurations

