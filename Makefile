FCSDIR ?= $(shell pwd)/fcserver
FRRDIR ?= $(shell pwd)/frr

# It simplifies the usual compilation.
# It generated the debug version of FCServer and FRR.
all: fcs-build frr-build

# create group and user
frr-setup:
	groupadd -r -g 92 frr
	groupadd -r -g 85 frrvty
	adduser --system --ingroup frr --home /var/run/frr/ \
		   --gecos "FRR suite" --shell /sbin/nologin frr
	usermod -a -G frrvty frr

# bootstrap, common procedure of autotools
frr-bootstrap:
	cd ${FRRDIR}; ./bootstrap.sh

# configure, common procedure of autotools
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
		--enable-rpki \
		--disable-babeld \
		--disable-doc \
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

# generate frr programs
frr-build:
	cd ${FRRDIR}; make

# install frr, please run with root privilege
frr-install:
	cd ${FRRDIR}; make install; ldconfig

# clean frr files for re-generating
frr-clean:
	cd ${FRRDIR}; make clean

# clean all files
frr-distclean:
	cd ${FRRDIR}; make distclean

# frr configurations
frr-install-configurations:
	install -m 775 -o frr -g frr -d /var/log/frr
	install -m 775 -o frr -g frrvty -d /usr/local/etc
	install -m 640 -o frr -g frrvty ${FRRDIR}/tools/etc/frr/vtysh.conf /usr/local/etc/vtysh.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/frr.conf /usr/local/etc/frr.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/daemons.conf /usr/local/etc/daemons.conf
	install -m 640 -o frr -g frr ${FRRDIR}/tools/etc/frr/daemons /usr/local/etc/daemons
	install -m 644 ${FRRDIR}/tools/frr.service /etc/systemd/system/frr.service

# release version of FCServer
fcs-release:
	cmake -DCMAKE_BUILD_TYPE=Release -S ${FCSDIR} -B ${FCSDIR}/build
	cmake --build ${FCSDIR}/build

# debug version of FCServer
fcs-build:
	cmake -DCMAKE_BUILD_TYPE=Debug -S ${FCSDIR} -B ${FCSDIR}/build
	cmake --build ${FCSDIR}/build

# FCServer configurations
fcs-setup:
	mkdir -p /etc/frr/assets
	cp -r ${FCSDIR}/assets/* /etc/frr/assets
	chmod +r /etc/frr/assets/*.key

# clean all files
fcs-clean:
	@rm -rf ${FCSDIR}/build/

# running FCServer
fcs-run:
	${FCSDIR}/build/fcserver

.PHONY: all
.PHONY: fcs-build fcs-setup fcs-clean fcs-run
.PHONY: frr-bootstrap frr-config frr-build frr-install frr-install-configurations

