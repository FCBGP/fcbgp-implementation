ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ut_libnio
S := ut_libnio.c
X :=
Y := -lnio -lsysmgr -ldiag -lbase -lpthread

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))

T := my_scanner
S := my_scanner.c pkt6.c
X :=
Y := -g -lnio -lsysmgr -ldiag -lbase -lpthread -L/usr/lib64/mysql -lmysqlclient

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))
