ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ut_listener
S := ut_listener.c
X := -g
Y := -llistener -ldiag -lcut -lcmd -lbase -ldl -lrt

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))
