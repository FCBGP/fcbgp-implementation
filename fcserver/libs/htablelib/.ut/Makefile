ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ut_libhtable
S := ut_libhtable.c
X :=
Y := -lhtable -lpthread

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))
