ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ut_libcmd
S := ut_libcmd.c
X :=
Y := -lcmd -lbase

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))

T := ut_rldemo
S := ut_rldemo.c
X :=
Y := -lreadline -ltinfo

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))
