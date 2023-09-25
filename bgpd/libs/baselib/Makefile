ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := base
S := libmem.c libstring.c liblist.c librqueue.c libdpa.c libcrc32.c libbase64.c libchecksum.c libtty.c
H := libmem.h libstring.h liblist.h librqueue.h libdpa.h libcrc32.h libbase64.h libchecksum.h libtty.h
X :=

H += libtypes.h libendian.h libmutex.h libatomic.h libatomic64.h libcondition.h
H += librwlock.h libspinlock.h libjhash.h libphdr.h libthread.h

# $(eval $(call add_target_library,name,sources,cflags,type,headers))
$(eval $(call add_target_library,$(T),$(S),$(X),static,$(H)))

# $(eval $(call add_host_library,name,sources,cflags,type,headers))
$(eval $(call add_host_library,$(T),$(S),$(X),static,$(H)))

