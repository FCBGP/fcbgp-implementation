ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := listener
S := liblistener.c
H := liblistener.h

ifeq ("$(PRJ_SUPPORT_DEBUG)","YES")
X := -DLISTENER_DEBUG
endif

# $(eval $(call add_target_library,name,sources,cflags,type,headers))
$(eval $(call add_target_library,$(T),$(S),$(X),static,$(H)))

# $(eval $(call add_host_library,name,sources,cflags,type,headers))
$(eval $(call add_host_library,$(T),$(S),$(X),static,$(H)))

#$(eval $(call add_subdirectory,.ut))
