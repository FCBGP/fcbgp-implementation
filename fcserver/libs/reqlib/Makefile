ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := req
S := libreq.c
H := libreq.h
X :=

# $(eval $(call add_target_library,name,sources,cflags,type,headers))
$(eval $(call add_target_library,$(T),$(S),$(X),static,$(H)))

# $(eval $(call add_host_library,name,sources,cflags,type,headers))
$(eval $(call add_host_library,$(T),$(S),$(X),static,$(H)))

#$(eval $(call add_subdirectory,.ut))
