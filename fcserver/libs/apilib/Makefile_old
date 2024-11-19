ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := reqapi
S += webreq.c gen_addr_req.c NIDTGA_snmp_req.c tracereq.c
H := reqapi.h libapi.h
X :=

# $(eval $(call add_host_library,name,sources,cflags,type,headers))
$(eval $(call add_target_library,$(T),$(S),$(X),static,$(H)))
