ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := food
S := food.c foorep.c
X :=
Y := -lrep -llistener -ldispatch -lsysmgr -lsymtable -lhtable -lmsgpack -lstream -lcmd -lmpse -lmbs -lcache -lbase -ldiag -lmd5 -lpthread -lrt

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))

T := foocmd
S := foocmd.c fooreq.c
X :=
Y := -lreq -lsymtable -lhtable -lmsgpack -lstream -lcmd -lmbs -lcache -lbase -ldiag -lmd5 -lpthread

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))
