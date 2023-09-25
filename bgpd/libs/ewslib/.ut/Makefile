ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ut_libews
S := ut_libews.c
X := -DLINUX -DUSE_WEBSOCKET
Y := -lews -ldiag -lbase -lpthread

ifeq ("$(PRJ_SUPPORT_IPV6)","YES")
X += -DUSE_IPV6
endif

ifeq ("$(PRJ_SUPPORT_SSL)","YES")
X += -DNO_SSL_DL
Y += -lssl -lcrypto
else
X += -DNO_SSL
endif

Y += -lrt -ldl -lz

# $(eval $(call add_target_binary,name,sources,cflags,lflags))
$(eval $(call add_target_binary,$(T),$(S),$(X),$(Y)))

# $(eval $(call add_host_binary,name,sources,cflags,lflags))
$(eval $(call add_host_binary,$(T),$(S),$(X),$(Y)))

