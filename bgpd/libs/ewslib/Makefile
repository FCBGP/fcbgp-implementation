ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

T := ews
S := libews.c
H := libews.h
X := -Wextra -Wshadow -Wformat-security -Winit-self -Wmissing-prototypes -DLINUX -DUSE_WEBSOCKET -DUSE_STACK_SIZE=102400

ifeq ("$(PRJ_SUPPORT_IPV6)","YES")
X += -DUSE_IPV6
endif

ifeq ("$(PRJ_SUPPORT_SSL)","YES")
X += -DNO_SSL_DL
else
X += -DNO_SSL
endif

# $(eval $(call add_target_library,name,sources,cflags,type,headers))
$(eval $(call add_target_library,$(T),$(S),$(X),static,$(H)))

# $(eval $(call add_host_library,name,sources,cflags,type,headers))
$(eval $(call add_host_library,$(T),$(S),$(X),static,$(H)))
