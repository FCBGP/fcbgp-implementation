ROOTDIR ?= $(shell while true; do [ -f common.mk ] && break; p="../$$p"; [ `pwd` = "/" ] && p="" && break; cd ..; done; pwd)
include $(ROOTDIR)/common.mk

$(eval $(call add_subdirectory,baselib))
$(eval $(call add_subdirectory,cmdlib))
$(eval $(call add_subdirectory,mpselib))
$(eval $(call add_subdirectory,md5lib))
$(eval $(call add_subdirectory,sha256lib))
$(eval $(call add_subdirectory,diaglib))
$(eval $(call add_subdirectory,cachelib))
$(eval $(call add_subdirectory,mbslib))
$(eval $(call add_subdirectory,sysmgrlib))

$(eval $(call add_subdirectory,streamlib))
$(eval $(call add_subdirectory,msgpacklib))
$(eval $(call add_subdirectory,sessmgrlib))
$(eval $(call add_subdirectory,listenerlib))
$(eval $(call add_subdirectory,dispatchlib))
$(eval $(call add_subdirectory,htablelib))
$(eval $(call add_subdirectory,xtablelib))
$(eval $(call add_subdirectory,ewslib))
$(eval $(call add_subdirectory,cJSONlib))

$(eval $(call add_subdirectory,niolib))
$(eval $(call add_subdirectory,ncslib))
$(eval $(call add_subdirectory,reqlib))
$(eval $(call add_subdirectory,replib))
$(eval $(call add_subdirectory,apilib))

