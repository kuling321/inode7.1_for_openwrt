include $(TOPDIR)/rules.mk


PKG_NAME:=wuliclientBulidl
PKG_RELEASE:=1.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
SECTION:=utils
CATEGORY:=Utilities
PKGARCH:=all
TITLE:= $(PKG_NAME)
MAINTAINER:=K.L
endef

define Package/$(PKG_NAME)/description
    wuliclient for Inode7.1 portal in zhibt
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/bin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
