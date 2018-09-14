include $(TOPDIR)/rules.mk

PKG_NAME:=lua-log
PKG_VERSION:=1.0.1
PKG_RELEASE:=2

PKG_BUILD_DIR:=$(BUILD_DIR)/lua-log-$(PKG_VERSION)
#PKG_HASH:=9b7dc52656f5cbec846a7ba3299f73bd
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/CIRALabs/log.lua.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_DATE:=2018-08-31

include $(INCLUDE_DIR)/package.mk

define Package/lua-log
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=Logging utilities for LUA
  URL:=http://www.securehomegateway.ca/
endef

define Package/lua-log/description
 A tiny logging module for Lua.
endef

define Package/lua-log/install
	$(INSTALL_DIR) $(1)/usr/lib/lua;
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/log.lua  $(1)/usr/lib/lua
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,lua-log))
