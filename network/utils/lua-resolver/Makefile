
include $(TOPDIR)/rules.mk

PKG_NAME:=lua-resolver
PKG_VERSION:=1.0.0
PKG_RELEASE:=2

PKG_BUILD_DIR:=$(BUILD_DIR)/lua-resolver-$(PKG_VERSION)
#PKG_SOURCE:=lua-cjson-$(PKG_VERSION).tar.gz
#PKG_HASH:=9b7dc52656f5cbec846a7ba3299f73bd
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/zeitgeist87/LuaResolver.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_DATE:=2018-08-31

include $(INCLUDE_DIR)/package.mk

define Package/lua-resolver
  PKGARCH=all
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=LUA resolver package
  URL:=https://github.com/zeitgeist87/LuaResolver.git
endef

define Package/lua-resolver/description
	The Lua Resolver module provides for DNS lookups in LUA.
endef

define Package/lua-resolver/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/dns;
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dns/parser.lua $(PKG_BUILD_DIR)/dns/resolver.lua $(1)/usr/lib/lua/dns
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,lua-resolver))
