#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=lua-resty-dns
PKG_VERSION:=2.1.0
PKG_RELEASE:=2
PKG_MAINTAINER:=Thijs Schreijer
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/CIRALabs/lua-resty-dns/archive/2.1.0.tar.gz
PKG_HASH:=53345643af647c3da5aba672913cb1633ff92f0fa765c2ca2769117801982987

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
HOST_BUILD_DEPENDS:=lua/host

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/lua-resty-dns-client
  SUBMENU:=Lua
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Lua DNS Client
  URL:=https://github.com/CIRALabs/lua-resty-dns-client
  DEPENDS:= +lua
endef

define Package/lua-resty-dns-client/description
  Lua RESTY DNS CLIENT is a fast DNS client library
endef

CMAKE_OPTIONS += \
	-DUSE_LUA=ON

CMAKE_HOST_OPTIONS += \
	-DLUA_MATH_LIBRARY=m

define Package/lua-resty-dns-client/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/resty-dns-client
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/resty/dns/*.lua $(1)/usr/lib/lua/resty-dns-client
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,lua-resty-dns-client))
