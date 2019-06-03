include $(TOPDIR)/rules.mk

PKG_NAME:=lua-basexx
PKG_VERSION:=0.4.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/aiq/basexx.git
PKG_SOURCE_VERSION:=v0.4.1
PKG_SOURCE_DATE:=2019-04-23

include $(INCLUDE_DIR)/package.mk

define Package/lua-basexx
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=Lua-basexx
  URL:=http://www.securehomegateway.ca/
  DEPENDS:=+lua
endef

define Package/lua-basexx/description
  A Lua library for base2, base16, base32, base64, base85 decoding and encoding of data strings.
endef

define Build/Compile
  true
endef

define Package/lua-basexx/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lib/basexx.lua $(1)/usr/lib/lua
endef

$(eval $(call BuildPackage,lua-basexx))
