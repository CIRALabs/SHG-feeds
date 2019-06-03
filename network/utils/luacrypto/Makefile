include $(TOPDIR)/rules.mk

PKG_NAME:=luacrypto
PKG_VERSION:=0.3.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mkottman/luacrypto
PKG_SOURCE_VERSION:=0.3.2
PKG_SOURCE_DATE:=2013-05-25

include $(INCLUDE_DIR)/package.mk

define Package/luacrypto
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=LuaCrypto
  URL:=http://www.securehomegateway.ca/
  DEPENDS:=+lua +libopenssl
endef

define Package/luacrypto/description
 LuaCrypto provides a Lua frontend to the OpenSSL cryptographic library.
endef

define Package/luacrypto/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/.libs/crypto.so $(1)/usr/lib/lua/
endef

$(eval $(call BuildPackage,luacrypto))

