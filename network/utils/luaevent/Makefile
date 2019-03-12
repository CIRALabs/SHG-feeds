include $(TOPDIR)/rules.mk

PKG_NAME:=luaevent
PKG_VERSION:=0.4.6
PKG_RELEASE:=1

# Using released version
#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=https://github.com/harningt/luaevent/archive/v$(PKG_VERSION).tar.gz?
#PKG_HASH:=dd12babb252115895618c1243557534decde289bf0c255ffebf0dcd14a18705d
#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/harningt/luaevent
PKG_SOURCE_VERSION:=develop
PKG_SOURCE_DATE:=2019-02-12


PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/luaevent
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=Luaevent
  URL:=http://www.securehomegateway.ca/
  DEPENDS:=+lua +libevent2
endef

define Package/luaevent/description
 This is a binding of libevent to Lua.
endef

define Package/luaevent/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luaevent
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/luaevent.lua $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core.so $(1)/usr/lib/lua/luaevent
endef

$(eval $(call BuildPackage,luaevent))

