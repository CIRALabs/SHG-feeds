include $(TOPDIR)/rules.mk
#include git-token.txt

PKG_NAME:=shg-device-manager-luci
PKG_VERSION:=2023.02.02.01
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/shg-device-manager-luci-$(PKG_VERSION)
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://${GIT-TOKEN}:x-oauth-basic@github.com/CIRALabs/sshg-openwrt
PKG_SOURCE_VERSION:=story/shg-javascript
PKG_SOURCE_DATE:=2023-02-14

include $(INCLUDE_DIR)/package.mk

define Package/shg-device-manager-luci
  PKGARCH:=all
  DEPENDS:=+shg-device-manager +luci
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=IoT Device Manager
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg-device-manager-luci/description
 This package provides an interface in LuCI to the device_manager REST api
endef

define Package/shg-device-manager-luci/install
	${INSTALL_DIR} $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d $(1)/www/luci-static/resources/view/shg
	${INSTALL_DATA} ${PKG_BUILD_DIR}/device_manager_luci/htdocs/luci-static/resources/view/shg/configurations.js $(1)/www/luci-static/resources/view/shg/configurations.js
	${INSTALL_DATA} ${PKG_BUILD_DIR}/device_manager_luci/htdocs/luci-static/resources/view/shg/devicemanager.js $(1)/www/luci-static/resources/view/shg/devicemanager.js
	${INSTALL_DATA} ${PKG_BUILD_DIR}/device_manager_luci/root/usr/share/rpcd/acl.d/luci-app-shg.json $(1)/usr/share/rpcd/acl.d/luci-app-shg.json
	${INSTALL_DATA} ${PKG_BUILD_DIR}/device_manager_luci/root/usr/share/luci/menu.d/luci-app-shg.json $(1)/usr/share/luci/menu.d/luci-app-shg.json
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,shg-device-manager-luci))
