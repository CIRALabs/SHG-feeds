include $(TOPDIR)/rules.mk

PKG_NAME:=shg-provisioning
PKG_VERSION:=1.3.0
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk

define Package/shg-provisioning
  PKGARCH:=all
  DEPENDS:=+coreutils +coreutils-base64 +curl
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=SHG provisioning init script
  URL:=http://www.securehomegateway.ca/
  MENU:=1
endef

define Package/shg-provisioning/description
  Script initializing the Turris with SHG filesystem.
endef

define Build/Compile
	true
endef

define Package/shg-provisioning/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/shg
	$(INSTALL_BIN) ./files/shg-provisioning $(1)/etc/init.d/shg-provisioning
	$(INSTALL_BIN) ./files/enroll-certificate $(1)/usr/sbin
endef

$(eval $(call BuildPackage,shg-provisioning))
