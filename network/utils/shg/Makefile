include $(TOPDIR)/rules.mk

PKG_NAME:=shg
PKG_VERSION:=0.1.0
PKG_RELEASE:=4

include $(INCLUDE_DIR)/package.mk

define Package/shg
  PKGARCH:=all
  #DEPENDS:=+mud-controller +mud-supervisor +shg-provisioning +shg-wifi-configuration +shg-radius-configuration +spin-shg
  DEPENDS:=+shg-provisioning +shg-device-manager
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=SHG meta-package
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg/description
  This package will install and configure a Turris Omnia router to an SHG one.
endef

define Build/Compile
  true
endef

define Package/shg/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/shg.defaults $(1)/etc/uci-defaults/shg
endef

define Package/shg/preinst
#!/bin/sh
grep shg $${IPKG_INSTROOT}/etc/services_wanted || \
    echo "
shg-provisioning
mosquitto
spin
" >> $${IPKG_INSTROOT}/etc/services_wanted

grep cira $${IPKG_INSTROOT}/etc/opkg/distfeeds.conf || \
echo "
src/gz ciralabs https://build.securehomegateway.ca/hbl/omnia/packages/ciralabs" >> $${IPKG_INSTROOT}/etc/opkg/distfeeds.conf
endef

$(eval $(call BuildPackage,shg))
