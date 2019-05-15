include $(TOPDIR)/rules.mk

PKG_NAME:=shg-radius-configuration
PKG_VERSION:=1.0.0
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk

define Package/shg-radius-configuration
  PKGARCH:=all
  DEPENDS:=+shg-wifi-configuration +libpcre +freeradius3 +freeradius3-mod-sql +freeradius3-mod-sql-sqlite +freeradius3-mod-expr +freeradius3-mod-always +freeradius3-mod-attr-filter +freeradius3-mod-preprocess
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=SHG configuration for PSK-Radius integration
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg-radius-configuration/description
  Configuration for PSK-Radius integration
endef

define Build/Compile
	true
endef

define Package/shg-radius-configuration/install
	$(INSTALL_DIR) $(1)/etc/shg/radius-configuration/lib/netifd/
	$(INSTALL_DATA) ./files/netifd-wireless.sh $(1)/etc/shg/radius-configuration/lib/netifd/
	$(INSTALL_DATA) ./files/hostapd.sh $(1)/etc/shg/radius-configuration/lib/netifd/
	$(INSTALL_DIR) $(1)/etc/shg/radius-configuration/etc/freeradius3/
	$(INSTALL_DATA) ./files/radiusd.conf $(1)/etc/shg/radius-configuration/etc/freeradius3
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	# Need to be executed after shg-wifi-configuration
	$(INSTALL_DATA) ./files/shg-radius-configuration.defaults $(1)/etc/uci-defaults/90_shg-radius-configuration
endef

define Package/shg-radius-configuration/postinst
#!/bin/sh
# Deploy custom configuration files
cp $${IPKG_INSTROOT}/lib/netifd/hostapd.sh $${IPKG_INSTROOT}/lib/netifd/hostapd.sh.orig
cp $${IPKG_INSTROOT}/lib/netifd/netifd-wireless.sh $${IPKG_INSTROOT}/lib/netifd/netifd-wireless.sh.orig
cp $${IPKG_INSTROOT}/etc/shg/radius-configuration/lib/netifd/* $${IPKG_INSTROOT}/lib/netifd/
cp $${IPKG_INSTROOT}/etc/shg/radius-configuration/etc/freeradius3/radiusd.conf $${IPKG_INSTROOT}/etc/freeradius3/
endef

$(eval $(call BuildPackage,shg-radius-configuration))
