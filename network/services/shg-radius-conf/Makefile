include $(TOPDIR)/rules.mk

PKG_NAME:=shg-radius-configuration
PKG_VERSION:=1.0.0
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk

define Package/shg-radius-configuration
  PKGARCH=all
  DEPENDS:=+freeradius3-mod-sql-sqlite +freeradius3-mod-expr +freeradius3-mod-always +freeradius3-mod-attr-filter +freeradius3-mod-preprocess
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
endef

define Package/shg-radius-configuration/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# Deploy custom configuration files
	cp /lib/netifd/hostapd.sh /lib/netifd/hostapd.sh.orig
	cp /lib/netifd/netifd-wireless.sh /lib/netifd/netifd-wireless.sh.orig
	cp /etc/shg/radius-configuration/lib/netifd/* /lib/netifd/
	cp /etc/shg/radius-configuration/etc/freeradius3/radiusd.conf /etc/freeradius3/
	# Enable radius - Seems it is not enabled by default
	/etc/init.d/radiusd enable
}
endef

$(eval $(call BuildPackage,shg-radius-configuration))
