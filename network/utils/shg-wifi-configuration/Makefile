include $(TOPDIR)/rules.mk

PKG_NAME:=shg-wifi-configuration
PKG_VERSION:=1.0.0
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk

define Package/shg-wifi-configuration
  PKGARCH:=all
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=SHG configuration for wifi
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg-wifi-configuration/description
  Configuration for wifi
endef

define Build/Compile
	true
endef

define Package/shg-wifi-configuration/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/shg-wifi-configuration.defaults $(1)/etc/uci-defaults/70_shg-wifi-configuration
endef

$(eval $(call BuildPackage,shg-wifi-configuration))
