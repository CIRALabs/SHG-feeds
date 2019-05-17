include $(TOPDIR)/rules.mk

PKG_NAME:=shg
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/shg
  PKGARCH:=all
  DEPENDS:=+mud-controller +mud-supervisor +shg-provisioning +shg-wifi-configuration +shg-radius-configuration
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=SHG meta-package
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg/description
  This package will install and configure a Turris Omnia routeur to an SHG one.
endef

define Build/Compile
  true
endef

define Package/shg/install
  true
endef

define Package/shg/preinst
#!/bin/sh
grep shg $${IPKG_INSTROOT}/etc/services_wanted || \
    echo "
shg-provisioning
mud-controller
mud-supervisor
radiusd
mosquitto
" >> $${IPKG_INSTROOT}/etc/services_wanted

grep cira $${IPKG_INSTROOT}/etc/opkg/distfeeds.conf || \
echo "
src/gz cira https://www.viagenie.ca/cira-shg/repo/beta1" >> $${IPKG_INSTROOT}/etc/opkg/distfeeds.conf
endef

$(eval $(call BuildPackage,shg))
