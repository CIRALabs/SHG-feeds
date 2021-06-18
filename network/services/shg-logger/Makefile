include $(TOPDIR)/rules.mk

PKG_NAME:=shg-logger
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_SOURCE_DATE:=2021-06-17


include $(INCLUDE_DIR)/package.mk

define Package/shg-logger
  PKGARCH:=all
  DEPENDS:=+shg-provisioning +spin-shg +shg-device-manager
  SECTION:=ciralabs
  TITLE:=shg-logger
  URL:=http://www.securehomegateway.ca
endef

define Package/shg-logger/description
  This package will install a utilit collect and send interesting MQTT logs to
  securehomegateway.ca using the SSHG router's certificate for authentication/authorization.
endef

define Build/Compile
  true
endef

define Package/shg-logger/install
  $(INSTALL_BIN) ./files/shg-logger.init $(1)/etc/init.d/shg-logger
  $(INSTALL_BIN) ./files/shg-logger.py $(1)/etc/shg
endef

$(eval $(call BuildPackage,shg-logger))
