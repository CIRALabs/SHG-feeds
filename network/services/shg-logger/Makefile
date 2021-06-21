include $(TOPDIR)/rules.mk

PKG_NAME:=shg-logger
PKG_VERSION:=1.0.1
PKG_RELEASE:=1
PKG_SOURCE_DATE:=2021-06-17


include $(INCLUDE_DIR)/package.mk

define Package/shg-logger
  PKGARCH:=all
  DEPENDS:=
  SECTION:=ciralabs
  TITLE:=shg-logger
  CATEGORY:=Network
  URL:=http://www.securehomegateway.ca
  MENU:=1
endef

define Package/shg-logger/description
  This package will install a utility to collect and send interesting MQTT logs to
  securehomegateway.ca using the SSHG router's certificate for authentication/authorization.
endef

define Build/Compile
  true
endef

# NOTE _ it is important that the lines inside this section are indented with TABs!
# SPACEs will not work for the compile!
# jb - 2021/06/21
define Package/shg-logger/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/shg

	$(INSTALL_BIN) ./files/shg-logger.init $(1)/etc/init.d/shg-logger
	$(INSTALL_BIN) ./files/shg-logger.py $(1)/etc/shg
endef

$(eval $(call BuildPackage,shg-logger))
