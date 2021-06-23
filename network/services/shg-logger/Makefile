include $(TOPDIR)/rules.mk

PKG_NAME:=shg-logger
PKG_VERSION:=1.0.4
PKG_RELEASE:=1
PKG_SOURCE_DATE:=2021-06-23


include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	PKGARCH:=all
	DEPENDS:=
	SECTION:=ciralabs
	TITLE:=shg-logger
	CATEGORY:=Network
	URL:=http://www.securehomegateway.ca
endef

define Package/shg-logger/description
	This package will install a utility to collect and send interesting MQTT logs to
	securehomegateway.ca using the SSHG router's certificate for authentication/authorization.
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/shg
	$(INSTALL_DIR) $(1)/etc/rc.d

	$(INSTALL_BIN) ./files/shg-logger.init $(1)/etc/init.d/shg-logger
	$(INSTALL_BIN) ./files/shg-logger.py $(1)/etc/shg

	# Putting this hack in place because I CANNOT get openWRT to
	# create the symlink from init.d to rc.d
	# jb - 2021/06/23
	$(INSTALL_BIN) ./files/shg-logger.init $(1)/etc/rc.d/S94shg-logger
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
