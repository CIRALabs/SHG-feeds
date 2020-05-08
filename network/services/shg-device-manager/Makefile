include $(TOPDIR)/rules.mk

PKG_NAME:=shg-device-manager
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/shg-device-manager-$(PKG_VERSION)
PKG_SOURCE:=shg-device-manager-$(PKG_VERSION).tar.gz
PKG_HASH:=316fff3211c5e27467b94bd4c14d1087ed991cefe0ecb3d755c8858bdb734349
PKG_CAT:=zcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/CIRALabs/sshg-openwrt.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_DATE:=2020-04-20

include $(INCLUDE_DIR)/package.mk

define Package/shg-device-manager
  PKGARCH:=all
  DEPENDS:=+python3-flask +python3-flask-jwt-extended +python3-flask-cors
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=IoT Device Manager
  URL:=http://www.securehomegateway.ca/
endef

define Package/shg-device-manager/description
 This package provides an interface to the SHG Smartphone application.
 It discovers IoT devices in the home, characterizes their network traffic, and
 allows the home owner to control what network access the devices get.
 It can import or export RFC8520 MUD files via URL or QR code.
 Eventually, it will provide IoT device onboarding services as well.
endef

define Package/shg-device-manager/install
	mkdir -p $(1)/srv/auth_server $(1)/etc/init.d
	tar -C ${PKG_BUILD_DIR} -c -f - auth_server | tar -C $(1)/srv -x -f -
	$(INSTALL_BIN) ./files/shg-device-manager.init $(1)/etc/init.d/shg-device-manager
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,shg-device-manager))
