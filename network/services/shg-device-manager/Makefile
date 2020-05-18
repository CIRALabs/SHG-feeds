include $(TOPDIR)/rules.mk

PKG_NAME:=shg-device-manager
PKG_VERSION:=0.2.3
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/shg-device-manager-$(PKG_VERSION)
#PKG_SOURCE:=shg-device-manager-$(PKG_VERSION).tar.gz
#PKG_HASH:=316fff3211c5e27467b94bd4c14d1087ed991cefe0ecb3d755c8858bdb734349
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/CIRALabs/sshg-openwrt.git
PKG_SOURCE_URL:=git+ssh://obiwan.sandelman.ca/ssw/projects/shg/sshg-openwrt
PKG_SOURCE_VERSION:=hera_test1
PKG_SOURCE_DATE:=2020-04-20

include $(INCLUDE_DIR)/package.mk

define Package/shg-device-manager
  PKGARCH:=all
  DEPENDS:=+python3-flask +python3-flask-jwt-extended +python3-flask-cors +python3-schema +python3-flup +lighttpd-mod-openssl
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
	${INSTALL_DIR} $(1)/srv/shg-device-manager $(1)/etc/init.d $(1)/etc/lighttpd/conf.d
	tar -C ${PKG_BUILD_DIR}/auth_server -c -f - . | tar -C $(1)/srv/shg-device-manager -x -f -
	${INSTALL_BIN} ./files/lighttpd-shg-device-manager.conf $(1)/etc/lighttpd/conf.d/52-shg-device-manager.conf
	${INSTALL_BIN} ./files/shg-device-manager.init $(1)/etc/init.d/shg-device-manager
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,shg-device-manager))
