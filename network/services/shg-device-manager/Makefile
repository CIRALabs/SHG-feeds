include $(TOPDIR)/rules.mk

PKG_NAME:=shg-device-manager
PKG_VERSION:=2021.1.13-1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/shg-device-manager-$(PKG_VERSION)
#PKG_SOURCE:=shg-device-manager-$(PKG_VERSION).tar.xz
#PKG_HASH=3438766c46b348239ff0b90d542b8cb2a0ac0dbb8ccaf99263ac6abe084c3828
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL:=https://github.com/CIRALabs/sshg-openwrt.git
PKG_SOURCE_URL:=git+ssh://obiwan.sandelman.ca/ssw/projects/shg/sshg-openwrt
PKG_SOURCE_VERSION:=master
PKG_SOURCE_DATE:=2021-01-13

include $(INCLUDE_DIR)/package.mk

define Package/shg-device-manager
  PKGARCH:=all
  DEPENDS:=+python3-flask +python3-flask-jwt-extended +python3-flask-cors \
	+python3-schema +python3-flup +lighttpd-mod-openssl +python3-watchdog \
	+python3-pathtools +python3-sqlalchemy +python3-flask_sqlalchemy \
	+python3-flask_migrate +python3-flask_script +python3-getmac
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
	tar -C ${PKG_BUILD_DIR}/device_manager -c -f - . | tar -C $(1)/srv/shg-device-manager -x -f -
	${INSTALL_BIN} ./files/lighttpd-shg-device-manager.conf $(1)/etc/lighttpd/conf.d/52-shg-device-manager.conf
	${INSTALL_BIN} ./files/shg-device-manager.init $(1)/etc/init.d/shg-device-manager
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,shg-device-manager))
