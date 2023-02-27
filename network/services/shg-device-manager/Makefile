include $(TOPDIR)/rules.mk
# Load the git token so we don't commit it to the repo...
include git-token.txt

PKG_NAME:=shg-device-manager
PKG_VERSION:=2022.03.09.01
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/shg-device-manager-$(PKG_VERSION)
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://${GIT-TOKEN}:x-oauth-basic@github.com/CIRALabs/sshg-openwrt
PKG_SOURCE_VERSION:=story/shg-javascript
PKG_SOURCE_DATE:=2022-03-09

include $(INCLUDE_DIR)/package.mk

define Package/shg-device-manager
  PKGARCH:=all
  DEPENDS:=+python3-flask +python3-flask-jwt-extended +python3-flask-cors \
	+python3-schema +python3-flup +python3-watchdog +python3-sqlalchemy \
	+python3-flask-sqlalchemy +python3-flask-migrate +python3-getmac \
	+python3-alembic +python3-password-strength +python3-mako \
	+python3-dateutil +python3-requests +python3-paho-mqtt +python3-uci \
	+lighttpd-mod-openssl +lighttpd-mod-fastcgi +lighttpd-mod-setenv \
	+lighttpd-mod-redirect
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
endef

define Package/shg-device-manager/install
	${INSTALL_DIR} $(1)/srv/shg-device-manager $(1)/etc/init.d $(1)/etc/lighttpd/conf.d $(1)/usr/share/shg $(1)/usr/bin $(1)/etc/uci-defaults
	tar -C ${PKG_BUILD_DIR}/device_manager -c -f - . | tar -C $(1)/srv/shg-device-manager -x -f -
	${INSTALL_BIN} ./files/lighttpd-shg-device-manager.conf $(1)/etc/lighttpd/conf.d/52-shg-device-manager.conf
	${INSTALL_BIN} ./files/shg-init $(1)/etc/uci-defaults/60-shg
	${INSTALL_BIN} ./files/shg-device-manager.init $(1)/etc/init.d/shg-device-manager
	${INSTALL_DATA} $(PKG_BUILD_DIR)/device_manager_cli/shg/device_manager_client.py $(1)/usr/share/shg
	${INSTALL_DATA} $(PKG_BUILD_DIR)/device_manager_cli/shg/network.py $(1)/usr/share/shg
	${INSTALL_BIN} $(PKG_BUILD_DIR)/device_manager_cli/shg/shg.py $(1)/usr/share/shg
	${INSTALL_BIN} $(PKG_BUILD_DIR)/device_manager_cli/shg/device_manager_ui_helper.py $(1)/usr/share/shg
endef

define Package/shg-device-manager/postinst
  	ln -s /usr/share/shg/shg.py /usr/bin/shg
endef

define Build/Compile
	true
endef

$(eval $(call BuildPackage,shg-device-manager))
