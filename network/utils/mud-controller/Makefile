include $(TOPDIR)/rules.mk

PKG_NAME:=mud-controller
PKG_VERSION:=0.1.3
PKG_RELEASE:=16

PKG_BUILD_DIR:=$(BUILD_DIR)/mud-controller-$(PKG_VERSION)
#PKG_SOURCE:=mud-super-$(PKG_VERSION).tar.gz
#PKG_HASH:=9b7dc52656f5cbec846a7ba3299f73bd
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/CIRALabs/shg-mud-controller.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_DATE:=2018-08-31

include $(INCLUDE_DIR)/package.mk

define Package/mud-controller
  PKGARCH=all
  DEPENDS:=+libuci-lua lua-cjson lua-resolver luasocket lua-log luaevent
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=firewall manager using MUD files
  URL:=http://www.securehomegateway.ca/
endef

define Package/mud-controller/description
 mud-controller is a package to manage the firewall interfaces of openwrt using
 IETF RFCxxxx MUD files to control access by various home (IoT) devices.
 mud-controller is generally controlled by a mud-supervisor,
 of which https://github.com/CIRALabs/shg-fountain
 is one such supervisor.  (It is generally run in an LXC container)
endef

define Package/mud-controller/install
	echo installing to $(1)
	mkdir -p $(1)/etc/init.d
	make -C $(PKG_BUILD_DIR) DESTDIR=$(1) install
endef

define Build/Compile
	echo compile.; true
endef


$(eval $(call BuildPackage,mud-controller))
