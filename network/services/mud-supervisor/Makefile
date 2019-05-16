include $(TOPDIR)/rules.mk

PKG_NAME:=mud-supervisor
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_BUILD_DIR:=$(BUILD_DIR)/mud-supervisor-$(PKG_VERSION)
#PKG_SOURCE:=mud-super-$(PKG_VERSION).tar.gz
#PKG_HASH:=9b7dc52656f5cbec846a7ba3299f73bd
#PKG_CAT:=xzcat
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL:=https://github.com/CIRALabs/shg-mud-controller.git
#PKG_SOURCE_VERSION:=master
#PKG_SOURCE_DATE:=2019-01-01

include $(INCLUDE_DIR)/package.mk

define Package/mud-supervisor
  PKGARCH:=all
  DEPENDS:=+mud-controller +lxc
  SECTION:=ciralabs
  CATEGORY:=Network
  TITLE:=MUD supervisor and BRSKI Registrar using container
  URL:=http://www.securehomegateway.ca/
endef

define Package/mud-supervisor/description
 mud-supervisor is a package to do high-level management of IoT security.
 It uses the mud-controller to do the low-level control.  This module is written
 in ruby-on-rails, and keeps a database of devices.  It exposes an API to internal
 clients (smartphone, one-page app).
 It includes a BRSKI registrar.
endef

define Build/Compile
	true
endef

define Package/mud-supervisor/conffiles
/srv/lxc/mud-supervisor/config
endef

define Package/mud-supervisor/install
	$(INSTALL_DIR) $(1)/srv/lxc/mud-supervisor/
	$(CP) ./files/lxc/rootfs $(1)/srv/lxc/mud-supervisor/rootfs
	$(CP) ./files/lxc/config $(1)/srv/lxc/mud-supervisor/

	$(INSTALL_DIR) $(1)/root
	$(INSTALL_BIN) ./files/mudbash $(1)/root/
	$(INSTALL_BIN) ./files/mudssh $(1)/root/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mud-supervisor.init $(1)/etc/init.d/mud-supervisor

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/mud-supervisor.defaults $(1)/etc/uci-defaults/99_mud-supervisor
endef

$(eval $(call BuildPackage,mud-supervisor))
