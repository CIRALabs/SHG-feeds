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
 At present this is just a shell, the actual container needs to be downloaded
 with rsync.
endef

define Build/Compile
	true
endef

define Package/mud-supervisor/conffiles
/etc/lighttpd/conf.d/mud-supervisor.conf
/srv/lxc/mud-supervisor/config
endef

define Package/mud-supervisor/install
	$(INSTALL_DIR) $(1)/root
	$(INSTALL_DIR) $(1)/srv/lxc/
	$(INSTALL_DIR) $(1)/etc/lighttpd/conf.d

	$(INSTALL_BIN) ./files/upd $(1)/root/
	$(INSTALL_BIN) ./files/mudbash $(1)/root/
	$(INSTALL_BIN) ./files/mudssh $(1)/root/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mud-supervisor.init $(1)/etc/init.d/mud-supervisor

	$(CP) ./files/mud-supervisor-lxc.tar.gz $(1)/srv/lxc/
	$(CP) ./files/lighttpd/mud-supervisor.conf $(1)/etc/lighttpd/conf.d/
endef

# This is hacky/dirty and needed because lxc rootfile contains executables linked to libc
# However, turris has musl by default, so there is a missing dependency detected during packaging
# and I could not find a way to bypass this.
define Package/mud-supervisor/postinst
#!/bin/sh
rm -rf $${IPKG_INSTROOT}/srv/lxc/mud-supervisor
tar xf $${IPKG_INSTROOT}/srv/lxc/mud-supervisor-lxc.tar.gz -C $${IPKG_INSTROOT}/srv/lxc/
endef

$(eval $(call BuildPackage,mud-supervisor))
