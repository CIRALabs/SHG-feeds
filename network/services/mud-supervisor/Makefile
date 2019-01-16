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
  PKGARCH=all
  DEPENDS:=+mud-controller lxc
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

#	cp mud-supervisor.init $(1)/etc/init.d/mud-supervisor
#	chmod +x $(1)/etc/init.d/mud-supervisor

define Package/mud-supervisor/install
	echo installing to $(1)
	mkdir -p $(1)/etc/init.d $(1)/root
	cp upd mudbash mudssh  $(1)/root
	chmod +x $(1)/root/upd $(1)/root/mudbash $(1)/root/mudssh
endef

define Build/Compile
	echo compile.; true
endef


$(eval $(call BuildPackage,mud-supervisor))
