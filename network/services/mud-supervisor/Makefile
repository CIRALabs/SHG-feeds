include $(TOPDIR)/rules.mk

PKG_NAME:=mud-supervisor
PKG_VERSION:=20190517
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://junk.sandelman.ca/junk/
PKG_SOURCE:=shg_mud_supervisor-$(PKG_VERSION)-margarita32.tgz
PKG_HASH:=ea4b070178fae5323ffc9c9b4a2f4d88672fa858eba25101d663a1f835d88482

UNPACK_CMD=gzip -dc $(DL_DIR)/$(PKG_SOURCE) | $(HOST_TAR) -C $(1)/rootfs $(TAR_OPTIONS)

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

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/rootfs
	$(Build/Prepare/Default)
endef

define Build/Compile
	true
endef

define Package/mud-supervisor/conffiles
/srv/lxc/mud-supervisor/config
endef

define Package/mud-supervisor/install
	$(INSTALL_DIR) $(1)/srv/lxc/mud-supervisor/
	$(CP) $(PKG_BUILD_DIR)/rootfs $(1)/srv/lxc/mud-supervisor/rootfs
	$(CP) ./files/lxc/config $(1)/srv/lxc/mud-supervisor/
	# Fix missing /dev in lxc rootfs
	$(INSTALL_DIR) $(1)/srv/lxc/mud-supervisor/rootfs/dev/
	# Custom configuration
	$(INSTALL_BIN) ./files/lxc/start $(1)/srv/lxc/mud-supervisor/rootfs/root/
	$(INSTALL_BIN) ./files/production.rb $(1)/srv/lxc/mud-supervisor/rootfs/app/fountain/config/environments/production.rb
	$(INSTALL_BIN) ./files/routes.rb $(1)/srv/lxc/mud-supervisor/rootfs/app/fountain/config/routes.rb
	$(INSTALL_BIN) ./files/secure_gateway_controller.rb $(1)/srv/lxc/mud-supervisor/rootfs/app/fountain/app/controllers/secure_gateway_controller.rb

	$(INSTALL_DIR) $(1)/root
	$(INSTALL_BIN) ./files/mudbash $(1)/root/
	$(INSTALL_BIN) ./files/mudssh $(1)/root/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mud-supervisor.init $(1)/etc/init.d/mud-supervisor

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/mud-supervisor.defaults $(1)/etc/uci-defaults/99_mud-supervisor
endef

$(eval $(call BuildPackage,mud-supervisor))
