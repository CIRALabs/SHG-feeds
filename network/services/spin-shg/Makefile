include $(TOPDIR)/rules.mk

PKG_NAME:=spin-shg
PKG_VERSION:=0.9
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/spin-$(PKG_VERSION)
PKG_SOURCE:=spin-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://valibox.sidnlabs.nl/downloads/src/spin/
PKG_HASH:=72d17e11f66c6edaca4ccbccdd0055b533b86b67c542eeff1a3317817a78fad9

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += -ggdb3 -Wno-error=format
CONFIGURE_PATH:=src
MAKE_PATH:=src

define Package/spin-shg
  SECTION:=base
  CATEGORY:=SIDN
  TITLE:=Experimental tools for SPIN
  URL:=https://github.com/SIDN/spin
  DEPENDS:=+ip\
           +luaposix\
           +luasec\
           +luabitop\
           +lua-copas\
           +luasocket\
           +mosquitto-ssl\
           +libmosquitto-ssl\
           +lua-mosquitto\
           +libnfnetlink\
           +lua-minittp\
           +lua-websockets\
           +libmnl\
           +libnetfilter-conntrack\
           +kmod-nf-conntrack\
           +kmod-nf-conntrack-netlink\
           +libnetfilter-queue\
           +kmod-nfnetlink-queue\
           +iptables-mod-nfqueue\
           +libnetfilter-log\
           +kmod-nfnetlink-log\
           +iptables-mod-nflog\
           +libldns\
           +libuci
  MAINTAINER:=Jelte Jansen <jelte.jansen@sidn.nl>
endef

PKG_BUILD_DEPENDS:=libnfnetlink

SPIN_MAKE_OPTS:= -C $(PKG_BUILD_DIR)/$(MAKE_PATH) \
        PATH="$(TARGET_PATH)/$(MAKE_PATH)" \
        ARCH="$(LINUX_KARCH)" \
        CROSS_COMPILE="$(TARGET_CROSS)" \
        TARGET="$(HAL_TARGET)" \
        TOOLPREFIX="$(KERNEL_CROSS)" \
        TOOLPATH="$(KERNEL_CROSS)" \
        LDOPTS=" "

define Package/spin-shg/description
  Experiment with SPIN tools
endef

define Build/Configure
    $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Build/Compile
  $(MAKE) $(SPIN_MAKE_OPTS)
endef

define Package/spin-shg/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/rc.d
	cp -r ./files/* $(1)/
	$(INSTALL_DIR) $(1)/usr/lib/spin/web_ui
	cp -r ${PKG_BUILD_DIR}/src/web_ui/* $(1)/usr/lib/spin/web_ui
	$(INSTALL_DIR) $(1)/usr/lib/spin
	$(INSTALL_BIN) ${PKG_BUILD_DIR}/src/lua/*.lua $(1)/usr/lib/spin/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ${PKG_BUILD_DIR}/src/tools/spin_config/spin_config $(1)/usr/bin/spin_config
	$(INSTALL_BIN) ${PKG_BUILD_DIR}/src/tools/spin_print/spin_print $(1)/usr/bin/spin_print
	$(INSTALL_BIN) ${PKG_BUILD_DIR}/src/spind/spind $(1)/usr/bin/spind
	$(INSTALL_DIR) $(1)/etc/spin
endef

define Package/spin-shg/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	uci set mosquitto.mosquitto.port=1883
	uci set mosquitto.mosquitto.protocol=mqtt
	uci set mosquitto.spin_listener=listener
	uci set mosquitto.spin_listener.port=1884
	uci set mosquitto.spin_listener.protocol=websockets
	uci set mosquitto.owrt.use_uci='1'
	uci commit mosquitto
}
endef

$(eval $(call BuildPackage,spin-shg))
