include $(TOPDIR)/rules.mk

PKG_NAME:=spin
PKG_VERSION:=0.9-beta
PKG_RELEASE:=2

PKG_BUILD_DIR:=$(BUILD_DIR)/spin-$(PKG_VERSION)
PKG_SOURCE:=spin-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://valibox.sidnlabs.nl/downloads/src/spin/
PKG_HASH:=639222c6509c0d000429749696b54436e8e84c037d600305f90c417a69e02af8

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += -ggdb3 -Wno-error=format
CONFIGURE_PATH:=src
MAKE_PATH:=src

define Package/spin
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

define Package/spin/description
  Experiment with SPIN tools
endef

define Build/Configure
    $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Build/Compile
  $(MAKE) $(SPIN_MAKE_OPTS)
endef

define Package/spin/install
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

$(eval $(call BuildPackage,spin))
