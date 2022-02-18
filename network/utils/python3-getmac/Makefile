include $(TOPDIR)/rules.mk

PKG_NAME:=getmac
PKG_VERSION:=0.8.3
PKG_RELEASE:=1

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=6e38f9023b9792f53ef982cce6be65d84fea656be87100ab2f2d0376563af486

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-getmac
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Get Mac Address in Python3
  URL:=https://pypi.org/project/getmac/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-getmac/description
  Pure-Python package to get the MAC address of network interfaces and hosts on the local network.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
