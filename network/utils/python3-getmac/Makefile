include $(TOPDIR)/rules.mk

PKG_NAME:=getmac
PKG_VERSION:=2.0.6
PKG_RELEASE:=1

PYPI_NAME:=getmac
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/60/a2/d64aed61f8f86827eab2e77e49a6158630690daa8130f7452a4b676acefc/getmac-0.8.2.tar.gz
#PKG_HASH:=bfc7150eaf809b1c283879302f04c42791136060c6eeb12c0c6674fb1291fae5
PKG_SOURCE=getmac-0.8.2.tar.gz

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
