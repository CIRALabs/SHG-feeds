include $(TOPDIR)/rules.mk

PKG_NAME:=watchdog
PKG_VERSION:=2.1.6
PKG_RELEASE:=1

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=a36e75df6c767cbf46f61a91c70b3ba71811dfa0aca4a324d9407a06a8b7a2e7

PKG_MAINTAINER:=Michael Richardson
#PKG_LICENSE:="Apache License 2.0"
PKG_LICENSE:=APACHE2
#PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-watchdog
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Filesystem events monitoring
  URL:=http://github.com/gorakhargosh/watchdog
  DEPENDS:=+python3
  VARIANT:=python3
endef

define Package/python3-watchdog/description
  A python extension for monitoring filesystem events.
endef

$(eval $(call Py3Package,python3-watchdog))
$(eval $(call BuildPackage,python3-watchdog))
$(eval $(call BuildPackage,python3-watchdog-src))
