include $(TOPDIR)/rules.mk

PKG_NAME:=python3-watchdog
PKG_VERSION:=0.10.3
PKG_RELEASE:=1

PYPI_NAME:=watchdog
PKG_HASH:=4214e1379d128b0588021880ccaf40317ee156d4603ac388b9adcf29165e0c04
PKG_SOURCE_URL:=https://pypi.python.org/packages/source/w/watchdog/watchdog-0.10.3.tar.gz

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
