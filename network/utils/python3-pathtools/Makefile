include $(TOPDIR)/rules.mk

PKG_NAME:=python3-pathtools
PKG_VERSION:=0.1.2
PKG_RELEASE:=1

PYPI_NAME:=pathtools
PKG_CAT:=xzcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/gorakhargosh/pathtools.git
PKG_MIRROR_HASH:=1b9efa8573069595ada7f0c875f09b2078a4949ceddfb975e2ac620ef1782251
PKG_SOURCE_VERSION:=master

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-pathtools
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Pattern matching and various utilities for file systems paths.
  URL:=https://github.com/gorakhargosh/pathtools
  DEPENDS:=+python3
  VARIANT:=python3
endef

define Package/python3-pathtools/description
  Pattern matching and various utilities for file systems paths.
endef

$(eval $(call Py3Package,python3-pathtools))
$(eval $(call BuildPackage,python3-pathtools))
$(eval $(call BuildPackage,python3-pathtools-src))
