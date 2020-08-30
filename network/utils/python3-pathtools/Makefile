include $(TOPDIR)/rules.mk

PKG_NAME:=pathtools
PKG_VERSION:=0.1.3
PKG_RELEASE:=2

PYPI_NAME:=pathtools
PKG_CAT:=zcat
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/CIRALabs/pathtools.git
PKG_MIRROR_HASH:=795d1928c011a5d766dd66d2fab0dbef4c3e3da11eccfab2bb28397476b758c9
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
  PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-pathtools/description
  Pattern matching and various utilities for file systems paths.
endef

$(eval $(call Py3Package,python3-pathtools))
$(eval $(call BuildPackage,python3-pathtools))
$(eval $(call BuildPackage,python3-pathtools-src))
