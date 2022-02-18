include $(TOPDIR)/rules.mk

PKG_NAME:=password-strength
PKG_VERSION:=0.0.3.post2
PKG_RELEASE:=1

PYPI_NAME:=password_strength
PKG_HASH:=bf4df10a58fcd3abfa182367307b4fd7b1cec518121dd83bf80c1c42ba796762

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-password-strength
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Password-Strength
  URL:=https://pypi.org/project/password-strength/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-password_strength/description
  Password strength and validation.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
