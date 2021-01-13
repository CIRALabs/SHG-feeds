include $(TOPDIR)/rules.mk

PKG_NAME:=flask_script
PKG_VERSION:=2.0.6
PKG_RELEASE:=1

PYPI_NAME:=Flask-Script
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/00/a4/cd587b2b19f043b65bf33ceda2f6e4e6cdbd0ce18d01a52b9559781b1da6/Flask-Script-2.0.6.tar.gz
PKG_HASH:=bfc7150eaf809b1c283879302f04c42791136060c6eeb12c0c6674fb1291fae5
PKG_SOURCE=Flask-Script-2.0.6.tar.gz

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask_script
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Flask Script
  URL:=https://pypi.org/project/Flask-Script/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-flask_script/description
  Flask support for writing external scripts.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
