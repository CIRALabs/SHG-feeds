include $(TOPDIR)/rules.mk

PKG_NAME:=Flask-Cors
PKG_VERSION:=3.0.8
PKG_RELEASE:=1

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=72170423eb4612f0847318afff8c247b38bd516b7737adfc10d1c2cdbb382d16

PKG_MAINTAINER:=Cory Dolphin
PKG_LICENSE:=MIT License
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask-cors
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=CORS extension for flask
  URL:=https://github.com/corydolphin/flask-cors
  DEPENDS:=+python3 +python3-flask +python3-six
  VARIANT:=python3
endef

define Package/python3-flask-cors/description
  A Flask extension for handling Cross Origin Resource Sharing (CORS), making cross-origin AJAX possible.
endef

$(eval $(call Py3Package,python3-flask-cors))
$(eval $(call BuildPackage,python3-flask-cors))
$(eval $(call BuildPackage,python3-flask-cors-src))
