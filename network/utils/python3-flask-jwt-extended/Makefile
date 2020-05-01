include $(TOPDIR)/rules.mk

PKG_NAME:=python-flask-jwt-extended
PKG_VERSION:=3.20.0
PKG_RELEASE:=1

#PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PYPI_NAME:=Flask-JWT-Extended
PKG_HASH:=0aa8ee6fa7eb3be9314e39dd199ac8e19389a95371f9d54e155c7aa635e319dd

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask-jwt-extended
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Extended JWT integration with Flask
  URL:=http://github.com/vimalloc/flask-jwt-extended
  DEPENDS:=+python3 +python3-flask +python3-pyjwt +python3-six \
	  +python3-werkzeug
  VARIANT:=python3
endef

define Package/python3-flask-jwt-extended/description
  This package not only adds support for using JSON Web Tokens (JWT)
  to Flask for protecting views, but also many helpful (and optional) 
  features built in to make working with JSON Web Tokens easier.
endef

$(eval $(call Py3Package,python3-flask-jwt-extended))
$(eval $(call BuildPackage,python3-flask-jwt-extended))
$(eval $(call BuildPackage,python3-flask-jwt-extended-src))
