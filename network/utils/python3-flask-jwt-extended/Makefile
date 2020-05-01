include $(TOPDIR)/rules.mk

PKG_NAME:=python-flask-jwt-extended
PKG_VERSION:=3.20.0
PKG_RELEASE:=1

#PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PYPI_NAME:=PyJWT
PKG_HASH:=062d2cac64f5c02fd689105b99390b2490e550a1c0994cb9d781454ec31bd50c

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
endef

define Package/python3-flask-jwt-extended/description
  This package not only adds support for using JSON Web Tokens (JWT)
  to Flask for protecting views, but also many helpful (and optional) 
  features built in to make working with JSON Web Tokens easier.
endef

$(eval $(call Py3Package,python3-flask-jwt-extended))
$(eval $(call BuildPackage,python3-flask-jwt-extended))
#$(eval $(call BuildPackage,python3-flask-jwt-extended-src))
