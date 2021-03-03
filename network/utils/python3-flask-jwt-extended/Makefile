include $(TOPDIR)/rules.mk

PKG_NAME:=python-flask-jwt-extended
PKG_VERSION:=3.25.0
PKG_RELEASE:=1

#PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PYPI_NAME:=Flask-JWT-Extended
PKG_HASH:=bbf4467f41c56cf1fd8a5870d2556f419c572aad2b4085757581c3f9b4d7767a

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
