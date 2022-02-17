include $(TOPDIR)/rules.mk

PKG_NAME:=flask_sqlalchemy
PKG_VERSION:=2.4.4
PKG_RELEASE:=2

PYPI_NAME:=Flask-SQLAlchemy
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/cc/d3/58d45c266b1c6e9f54a12af54f444547b142f6312e4520c771de0171d031
PKG_HASH:=bfc7150eaf809b1c283879302f04c42791136060c6eeb12c0c6674fb1291fae5
PKG_SOURCE=Flask-SQLAlchemy-2.4.4.tar.gz

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask_sqlalchemy
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Flask interface for SQL-Alchemy
  URL:=https://flask-sqlalchemy.palletsprojects.com/en/2.x/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-flask_sqlalchemy/description
  Flask interface to SQL-Alchemy
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
