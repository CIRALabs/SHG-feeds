include $(TOPDIR)/rules.mk

PKG_NAME:=Flask-SQLAlchemy
PKG_VERSION:=2.5.1
PKG_RELEASE:=1

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=2bda44b43e7cacb15d4e05ff3cc1f8bc97936cc464623424102bfc2c35e95912

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask-sqlalchemy
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Flask interface for SQL-Alchemy
  URL:=https://flask-sqlalchemy.palletsprojects.com/en/2.x/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-flask-sqlalchemy/description
  Flask interface to SQL-Alchemy
endef

$(eval $(call Py3Package,python3-flask-sqlalchemy))
$(eval $(call BuildPackage,python3-flask-sqlalchemy))
$(eval $(call BuildPackage,python3-flask-sqlalchemy-src))
