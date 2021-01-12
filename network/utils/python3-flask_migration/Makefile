include $(TOPDIR)/rules.mk

PKG_NAME:=flask_migration
PKG_VERSION:=2.5.3
PKG_RELEASE:=1

PYPI_NAME:=Flask-Migration
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/75/3e/5675d46efdb62eb369bc951c7107657bea9ddf20cea65dab9816dc27e6ee/Flask-Migrate-2.5.3.tar.gz
PKG_HASH:=bfc7150eaf809b1c283879302f04c42791136060c6eeb12c0c6674fb1291fae5
PKG_SOURCE=Flask-Migration-2.5.3.tar.gz

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask_migration
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Flask Migration
  URL:=https://pypi.org/project/Flask-Migrate/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-flask_migration/description
  SQLAlchemy database migrations for Flask applications using Alembic.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
