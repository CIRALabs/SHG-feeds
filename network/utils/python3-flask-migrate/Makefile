include $(TOPDIR)/rules.mk

PKG_NAME:=Flask-Migrate
PKG_VERSION:=3.1.0
PKG_RELEASE:=1

PYPI_NAME:=$(PKG_NAME)
PKG_HASH:=57d6060839e3a7f150eaab6fe4e726d9e3e7cffe2150fb223d73f92421c6d1d9

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-flask-migrate
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Flask Migrate
  URL:=https://pypi.org/project/Flask-Migrate/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-flask-migrate/description
  SQLAlchemy database migrations for Flask applications using Alembic.
endef

$(eval $(call Py3Package,python3-flask-migrate))
$(eval $(call BuildPackage,python3-flask-migrate))
$(eval $(call BuildPackage,python3-flask-migrate-src))
