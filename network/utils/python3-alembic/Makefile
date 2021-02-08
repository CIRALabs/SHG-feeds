include $(TOPDIR)/rules.mk

PKG_NAME:=alembic
PKG_VERSION:=1.4.3
PKG_RELEASE:=2

PYPI_NAME:=alembic
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/cd/f5/705578ee067b92bcfbda4ca1122bdf8c7387dc2c691f1a9d39f18d78f84c
PKG_HASH:=5334f32314fb2a56d86b4c4dd1ae34b08c03cae4cb888bc699942104d66bc245
PKG_SOURCE=alembic-1.4.3.tar.gz

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk



define Package/python3-alembic
  DEPENDS:=+python3-mako +python3-dateutil
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Alembic
  URL:=https://pypi.org/project/alembic/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-alembic/description
   Alembic is a database migrations tool written by the author of SQLAlchemy.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
