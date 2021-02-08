include $(TOPDIR)/rules.mk

PKG_NAME:=mako
PKG_VERSION:=1.1.4
PKG_RELEASE:=1

PYPI_NAME:=Mako
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/5c/db/2d2d88b924aa4674a080aae83b59ea19d593250bfe5ed789947c21736785/
PKG_HASH:=17831f0b7087c313c0ffae2bcbbd3c1d5ba9eeac9c38f2eb7b50e8c99fe9d5ab
PKG_SOURCE=Mako-1.1.4.tar.gz

PKG_MAINTAINER:=Michael Richardson
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/../feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/python/python3-package.mk

define Package/python3-mako
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Mako
  URL:=https://pypi.org/project/mako/
  DEPENDS:=+python3
  VARIANT:=python3
  #PYTHON3_PKG_SETUP_ARGS:=
endef

define Package/python3-mako/description
     Mako is a template library written in Python. It provides a familiar,
     non-XML syntax which compiles into Python modules for maximum
     performance. Mako’s syntax and API borrows from the best ideas of many
     others, including Django templates, Cheetah, Myghty, and
     Genshi. Conceptually, Mako is an embedded Python (i.e. Python Server
     Page) language, which refines the familiar ideas of componentized layout
     and inheritance to produce one of the most straightforward and flexible
     models available, while also maintaining close ties to Python calling
     and scoping semantics.
endef

$(eval $(call Py3Package,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}))
$(eval $(call BuildPackage,python3-${PKG_NAME}-src))
