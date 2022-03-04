include $(TOPDIR)/rules.mk

PKG_NAME:=mako
PKG_VERSION:=1.1.6
PKG_RELEASE:=1

PYPI_NAME:=Mako
PKG_SOURCE_URL=https://files.pythonhosted.org/packages/af/b6/42cd322ae555aa770d49e31b8c5c28a243ba1bbb57ad927e1a5f5b064811
PKG_HASH:=4e9e345a41924a954251b95b4b28e14a301145b544901332e658907a7464b6b2
PKG_SOURCE=Mako-1.1.6.tar.gz

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
