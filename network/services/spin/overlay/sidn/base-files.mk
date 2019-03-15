# Figure out the containing dir of this Makefile
OVERLAY_DIR:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Declare custom installation commands
define custom_install_commands
        @echo "Installing extra files from $(OVERLAY_DIR)"
        $(INSTALL_DIR) $(1)/etc/mosquitto
	$(INSTALL_DATA) $(OVERLAY_DIR)/etc/mosquitto.conf $(1)/etc/mosquitto/mosquitto.conf
endef

