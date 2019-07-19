PREFIX ?= /usr/local

SERVICE_FILE_DEST = /etc/systemd/system
SERVICE_NAME = eth-bridge-pru-serial485

.PHONY: install uninstall


install:
	# Install Service
	cp --preserve=mode services/${SERVICE_NAME}.service ${SERVICE_FILE_DEST}

	systemctl daemon-reload


uninstall:
	systemctl stop ${SERVICE_NAME}

	rm -f ${SERVICE_FILE_DEST}/${SERVICE_NAME}.service


	systemctl daemon-reload

