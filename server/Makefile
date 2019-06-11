PREFIX ?= /usr/local

SERVICE_FILE_DEST = /etc/systemd/system
SERVICE_NAME_GENERAL = bridge-pru-serial485-general
SERVICE_NAME_RW = bridge-pru-serial485-rw

.PHONY: install uninstall


install:
	# Install Service
	cp --preserve=mode services/${SERVICE_NAME_GENERAL}.service ${SERVICE_FILE_DEST}
	cp --preserve=mode services/${SERVICE_NAME_RW}.service ${SERVICE_FILE_DEST}

	systemctl daemon-reload


uninstall:
	systemctl stop ${SERVICE_NAME_GENERAL}
	systemctl stop ${SERVICE_NAME_RW}

	rm -f ${SERVICE_FILE_DEST}/${SERVICE_NAME_GENERAL}.service
	rm -f ${SERVICE_FILE_DEST}/${SERVICE_NAME_RW}.service


	systemctl daemon-reload

