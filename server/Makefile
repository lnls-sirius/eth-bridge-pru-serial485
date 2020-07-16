PREFIX ?= /usr/local

SERVICE_FILE_DEST = /etc/systemd/system
SERVICE_NAME = eth-bridge-pru-serial485
SERVICE_C_NAME = c-eth-bridge-pru-serial485

.PHONY: install uninstall


install:
	# Install Service
        gcc -o teste -O3 -lPRUserial485 -lprussdrv -pthread teste-server.c
	cp --preserve=mode services/${SERVICE_NAME}.service ${SERVICE_FILE_DEST}
	cp --preserve=mode services/${SERVICE_C_NAME}.service ${SERVICE_FILE_DEST}

	systemctl daemon-reload


uninstall:
	systemctl stop ${SERVICE_NAME}
	systemctl stop ${SERVICE_C_NAME}
        rm -f teste
	rm -f ${SERVICE_FILE_DEST}/${SERVICE_NAME}.service
	rm -f ${SERVICE_FILE_DEST}/${SERVICE_C_NAME}.service


	systemctl daemon-reload

