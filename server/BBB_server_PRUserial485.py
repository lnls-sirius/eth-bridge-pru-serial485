#!/usr/bin/python-sirius
# -*- coding: utf-8 -*-

"""Ethernet bridge for PRUserial485 library.
SERVER SIDE - BEAGLEBONE BLACK SCRIPT
Author: Patricia Nallin


"""

import logging
import os.path
import socket
import struct
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from queue import Queue

import PRUserial485 as _lib

sys.path.append(os.path.abspath(os.path.join(os.path.pardir, 'common')))
from consts import *

RELEASE_DATE = 'October/2024'

# TCP port for PRUserial485 bridge
SERVER_PORT = 5000
DAEMON_PORT = 5500

# Multi-client variables
global connected_clients, read_data
connected_clients = []
read_data = {}

# Initialize PRUserial485 - may be reinitialized if needed
_lib.PRUserial485_open(6, b'M')
_lib.PRUserial485_write(b'\x00', 0)

global logger


def payload_length(payload) -> bytes:
    """."""
    return (
        struct.pack('B', payload[0])
        + struct.pack('B', payload[1])
        + struct.pack('>I', (len(payload) - 1))
        + payload[2:]
    )


def validate_answer(payload: bytes, sent: bytes = b'unknown command') -> bytes:
    if payload == b'' or not isinstance(payload, bytes):
        logger.error('Received empty response for {}'.format(sent))
        if not payload:
            return ANSWER_NOQUEUE
        return ANSWER_ERR + payload
    else:
        return ANSWER_OK + payload


def processThread():
    global read_data
    unpack_float = struct.Struct('>f').unpack
    pack_unsigned_byte = struct.Struct('B').pack

    while True:
        # Get next operation
        item = queue.get(block=True)
        item[0] = pack_unsigned_byte(item[0])
        msg_id = pack_unsigned_byte(item[1])
        client = item[3]
        answer = b''

        # Verification and implementation
        if item[0] == COMMAND_PRUserial485_write:
            timeout = unpack_float(item[2][:4])[0]
            data = item[2][4:]
            res = _lib.PRUserial485_write(data, timeout)

            read_data[client] = _lib.PRUserial485_read()
            answer = validate_answer(pack_unsigned_byte(res), data)

        elif item[0] == COMMAND_PRUserial485_read:
            answer = validate_answer(read_data[client], b'read')

        elif item[0] == COMMAND_PRUserial485_request:
            timeout = unpack_float(item[2][:4])[0]
            data = item[2][4:]
            res = _lib.PRUserial485_write(data, timeout)
            answer = validate_answer(_lib.PRUserial485_read(), data)
        client.sendall(payload_length(item[0] + msg_id + answer))


def clientThread(client_connection, client_info, conn_port):
    global connected_clients, read_data
    connected_clients.append(client_info)
    read_data[client_connection] = []

    try:
        while True:
            # Message header - Operation command (1 byte) + data size (4 bytes)
            data = client_connection.recv(6)

            if len(data) == 6:
                command = data[0]
                msg_id = data[1]
                data_size = struct.unpack('>I', data[2:])[0]

                # Get message
                message = b''

                # Wait max 500 ms until complete message is received
                client_connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVTIMEO,
                    struct.pack('ll', 0, 500000),
                )

                for i in range(int(data_size / 4096)):
                    message += client_connection.recv(4096, socket.MSG_WAITALL)
                message += client_connection.recv(
                    int(data_size % 4096), socket.MSG_WAITALL
                )

                # Reset blocking socket
                client_connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVTIMEO,
                    struct.pack('ll', 0, 0),
                )

                # Put operation in Queue
                if len(message) == data_size:
                    if (conn_port == SERVER_PORT) and any(
                        [ord(cmd) == command for cmd in COMMANDS]
                    ):
                        queue.put(
                            [command, msg_id, message, client_connection]
                        )
                    else:
                        ans = struct.pack('B', command) + msg_id + ANSWER_ERR
                        client_connection.sendall(payload_length(ans))
            else:
                connected_clients.remove(client_info)
                read_data.pop(client_connection)
                logger.info(
                    'Client {}:{} disconnected on port {}.'.format(
                        client_info[0], client_info[1], conn_port
                    )
                )
                break

    except Exception as e:
        connected_clients.remove(client_info)
        read_data.pop(client_connection)
        logger.info(e)
        logger.info(
            'Client {}:{} disconnected on port {}.'.format(
                client_info[0], client_info[1], conn_port
            )
        )


def connectionThread(conn_port):
    global connected_clients
    while True:
        try:
            # Opens TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('', conn_port))
            server_socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            server_socket.listen(5)
            logger.info(
                'TCP/IP server on port '
                '{} started and waiting for connection'.format(conn_port)
            )

            while True:
                # Wait for client connection
                connection, client_info = server_socket.accept()

                # 'Keep alive' option to prevent/close ghost connections
                connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1
                )  # Enable KeepAlive functionality
                connection.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1
                )  # Wait 1 sec before testing keepalive
                connection.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3
                )  # Retry keepalive after 3 secs
                connection.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3
                )  # Retry keepalive 3 times

                # Create client listening thread
                logger.info(
                    'Port {}: client {}:{} connected'.format(
                        conn_port, client_info[0], client_info[1]
                    )
                )

                new_client_thread = threading.Thread(
                    target=clientThread,
                    args=[connection, client_info, conn_port],
                )
                new_client_thread.setDaemon(True)
                new_client_thread.start()

        except Exception:
            server_socket.close()
            logger.error('Connection problem on port {}: ', exc_info=True)
            time.sleep(5)


def daemon_server():
    while True:
        try:
            # Opens a Daemon TCP/IP socket - To signalize whether
            # server is available
            daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            daemon_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            daemon_socket.bind(('', DAEMON_PORT))
            daemon_socket.listen(1)
            logger.info(
                'TCP/IP daemon server on port {} started\n'.format(DAEMON_PORT)
            )

            while True:
                daemon_socket.accept()

        except Exception:
            daemon_socket.close()
            logger.error(
                'Connection problem on daemon port {}: ', exc_info=True
            )
            time.sleep(1)


if __name__ == '__main__':
    logger = logging.getLogger('eth-bridge')
    formatter = logging.Formatter(
        '%(asctime)-15s - (%(name)s) %(levelname)s - %(message)s',
        datefmt='%d/%m/%Y %H:%M:%S',
    )

    file_handler = RotatingFileHandler(
        LOG_FILE_PATH, maxBytes=15000000, backupCount=5
    )
    file_handler.setFormatter(formatter)

    if not logger.hasHandlers():
        logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)

    logger.info(
        '----- TCP/IP SERVER FOR PRUSERIAL485 '
        '(Ethernet bridge for PRUserial485) -----'
    )
    logger.info('----- Release date: {} -----'.format(RELEASE_DATE))

    queue = Queue()

    # Create and start process threads
    process = threading.Thread(target=processThread)
    process.setDaemon(True)
    process.start()

    # Create and start connection threads
    connection = threading.Thread(target=connectionThread, args=[SERVER_PORT])
    connection.setDaemon(True)
    connection.start()

    while True:
        time.sleep(10)
