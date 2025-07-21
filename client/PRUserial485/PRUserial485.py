#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Ethernet bridge for PRUserial485 library.

CLIENT SIDE - PRUserial485 via Ethernet bridge
Author: Patricia Nallin

Release Date:
18/july/2020

Bytes:
- 0: command
- 1..4: payload length
- 5.. : payload
"""

import logging as _log
import socket
import struct

import PRUserial485.consts as _c

SERVER_PORT = 5000
DEFAULT_TIMEOUT = 1  # [s]


class _EthBridgeClientCommonInterface:
    """."""

    pack_float = struct.Struct('>f').pack

    def __init__(self, ip_address):
        """."""
        # IP
        self._bbb_ip = self._check_ip_address(ip_address)
        # self._bbb_ip = ip_address
        self.socket = None
        self.msg_id = 0

    def open(self, baudrate: int = 6, mode: bytes = b'M') -> int:
        """Procedimento de inicialização da PRU."""
        if (mode in _c.AVAILABLE_MODES) and (
            baudrate in _c.AVAILABLE_BAUDRATES
        ):
            payload = (
                _c.COMMAND_PRUserial485_open
                + mode
                + struct.pack('>I', baudrate)
            )
            command, payload_recv = self._send_communication_data(payload)

            if (
                command == ord(_c.COMMAND_PRUserial485_open)
                and len(payload_recv) == 1
            ):
                return payload_recv[0]
            else:
                raise ValueError(
                    'Failed to open connection, '
                    'invalid reply received: {}'.format(payload_recv)
                )

    def close(self):
        """Encerra a PRU."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_close
        self._send_communication_data(payload)

    def read(self) -> list:
        """Recebe dados através da interface serial."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_read
        command, payload_recv = self._send_communication_data(payload)

        if not payload_recv or payload_recv[0] == _c.ANSWER_ERR[0]:
            raise TimeoutError('Timeout while waiting for power supply reply')
        if not payload_recv or payload_recv[0] == _c.ANSWER_NOQUEUE[0]:
            raise ValueError('No item in queue to be read')

        data = [chr(i) for i in payload_recv[1:]]

        if command == _c.COMMAND_PRUserial485_read[0]:
            return data
        else:
            raise ValueError(
                'Unexpected command {} returned ({} expected)'.format(
                    _c.COMMAND_PRUserial485_read[0], command
                )
            )

    def write(self, data=None, timeout: float = 2) -> int:
        """Envia dados através da interface serial."""
        data = data or []
        # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
        payload = _c.COMMAND_PRUserial485_write + self.pack_float(timeout)
        payload += bytearray(map(ord, data))
        command, payload_recv = self._send_communication_data(payload)

        if not payload_recv or payload_recv[0] != _c.ANSWER_OK[0]:
            raise TimeoutError('Timeout while waiting for power supply reply')

        if (
            command == _c.COMMAND_PRUserial485_write[0]
            and len(payload_recv) == 2
        ):
            return payload_recv[1]
        else:
            raise ValueError(
                'Unexpected command {} returned ({} expected)'.format(
                    _c.COMMAND_PRUserial485_write[0], command
                )
            )

    def request(self, data=None, timeout: float = 2) -> list:
        """Envia dados através da interface serial e ja recebe a resposta."""
        data = data or []
        # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
        payload = _c.COMMAND_PRUserial485_request + self.pack_float(timeout)
        payload += bytearray(map(ord, data))
        command, payload_recv = self._send_communication_data(payload)

        if not payload_recv or payload_recv[0] != _c.ANSWER_OK[0]:
            raise TimeoutError('Timeout while waiting for power supply reply')

        data = [chr(i) for i in payload_recv[1:]]

        if command == _c.COMMAND_PRUserial485_request[0]:
            return data
        else:
            raise ValueError(
                'Unexpected command {} returned ({} expected)'.format(
                    _c.COMMAND_PRUserial485_request[0], command
                )
            )

    def version(self):
        """Return version."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_version
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_version) and payload_recv:
            return payload_recv.decode()
        else:
            return None

    def server_version(self):
        """Return version."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_server_eth_version
        command, payload_recv = self._send_communication_data(payload)
        if (
            command == ord(_c.COMMAND_PRUserial485_server_eth_version)
            and payload_recv
        ):
            return payload_recv.decode()
        else:
            return None

    def address(self):
        """Retorna endereco fisico da placa."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_address
        command, payload_recv = self._send_communication_data(payload)
        if (
            command == ord(_c.COMMAND_PRUserial485_address)
            and len(payload_recv) == 1
        ):
            return ord(payload_recv)
        else:
            return None

    # --- aux. methods ---
    @staticmethod
    def _check_ip_address(ip_address):
        """Define beaglebone IP address."""
        if (
            ip_address.startswith('10.128') or ip_address.startswith('10.0.38')
        ) and len(ip_address.split('.')) == 4:
            return ip_address
        else:
            raise ValueError('Invalid IP')

    @staticmethod
    def _payload_length(payload, msg_id):
        """Inserts payload length at payload's second byte."""
        return (
            struct.pack('B', payload[0])  # function code 1 byte
            + struct.pack('B', msg_id)  # message id 1 byte
            + struct.pack('>I', (len(payload) - 1))  # size 4 bytes
            + payload[1:]  # message
        )

    def _socket_connect(self, conn_port):
        """Create socket connection."""
        if self._bbb_ip is None:
            raise ValueError('BeagleBone IP address undefined!')

        if self.socket is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(DEFAULT_TIMEOUT)

        self.socket.connect((self._bbb_ip, conn_port))
        self.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    def _send_communication_data(self, payload):
        _ = payload
        return b'', b''


class EthBridgeClient(_EthBridgeClientCommonInterface):
    """."""

    def __init__(self, ip_address):
        """."""
        super().__init__(ip_address)

        # NOTE: Should I connect here with option #1, #2 or should I leave
        # it for the first interaction with the server?
        self.connect_socket()  # #1
        # Thread(target=self.connect_socket, daemon=True).start()  # #2

    def close(self):
        """Encerra a PRU."""
        super().close()
        self.close_socket()

    def close_socket(self):
        """Close socket connection."""
        # close socket
        self.socket.close()

    def connect_socket(self):
        """Open a socket connection."""
        self._socket_connect(SERVER_PORT)

    # --- aux. methods ---

    def _send_communication_data(self, payload):
        """."""
        datalen = EthBridgeClient._payload_length(payload, self.msg_id)

        # values to be returned in case of unsuccessfull sending data
        command_recv = b''
        payload = b''

        try:
            self.socket.sendall(datalen)
        except socket.timeout:
            _log.warning('socket timeout while trying sendall...')
            raise
        except Exception as err0:
            _log.warning('exception while trying sendall: ' + str(err0))
            self.socket = None
            for _ in range(3):
                # Try reconnecting 3 times if remote socket is not available
                try:
                    self.connect_socket()
                    self.socket.sendall(datalen)
                    break
                except socket.timeout:
                    _log.warning(
                        'socket timeout while after first exception...'
                    )
                    raise
                except Exception:
                    _log.warning('second exception after first exception...')
                    self.socket = None
            else:
                return command_recv, payload

        while True:
            command_recv, msg_id, payload = self._read_communication_data()
            if msg_id is None or msg_id == self.msg_id:
                break

        self.msg_id = (self.msg_id + 1) % 256
        return command_recv, payload

    def _read_communication_data(self):
        command_recv = b''
        payload = b''
        # Receive prefix: command (1 byte) + data_size (4 bytes)
        try:
            answer = self.socket.recv(6)
        except socket.timeout:
            _log.warning('socket timeout while trying recv(6)...')
            raise
        except ConnectionResetError:
            # This except might happen when server is suddenly stopped
            _log.warning('conn reset error while trying recv(6)...')
            answer = []

        if answer:
            command_recv = answer[0]
            msg_id = answer[1]
            data_size = struct.unpack('>I', answer[2:])[0]
        else:
            return command_recv, None, payload

        # Receive data/payload
        if data_size:
            try:
                for _ in range(int(data_size / 4096)):
                    payload += self.socket.recv(4096, socket.MSG_WAITALL)
                payload += self.socket.recv(
                    int(data_size % 4096), socket.MSG_WAITALL
                )
            except socket.timeout:
                _log.warning('socket timeout while processing data...')
                raise
            except ConnectionResetError:
                # This except might happen when server is suddenly stopped
                _log.warning('conn reset error while processing data...')
                return command_recv, msg_id, payload

        return command_recv, msg_id, payload
