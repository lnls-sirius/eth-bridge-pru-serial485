#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.

CLIENT SIDE - PRUserial485 via Ethernet bridge
Author: Patricia Nallin

Release Date:
18/july/2020

Bytes:
- 0: command
- 1..4: payload length
- 5.. : payload
"""

import socket
import struct
from threading import Thread, Event
from queue import Queue, Empty

import PRUserial485.consts as _c


SERVER_PORT_RW = 5000
SERVER_PORT_GENERAL = 6000
DEFAULT_TIMEOUT = 1  # [s]


class ConstReturn:
    """Namespace for return constants."""

    SYNC_OFF = 0  # sync_status
    SYNC_ON = 1  # sync_status
    OK = 0
    ERR_CLEAR_PULSE = 1  # clear_pulse_count_sync
    ERR_LD_CURVE_MOPEN = 2  # loadCurve
    ERR_LD_CURVE_MMAP = 3  # loadCurve
    ERR_LD_CURVE_UMMAP = 4  # loadCurve
    ERR_INIT_PRU_SSDRV = 5  # init_start_PRU
    ERR_INIT_PRU_MODE = 6  # init_start_PRU
    ERR_INIT_PRU_BAUDR = 7  # init_start_PRU
    ERR_RECV_DATA_OLDMSG = 8  # recv_data_PRU


class ConstSyncMode:
    """Namespace for PRU sync modes."""

    MIGINT = 0x51  # Single curve sequence & Read msgs at End of curve
    MIGEND = 0x5E  # Single curve sequence & Read msgs at End of curve
    RMPINT = 0xC1  # Contin. curve sequence & Intercalated read messages
    RMPEND = 0xCE  # Contin. curve sequence & Read msgs at End of curve
    BRDCST = 0x5B  # Single Sequence - Single Broadcast Function command
    ALL = (MIGINT, MIGEND, RMPINT, RMPEND, BRDCST)


class _EthBridgeClientCommonInterface:
    """."""

    pack_float = struct.Struct(">f").pack

    def __init__(self, ip_address):
        """."""
        # IP
        self._bbb_ip = self._check_ip_address(ip_address)
        #self._bbb_ip = ip_address
        self.socket = None

    def open(self, baudrate: int = 6, mode: bytes = b"M") -> int:
        """Procedimento de inicialização da PRU."""
        if (mode in _c.AVAILABLE_MODES) and (baudrate in _c.AVAILABLE_BAUDRATES):
            payload = _c.COMMAND_PRUserial485_open + mode + struct.pack(">I", baudrate)
            command, payload_recv = self._send_communication_data(payload)

            if command == ord(_c.COMMAND_PRUserial485_open) and len(payload_recv) == 1:
                return payload_recv[0]
            else:
                raise ValueError("Failed to open connection, invalid reply received: {}".format(payload_recv))

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
            raise TimeoutError("Timeout while waiting for power supply reply")
        if not payload_recv or payload_recv[0] == _c.ANSWER_NOQUEUE[0]:
            raise ValueError("No item in queue to be read")

        data = [chr(i) for i in payload_recv[1:]]

        if command == _c.COMMAND_PRUserial485_read[0]:
            return data
        else:
            raise ValueError(
                "Unexpected command {} returned ({} expected)".format(_c.COMMAND_PRUserial485_read[0], command)
            )

    def write(self, data=[], timeout: float = 2) -> int:
        """Envia dados através da interface serial."""
        # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
        payload = _c.COMMAND_PRUserial485_write + self.pack_float(timeout)
        payload += bytearray(map(ord, data))
        command, payload_recv = self._send_communication_data(payload)

        if not payload_recv or payload_recv[0] != _c.ANSWER_OK[0]:
            raise TimeoutError("Timeout while waiting for power supply reply")

        if command == _c.COMMAND_PRUserial485_write[0] and len(payload_recv) == 2:
            return payload_recv[1]
        else:
            raise ValueError(
                "Unexpected command {} returned ({} expected)".format(_c.COMMAND_PRUserial485_write[0], command)
            )

    def request(self, data=[], timeout: float = 2) -> list:
        """Envia dados através da interface serial e ja recebe a resposta."""
        # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
        payload = _c.COMMAND_PRUserial485_request + self.pack_float(timeout)
        payload += bytearray(map(ord, data))
        command, payload_recv = self._send_communication_data(payload)

        if not payload_recv or payload_recv[0] != _c.ANSWER_OK[0]:
            raise TimeoutError("Timeout while waiting for power supply reply")

        data = [chr(i) for i in payload_recv[1:]]

        if command == _c.COMMAND_PRUserial485_request[0]:
            return data
        else:
            raise ValueError(
                "Unexpected command {} returned ({} expected)".format(_c.COMMAND_PRUserial485_request[0], command)
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
        if command == ord(_c.COMMAND_PRUserial485_server_eth_version) and payload_recv:
            return payload_recv.decode()
        else:
            return None

    def address(self):
        """Retorna endereco fisico da placa."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_address
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_address) and len(payload_recv) == 1:
            return ord(payload_recv)
        else:
            return None

    # --- aux. methods ---
    @staticmethod
    def _check_ip_address(ip_address):
        """Define beaglebone IP address."""
        if (ip_address.startswith("10.128") or ip_address.startswith("10.0.38")) and len(ip_address.split(".")) == 4:
            return ip_address
        else:
            raise ValueError("Invalid IP")

    @staticmethod
    def _payload_length(payload):
        """Inserts payload length at payload's second byte"""
        return struct.pack("B", payload[0]) + struct.pack(">I", (len(payload) - 1)) + payload[1:]

    def _socket_connect(self, conn_port):
        """Creates socket connection"""
        if self._bbb_ip is None:
            raise ValueError("BeagleBone IP address undefined!")

        if self.socket is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(DEFAULT_TIMEOUT)

        self.socket.connect((self._bbb_ip, conn_port))
        self.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    def _send_communication_data(self, payload):
        _ = payload
        return b"", b""


class EthBridgeClientComplete(_EthBridgeClientCommonInterface):
    """."""

    def __init__(self, ip_address, use_general=True):
        """."""
        super().__init__(ip_address)

        # Dictionary for COMM_RESPONSE
        self._comm_response = {}

        self._use_general = use_general

        # Queues
        self._queue_rw = Queue()
        if self._use_general:
            self._queue_general = Queue()

        self._thread_cmd_rw, self._thread_cmd_general = self._threads_create()

        self._close = False

    def close(self):
        """Finish PRU."""
        # Payload: none
        super().close()
        self._close = True

    def threads_start(self):
        """."""
        self._thread_cmd_rw.start()
        if self._use_general:
            self._thread_cmd_general.start()

    # ---

    def curve(self, curve1, curve2, curve3, curve4, block=0):
        """Loads curve"""
        # Payload: BLOCK (1 byte) +
        if len(curve1) == len(curve2) == len(curve3) == len(curve4) and block in _c.AVAILABLE_CURVE_BLOCKS:
            payload = _c.COMMAND_PRUserial485_curve + struct.pack("B", block)
            data1 = (struct.pack(">f", point) for point in curve1)
            data2 = (struct.pack(">f", point) for point in curve2)
            data3 = (struct.pack(">f", point) for point in curve3)
            data4 = (struct.pack(">f", point) for point in curve4)
            payload += b"".join(data1) + b"".join(data2) + b"".join(data3) + b"".join(data4)
            command, payload_recv = self._send_communication_data(payload)
            if command == ord(_c.COMMAND_PRUserial485_curve) and len(payload_recv) == 1:
                return ord(payload_recv)
            else:
                return None

    def set_curve_block(self, block=0):
        """Sets curve block that will be used"""
        # Payload: BLOCK (1 byte)
        if block in _c.AVAILABLE_CURVE_BLOCKS:
            payload = _c.COMMAND_PRUserial485_set_curve_block + struct.pack("B", block)
            self._send_communication_data(payload)

    def read_curve_block(self):
        """Reads curve block that will be used"""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_read_curve_block
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_read_curve_block) and len(payload_recv) == 1:
            return ord(payload_recv)
        else:
            return None

    def set_curve_pointer(self, pointer: int = 0):
        """Sets curve pointer to the next point (in the curve) to be processed"""
        # Payload: POINTER (4 bytes)
        if pointer > 0:
            payload = _c.COMMAND_PRUserial485_set_curve_pointer + struct.pack(">I", pointer)
            self._send_communication_data(payload)

    def read_curve_pointer(self):
        """Leitura do ponteiro de curva (proximo ponto que sera executado)."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_read_curve_pointer
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_read_curve_pointer) and len(payload_recv) == 4:
            return struct.unpack(">I", payload_recv)[0]
        else:
            return None

    def sync_start(self, sync_mode, delay: int, sync_address: int = 0x00):
        """Inicia operação em modo síncrono."""
        # Payload: SYNC_MODE (1 byte) + DELAY (4 bytes) + SYNC_ADDRESS (1 byte)
        if (sync_mode in _c.AVAILABLE_SYNC_MODES) and (delay >= 0) and (sync_address >= 0):
            payload = (
                _c.COMMAND_PRUserial485_sync_start
                + struct.pack("B", sync_mode)
                + struct.pack(">I", delay)
                + struct.pack("B", sync_address)
            )
            self._send_communication_data(payload)

    def sync_stop(self):
        """Finaliza a operação em modo síncrono."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_sync_stop
        self._send_communication_data(payload)

    def sync_status(self):
        """Verifica se sincronismo via PRU está aguardando pulso."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_sync_status
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_sync_status) and len(payload_recv) == 1:
            if ord(payload_recv) == 0:
                return False
            else:
                return True
        else:
            return None

    def read_pulse_count_sync(self):
        """Leitura do contador de pulsos - Sync."""
        # Payload: none
        payload = _c.COMMAND_PRUserial485_read_pulse_count_sync
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_read_pulse_count_sync) and len(payload_recv) == 4:
            return struct.unpack(">I", payload_recv)[0]
        else:
            return None

    def clear_pulse_count_sync(self):
        # Payload: none
        """Zera contador de pulsos - Sync."""
        payload = _c.COMMAND_PRUserial485_clear_pulse_count_sync
        command, payload_recv = self._send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_clear_pulse_count_sync) and len(payload_recv) == 1:
            return ord(payload_recv)
        else:
            return None

    # --- aux. methods ---

    def _threads_create(self):
        """."""
        thread_cmd_rw = Thread(target=self._socket_communicate, args=(SERVER_PORT_RW, self._queue_rw))
        thread_cmd_rw.setDaemon(True)
        if self._use_general:
            thread_cmd_general = Thread(
                target=self._socket_communicate, args=(SERVER_PORT_GENERAL, self._queue_general)
            )
            thread_cmd_general.setDaemon(True)
        else:
            thread_cmd_general = None

        return thread_cmd_rw, thread_cmd_general

    def _socket_communicate(self, conn_port, data_queue):
        """."""
        # Create socket connection
        if self._bbb_ip is None:
            raise ValueError("BeagleBone IP address undefined!")

        self._socket_connect(conn_port)
        remote_socket_connected = True

        while not self._close:

            # get queue item
            try:
                item = data_queue.get(block=True, timeout=1.0)
            except Empty:
                continue

            # command = item[0]
            sending_data = item[1]
            report_event = item[2]

            # Try reconnecting 3 times if remote socket is not available
            for _ in range(3):
                if not remote_socket_connected:
                    try:
                        self._socket_connect(conn_port)
                        remote_socket_connected = True
                    except Exception:
                        continue

                if remote_socket_connected:
                    try:
                        self.socket.sendall(EthBridgeClientComplete._payload_length(sending_data))
                        break
                    except Exception:
                        remote_socket_connected = False
                        self.socket = None

            # Receive prefix: command (1 byte) + data_size (4 bytes)
            answer = None
            if remote_socket_connected:
                try:
                    answer = self.socket.recv(5)
                except ConnectionResetError:
                    # This except might happen when server is suddenly stopped
                    answer = []

            if answer:
                command_recv = answer[0]
                data_size = struct.unpack(">I", answer[1:])[0]
            else:
                command_recv = b""
                data_size = 0

            # Receive data/payload
            payload = b""
            if data_size:
                try:
                    for _ in range(int(data_size / 4096)):
                        payload += self.socket.recv(4096, socket.MSG_WAITALL)
                    payload += self.socket.recv(int(data_size % 4096), socket.MSG_WAITALL)
                except ConnectionResetError:
                    # This except might happen when server is suddenly stopped
                    payload = b""

            # Store answer and notify function
            self._comm_response[report_event] = (command_recv, payload)
            report_event.set()

        # close socket
        self.socket.close()

    def _send_communication_data(self, payload):
        """."""
        # Creates notification event
        notification_event = Event()

        # Add command into queue
        if payload[0] == ord(_c.COMMAND_PRUserial485_write) or payload[0] == ord(_c.COMMAND_PRUserial485_read):
            self._queue_rw.put([payload[0], payload, notification_event])
        else:
            self._queue_general.put([payload[0], payload, notification_event])

        # Wait command complete. Get answer and delete event
        notification_event.wait()
        notification_event.clear()
        command, payload_recv = self._comm_response.pop(notification_event, None)
        del notification_event

        return command, payload_recv


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
        self._socket_connect(SERVER_PORT_RW)

    # --- aux. methods ---

    def _send_communication_data(self, payload):
        """."""
        datalen = EthBridgeClient._payload_length(payload)

        # values to be returned in case of unsuccessfull sending data
        command_recv = b""
        payload = b""

        try:
            self.socket.sendall(datalen)
        except socket.timeout:
            raise TimeoutError("Timeout while communicating with socket")  # raise same exception
        except Exception:
            self.socket = None
            for _ in range(3):
                # Try reconnecting 3 times if remote socket is not available
                try:
                    self.connect_socket()
                    self.socket.sendall(datalen)
                    break
                except socket.timeout:
                    raise TimeoutError("Timeout while communicating with socket")  # raise same exception
                except Exception:
                    self.socket = None
            else:
                return command_recv, payload

        # Receive prefix: command (1 byte) + data_size (4 bytes)
        try:
            answer = self.socket.recv(5)
        except socket.timeout:
            raise TimeoutError("Timeout while communicating with socket")  # raise same exception
        except ConnectionResetError:
            # This except might happen when server is suddenly stopped
            answer = []

        if answer:
            command_recv = answer[0]
            data_size = struct.unpack(">I", answer[1:])[0]
        else:
            return command_recv, payload

        # Receive data/payload
        if data_size:
            try:
                for _ in range(int(data_size / 4096)):
                    payload += self.socket.recv(4096, socket.MSG_WAITALL)
                payload += self.socket.recv(int(data_size % 4096), socket.MSG_WAITALL)
            except socket.timeout:
                raise TimeoutError("Timeout while communicating with socket")  # raise same exception
            except ConnectionResetError:
                # This except might happen when server is suddenly stopped
                return command_recv, payload

        return command_recv, payload
