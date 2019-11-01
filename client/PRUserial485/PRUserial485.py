#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.

CLIENT SIDE - PRUserial485 via Ethernet bridge
Author: Patricia Nallin

Release Date:
06/aug/2019

Bytes:
- 0: command
- 1..4: payload length
- 5.. : payload

Note: library clients should first
       a) invoke function "PRUserial_set_bbb_ip_address" and
       b) invoke function "PRUserial485_threads_start",
      before using communication functions.
"""

import socket
import struct
from threading import Thread, Event
from queue import Queue
from PRUserial485 import constants_PRUserial485_bridge as _c


SERVER_PORT_RW = 5000
SERVER_PORT_GENERAL = 6000


# BeagleBone IP
BBB_IP = None


# Queues
QUEUE_GENERAL = Queue()
QUEUE_RW = Queue()

# Dictionary for COMM_RESPONSE
COMM_RESPONSE = {}


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


# --- auxilliary functions ---


def _payload_length(payload):
    """."""
    return(struct.pack("B", payload[0]) +
           struct.pack(">I", (len(payload)-1)) + payload[1:])


def _socket_communicate(conn_port, data_queue):
    """."""
    # Create socket connection
    if BBB_IP is None:
        raise ValueError('BeagleBone IP address undefined!')

    remote_socket = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)
    remote_socket.connect((BBB_IP, conn_port))
    remote_socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    remote_socket_connected = True

    while True:
        item = data_queue.get(block=True)
        # command = item[0]
        sending_data = item[1]
        report_event = item[2]

        # Try reconnecting 3 times if remote socket is not available
        for _ in range(3):
            if not remote_socket_connected:
                try:
                    remote_socket.connect((BBB_IP, conn_port))
                    remote_socket.setsockopt(
                        socket.SOL_TCP, socket.TCP_NODELAY, 1)
                    remote_socket_connected = True
                except:
                    continue

            if remote_socket_connected:
                try:
                    remote_socket.sendall(_payload_length(sending_data))
                    break
                except:
                    remote_socket_connected = False
                    remote_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)

        # Receive prefix: command (1 byte) + data_size (4 bytes)
        if remote_socket_connected:
            try:
                answer = remote_socket.recv(5)
            except ConnectionResetError:
                # This except might happen when server is suddenly stopped
                answer = []

        if answer:
            command_recv = answer[0]
            data_size = struct.unpack(">I", answer[1:])[0]
        else:
            command_recv = b''
            data_size = 0

        # Receive data/payload
        payload = b''
        if data_size:
            try:
                for _ in range(int(data_size / 4096)):
                    payload += remote_socket.recv(4096, socket.MSG_WAITALL)
                payload += remote_socket.recv(
                    int(data_size % 4096), socket.MSG_WAITALL)
            except ConnectionResetError:
                # This except might happen when server is suddenly stopped
                payload = b''

        # Store answer and notify function
        COMM_RESPONSE[report_event] = (command_recv, payload)
        report_event.set()


def _send_communication_data(payload):
    """."""
    # Creates notification event
    notification_event = Event()

    # Add command into queue
    if payload[0] == ord(_c.COMMAND_PRUserial485_write) or \
       payload[0] == ord(_c.COMMAND_PRUserial485_read):
        QUEUE_RW.put([payload[0], payload, notification_event])
    else:
        QUEUE_GENERAL.put([payload[0], payload, notification_event])

    # Wait command complete. Get answer and delete event
    notification_event.wait()
    notification_event.clear()
    command, payload_recv = COMM_RESPONSE.pop(notification_event, None)
    del notification_event

    return command, payload_recv


# --- PRUserial485 API ---


def PRUserial485_set_bbb_ip_address(ip_address):
    """Define beaglebone IP address."""
    global BBB_IP
    BBB_IP = ip_address


def PRUserial485_open(baudrate=6, mode=b'M'):
    """Procedimento de inicialização da PRU."""
    if (mode in _c.AVAILABLE_MODES) and \
       (baudrate in _c.AVAILABLE_BAUDRATES):

        payload = _c.COMMAND_PRUserial485_open + \
            mode + struct.pack(">I", baudrate)

        command, payload_recv = _send_communication_data(payload)

        if command == ord(_c.COMMAND_PRUserial485_open) and \
           len(payload_recv) == 1:
            return ord(payload_recv)
        else:
            return None


def PRUserial485_close():
    """Encerra a PRU."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_close
    _send_communication_data(payload)


def PRUserial485_threads_start():
    """."""
    # create threads
    thread_cmd_general = \
        Thread(target=_socket_communicate,
               args=(SERVER_PORT_GENERAL, QUEUE_GENERAL))
    thread_cmd_general.setDaemon(True)
    thread_cmd_rw = \
        Thread(target=_socket_communicate,
               args=(SERVER_PORT_RW, QUEUE_RW))
    thread_cmd_rw.setDaemon(True)

    # start threads
    thread_cmd_general.start()
    thread_cmd_rw.start()


def PRUserial485_read():
    """Recebe dados através da interface serial."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read
    command, payload_recv = _send_communication_data(payload)
    data = [chr(i) for i in payload_recv]
    if command == ord(_c.COMMAND_PRUserial485_read):
        return data
    else:
        return None


def PRUserial485_write(data=None, timeout=0):
    """Envia dados através da interface serial."""
    # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
    if data is None:
        data = []
    payload = _c.COMMAND_PRUserial485_write + struct.pack(">f", timeout)
    payload += bytearray([ord(i) for i in data])
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_write) and \
       len(payload_recv) == 1:
        return ord(payload_recv)
    else:
        return None


def PRUserial485_version():
    """Return version."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_version
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_version) and payload_recv:
        return payload_recv.decode()
    else:
        return None


def PRUserial485_server_version():
    """Return version."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_server_eth_version
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_server_eth_version) and \
       payload_recv:
        return payload_recv.decode()
    else:
        return None


def PRUserial485_address():
    """Retorna endereco fisico da placa."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_address
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_address) and \
       len(payload_recv) == 1:
        return ord(payload_recv)
    else:
        return None


# --- Deprecated functions ---


def PRUserial485_curve(curve1, curve2, curve3, curve4, block=0):
    """Carregamento de curva."""
    # Payload: BLOCK (1 byte) +
    if len(curve1) == len(curve2) == len(curve3) == len(curve4) and block in \
       _c.AVAILABLE_CURVE_BLOCKS:
        payload = _c.COMMAND_PRUserial485_curve + struct.pack("B", block)
        payload += b''.join((struct.pack(">f", point) for point in curve1)) + \
                   b''.join((struct.pack(">f", point) for point in curve2)) + \
                   b''.join((struct.pack(">f", point) for point in curve3)) + \
                   b''.join((struct.pack(">f", point) for point in curve4))
        command, payload_recv = _send_communication_data(payload)
        if command == ord(_c.COMMAND_PRUserial485_curve) and \
           len(payload_recv) == 1:
            return ord(payload_recv)
        else:
            return None


def PRUserial485_set_curve_block(block=0):
    """Selecao de bloco de curva a ser realizado."""
    # Payload: BLOCK (1 byte)
    if block in _c.AVAILABLE_CURVE_BLOCKS:
        payload = _c.COMMAND_PRUserial485_set_curve_block + \
            struct.pack("B", block)
        _send_communication_data(payload)


def PRUserial485_read_curve_block():
    """Leitura do bloco de curva que sera realizado."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_curve_block
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_curve_block) and \
       len(payload_recv) == 1:
        return ord(payload_recv)
    else:
        return None


def PRUserial485_set_curve_pointer(pointer=0):
    """Ajusta ponteiro para proximo ponto a ser executado (curva)."""
    # Payload: POINTER (4 bytes)
    if pointer > 0:
        payload = _c.COMMAND_PRUserial485_set_curve_pointer + \
            struct.pack(">I", pointer)
        _send_communication_data(payload)


def PRUserial485_read_curve_pointer():
    """Leitura do ponteiro de curva (proximo ponto que sera executado)."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_curve_pointer
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_curve_pointer) and \
       len(payload_recv) == 4:
        return struct.unpack(">I", payload_recv)[0]
    else:
        return None


def PRUserial485_sync_start(sync_mode, delay, sync_address=0x00):
    """Inicia operação em modo síncrono."""
    # Payload: SYNC_MODE (1 byte) + DELAY (4 bytes) + SYNC_ADDRESS (1 byte)
    if (sync_mode in _c.AVAILABLE_SYNC_MODES) and (delay >= 0) and \
       (sync_address >= 0):
        payload = _c.COMMAND_PRUserial485_sync_start + \
            struct.pack("B", sync_mode) + struct.pack(">I", delay) + \
            struct.pack("B", sync_address)
        _send_communication_data(payload)


def PRUserial485_sync_stop():
    """Finaliza a operação em modo síncrono."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_sync_stop
    _send_communication_data(payload)


def PRUserial485_sync_status():
    """Verifica se sincronismo via PRU está aguardando pulso."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_sync_status
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_sync_status) and \
       len(payload_recv) == 1:
        if ord(payload_recv) == 0:
            return False
        else:
            return True
    else:
        return None


def PRUserial485_read_pulse_count_sync():
    """Leitura do contador de pulsos - Sync."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_pulse_count_sync
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_pulse_count_sync) and \
       len(payload_recv) == 4:
        return struct.unpack(">I", payload_recv)[0]
    else:
        return None


def PRUserial485_clear_pulse_count_sync():
    # Payload: none
    """Zera contador de pulsos - Sync."""
    payload = _c.COMMAND_PRUserial485_clear_pulse_count_sync
    command, payload_recv = _send_communication_data(payload)
    if command == ord(_c.COMMAND_PRUserial485_clear_pulse_count_sync) and \
       len(payload_recv) == 1:
        return ord(payload_recv)
    else:
        return None
