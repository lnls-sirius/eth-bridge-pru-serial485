#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.

CLIENT SIDE - PRUserial485 via Ethernet bridge
Author: Patricia Nallin

Release Date:
05/jun/2019

Bytes:
- 0: command
- 1..4: payload length
- 5.. : payload
"""

# # It is a python module. It must not be run itself.
# if (__name__ == "__main__"):
#     exit()

import socket
import sys
import struct
from PRUserial485 import constants_PRUserial485_bridge as _c
from PRUserial485.functions_PRUserial485_bridge import find_BBB_IP \
    as _find_BBB_IP
from siriuspy import util as _util


SERVER_PORT = 5000  # TCP port for PRUserial485 bridge
BBB_NAME = ''
BBB_IP = '10.128.101.120'


# Constants
SOCKET_BUSY = True
SOCKET_IDLE = False
socket_status = SOCKET_IDLE

# Creating socket object
remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
remote_socket.close()


def set_beaglebone_ip(bbbname=None):
    """."""
    global remote_socket
    global BBB_NAME
    global BBB_IP

    if bbbname is None:
        bbbname = socket.gethostname()

    BBB_NAME = bbbname.replace('--', ':')
    BBB_IP = _find_BBB_IP(BBB_NAME)
    if BBB_IP == '':
        sys.stdout.write(_util.get_timestamp() +
                         ": Beaglebone IP not found. Please check BBB NAME\n")
        sys.stdout.flush()
        sys.exit()

    sys.stdout.write(_util.get_timestamp() + ": '" + BBB_NAME + "'" +
                     " will be connected on " + BBB_IP + "\n")
    sys.stdout.flush()



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


def payload_length(payload):
    """."""
    return(struct.pack("B", payload[0]) +
           struct.pack(">I", (len(payload)-1)) + payload[1:])


def socket_communicate(sending_data):
    """."""

    # Wait if there is another operation in use
    while(socket_status == SOCKET_BUSY):
        continue

    # Get socket control
    socket_status = SOCKET_BUSY
    remote_socket.sendall(payload_length(sending_data))

    # Receive prefix: command (1 byte) + data_size (4 bytes)
    answer = remote_socket.recv(5)
    command = answer[0]
    data_size = struct.unpack(">I", answer[1:])[0]

    # Receive data/payload
    payload = b''
    if(data_size):
        for i in range(int(data_size / 4096)):
            payload += remote_socket.recv(4096, socket.MSG_WAITALL)
        payload += remote_socket.recv(int(data_size % 4096), socket.MSG_WAITALL)

    # Free socket control
    socket_status = SOCKET_IDLE

    return command, payload


def PRUserial485_open(baudrate=6, mode=b'M'):
    """Procedimento de inicialização da PRU."""
    global remote_socket
    # Payload: MODE (1 byte) + BAUDRATE (4 bytes)
    for i in range(3):
        try:
            if remote_socket._closed:
                remote_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_STREAM)
                remote_socket.connect((BBB_IP, SERVER_PORT))
            if (mode in _c.AVAILABLE_MODES) and \
               (baudrate in _c.AVAILABLE_BAUDRATES):
                payload = _c.COMMAND_PRUserial485_open + \
                          mode + struct.pack(">I", baudrate)
                command, payload_recv = socket_communicate(payload)
                command = struct.pack("B",command)
                if (command == _c.COMMAND_PRUserial485_open) and (len(payload_recv) == 1):
                    return(payload_recv)
            return
        except:
            sys.stdout.write(_util.get_timestamp() + ": Restoring socket...\n")
            sys.stdout.flush()
            remote_socket.close()


def PRUserial485_address():
    """Retorna endereco fisico da placa."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_address
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_address) and len(payload_recv) == 1:
        return(payload_recv)


def PRUserial485_close():
    """Encerra a PRU."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_close
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_close) and len(payload_recv) == 0:
        remote_socket.close()


def PRUserial485_write(data=[], timeout=0):
    """Envia dados através da interface serial."""
    # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
    payload = _c.COMMAND_PRUserial485_write + struct.pack(">f", timeout)
    payload += bytearray([ord(i) for i in data])
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_write) and len(payload_recv) == 1:
        return(payload_recv)


def PRUserial485_read():
    """Recebe dados através da interface serial."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read
    command, payload_recv = socket_communicate(payload)
    data = [chr(i) for i in payload_recv]
    if command == ord(_c.COMMAND_PRUserial485_read):
        return data


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
        command, payload_recv = socket_communicate(payload)
        if command == ord(_c.COMMAND_PRUserial485_curve) and len(payload_recv) == 1:
            return(payload_recv)


def PRUserial485_set_curve_block(block=0):
    """Selecao de bloco de curva a ser realizado."""
    # Payload: BLOCK (1 byte)
    if block in _c.AVAILABLE_CURVE_BLOCKS:
        payload = _c.COMMAND_PRUserial485_set_curve_block + \
            struct.pack("B", block)
        command, payload_recv = socket_communicate(payload)
        if command == ord(_c.COMMAND_PRUserial485_set_curve_block) and len(payload_recv) == 0:
            return


def PRUserial485_read_curve_block():
    """Leitura do bloco de curva que sera realizado."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_curve_block
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_curve_block) and len(payload_recv) == 1:
        return(payload_recv)


def PRUserial485_set_curve_pointer(pointer=0):
    """Ajusta ponteiro para proximo ponto a ser executado (curva)."""
    # Payload: POINTER (4 bytes)
    if pointer > 0:
        payload = _c.COMMAND_PRUserial485_set_curve_pointer + \
            struct.pack(">I", pointer)
        command, payload_recv = socket_communicate(payload)
        if command == ord(_c.COMMAND_PRUserial485_set_curve_pointer) and len(payload_recv) == 0:
            return


def PRUserial485_read_curve_pointer():
    """Leitura do ponteiro de curva (proximo ponto que sera executado)."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_curve_pointer
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_curve_pointer) and len(payload_recv) == 4:
        return(struct.unpack(">I",payload_recv)[0])


def PRUserial485_sync_start(sync_mode, delay, sync_address=0x00):
    """Inicia operação em modo síncrono."""
    # Payload: SYNC_MODE (1 byte) + DELAY (4 bytes) + SYNC_ADDRESS (1 byte)
    if (sync_mode in _c.AVAILABLE_SYNC_MODES) and (delay >= 0) and \
       (sync_address >= 0):
        payload = _c.COMMAND_PRUserial485_sync_start + \
            struct.pack("B", sync_mode) + struct.pack(">I", delay) + \
            struct.pack("B", sync_address)
        command, payload_recv = socket_communicate(payload)
        if command == ord(_c.COMMAND_PRUserial485_sync_start) and len(payload_recv) == 0:
            return


def PRUserial485_sync_stop():
    """Finaliza a operação em modo síncrono."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_sync_stop
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_sync_stop) and len(payload_recv) == 0:
        return


def PRUserial485_sync_status():
    """Verifica se sincronismo via PRU está aguardando pulso."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_sync_status
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_sync_status) and len(payload_recv) == 1:
        if payload_recv == 0:
            return False
        else:
            return True


def PRUserial485_read_pulse_count_sync():
    """Leitura do contador de pulsos - Sync."""
    # Payload: none
    payload = _c.COMMAND_PRUserial485_read_pulse_count_sync
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_read_pulse_count_sync) and len(payload_recv) == 4:
        return(struct.unpack(">I", payload_recv)[0])


def PRUserial485_clear_pulse_count_sync():
    # Payload: none
    """Zera contador de pulsos - Sync."""
    payload = _c.COMMAND_PRUserial485_clear_pulse_count_sync
    command, payload_recv = socket_communicate(payload)
    if command == ord(_c.COMMAND_PRUserial485_clear_pulse_count_sync) and len(payload_recv) == 1:
        return(payload_recv)
