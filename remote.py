#!/usr/bin/python-sirius
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.
REMOTE SIDE
Author: Patricia Nallin

Versions:
05/12/2018 - xxxxxxxxx

Bytes:
- 0: command
- 1..4: payload length
- 5.. : payload
"""

# It is a python module. It must not be run itself.
if (__name__ == "__main__"):
    exit()

from constants_PRUserial485_bridge import *
from functions_PRUserial485_bridge import *
import socket, time, sys, struct

# TCP port for PRUserial485 bridge
SERVER_PORT = 5000
BBB_IP = "10.0.6.55"


# Initial message
sys.stdout.write("Ethernet bridge for PRUserial485\n")
sys.stdout.flush()


remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
remote_socket.close()

def time_string():
    return(time.strftime("%d/%m/%Y, %H:%M:%S - ", time.localtime()))


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
    print(payload,(len(payload)-1),struct.pack(">I", (len(payload)-1)))
    return(struct.pack("B",payload[0]) + struct.pack(">I", (len(payload)-1)) + payload[1:])

def PRUserial485_open(baudrate = 6, mode = b'M'):
    """Procedimento de inicialização da PRU."""
    # Payload: MODE (1 byte) + BAUDRATE (4 bytes)
    global remote_socket
    if(remote_socket._closed):
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((BBB_IP, SERVER_PORT))
        sys.stdout.write(time_string() + "TCP/IP client connected at " + BBB_IP +  " on port " + str(SERVER_PORT) + "\n")
        sys.stdout.flush()

    if (mode in AVAILABLE_MODES) and (baudrate in AVAILABLE_BAUDRATES):
        payload = COMMAND_PRUserial485_open + mode + struct.pack(">I", baudrate)
        remote_socket.sendall(payload_length(payload))
        answer = remote_socket.recv(2)
        print(answer)
        if answer[0] == ord(ANSWER_Ok):
            return(answer[1])


def PRUserial485_address():
    """Retorna endereco fisico da placa."""
    # Payload: none
    print(remote_socket)
    payload = COMMAND_PRUserial485_address
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(2)
    print(answer)
    if answer[0] == ord(ANSWER_Ok):
        return(answer[1])



def PRUserial485_close():
    """Encerra a PRU"""
    # Payload: none
    payload = COMMAND_PRUserial485_close
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(1)
    if answer[0] == ord(ANSWER_Ok):
        remote_socket.close()
    print(remote_socket)


def PRUserial485_write(data = [], timeout = 0):
    """Envia dados através da interface serial."""
    # Payload: TIMEOUT (4 bytes) + DATA (len(DATA) bytes)
    payload = COMMAND_PRUserial485_write + struct.pack(">f", timeout)
    payload += bytearray([ord(i) for i in data])
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(2)
    if answer[0] == ord(ANSWER_Ok):
        return(answer[1])

def PRUserial485_read():
    """Recebe dados através da interface serial."""
    # Payload: none
    payload = COMMAND_PRUserial485_read
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(5000)
    print(answer)
    if answer[0] == ord(ANSWER_Ok):
        data_size = struct.unpack(">H",answer[1:3])[0]
        data = []
        if data_size:
            data = [chr(i) for i in answer[3:]]
        if data_size == len(data):
            return data

def PRUserial485_curve(curve1, curve2, curve3, curve4, block = 0):
    """Carregamento de curva."""
    # Payload: BLOCK (1 byte) +
    if len(curve1) == len(curve2) == len(curve3) == len(curve4) and block in AVAILABLE_CURVE_BLOCKS:
        payload = COMMAND_PRUserial485_curve + struct.pack("B", block)
        payload += b''.join((struct.pack(">f", point) for point in curve1)) + \
                    b''.join((struct.pack(">f", point) for point in curve2)) + \
                    b''.join((struct.pack(">f", point) for point in curve3)) + \
                    b''.join((struct.pack(">f", point) for point in curve4))
        remote_socket.sendall(payload_length(payload))
        print(payload_length(payload))
        answer = remote_socket.recv(2)
        if answer[0] == ord(ANSWER_Ok):
            return(answer[1])



def PRUserial485_set_curve_block(block = 0):
    """Selecao de bloco de curva a ser realizado."""
    # Payload: BLOCK (1 byte)
    if block in AVAILABLE_CURVE_BLOCKS:
        payload = COMMAND_PRUserial485_set_curve_block + struct.pack("B", block)
        remote_socket.sendall(payload_length(payload))
        answer = remote_socket.recv(1)
        if answer[0] == ord(ANSWER_Ok):
            return


def PRUserial485_read_curve_block():
    """Leitura do bloco de curva que sera realizado."""
    # Payload: none
    payload = COMMAND_PRUserial485_read_curve_block
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(2)
    if answer[0] == ord(ANSWER_Ok):
        return(answer[1])


def PRUserial485_set_curve_pointer(pointer = 0):
    """Ajusta ponteiro para proximo ponto a ser executado (curva)."""
    # Payload: POINTER (4 bytes)
    if pointer > 0:
        payload = COMMAND_PRUserial485_set_curve_pointer + struct.pack(">I", pointer)
        remote_socket.sendall(payload_length(payload))
        answer = remote_socket.recv(1)
        if answer[0] == ord(ANSWER_Ok):
            return

def PRUserial485_read_curve_pointer():
    """Leitura do ponteiro de curva (proximo ponto que sera executado)."""
    # Payload: none
    payload = COMMAND_PRUserial485_read_curve_pointer
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(5)
    if answer[0] == ord(ANSWER_Ok):
        return(struct.unpack(">I", answer[1:])[0])



def PRUserial485_sync_start(sync_mode, delay, sync_address=0x00):
    """Inicia operação em modo síncrono."""
    # Payload: SYNC_MODE (1 byte) + DELAY (4 bytes) + SYNC_ADDRESS (1 byte)
    if (sync_mode in AVAILABLE_SYNC_MODES) and (delay >= 0) and (sync_address >= 0):
        payload = COMMAND_PRUserial485_sync_start + struct.pack("B", sync_mode) + struct.pack(">I", delay) + struct.pack("B", sync_address)
        remote_socket.sendall(payload_length(payload))
        print(payload)
        answer = remote_socket.recv(1)
        if answer[0] == ord(ANSWER_Ok):
            return


def PRUserial485_sync_stop():
    """Finaliza a operação em modo síncrono."""
    # Payload: none
    payload = COMMAND_PRUserial485_sync_stop
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(1)
    if answer[0] == ord(ANSWER_Ok):
        return


def PRUserial485_sync_status():
    """Verifica se sincronismo via PRU está aguardando pulso."""
    # Payload: none
    payload = COMMAND_PRUserial485_sync_status
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(2)
    if answer[0] == ord(ANSWER_Ok):
        if answer[1] == 0:
            return False
        else:
            return True


def PRUserial485_read_pulse_count_sync():
    """Leitura do contador de pulsos - Sync."""
    # Payload: none
    payload = COMMAND_PRUserial485_read_pulse_count_sync
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(5)
    if answer[0] == ord(ANSWER_Ok):
        return(struck.unpack(">I", answer[1:])[0])


def PRUserial485_clear_pulse_count_sync():
    # Payload: none
    """Zera contador de pulsos - Sync."""
    payload = COMMAND_PRUserial485_clear_pulse_count_sync
    remote_socket.sendall(payload_length(payload))
    answer = remote_socket.recv(2)
    if answer[0] == ord(ANSWER_Ok):
        return(answer[1])
