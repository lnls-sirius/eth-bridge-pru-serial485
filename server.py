#!/usr/bin/python-sirius
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.
SERVER SIDE - BEAGLEBONE BLACK
Author: Patricia Nallin

Versions:
05/12/2018 - xxxxxxxxx
"""



from constants_PRUserial485_bridge import *
from functions_PRUserial485_bridge import *
import socket, time, sys, struct
from queue import PriorityQueue
from PRUserial485 import *

# TCP port for PRUserial485 bridge
SERVER_PORT = 5000
BBB_IP = ""

# Initial message
sys.stdout.write("Ethernet bridge for PRUserial485\n")
sys.stdout.flush()


def time_string():
    return(time.strftime("%d/%m/%Y, %H:%M:%S - ", time.localtime()))


def PRUserial485_read():
    """Recebe dados através da interface serial."""
    message = COMMAND_PRUserial485_read
    remote_socket.sendall(message)
    answer = remote_socket.recv(5000)
    if answer[0] == ANSWER_Ok:
        data_size = struct.unpack(">H",answer[1:3])
        data = []
        if data_size:
            data = [chr(i) for i in answer[3:]]
        if data_size == len(data):
            return data


def PRUserial485_set_curve_block(block = 0):
    """Selecao de bloco de curva a ser realizado."""
    if block in AVAILABLE_CURVE_BLOCKS
        message = COMMAND_PRUserial485_set_curve_block + struct.pack("B", block)
        remote_socket.sendall(message)
        answer = remote_socket.recv(1)
        if answer[0] == ANSWER_Ok:
            return


def PRUserial485_read_curve_block():
    """Leitura do bloco de curva que sera realizado."""
    message = COMMAND_PRUserial485_read_curve_block
    remote_socket.sendall(message)
    answer = remote_socket.recv(2)
    if answer[0] == ANSWER_Ok:
        return(ord(answer[1]))


def PRUserial485_set_curve_pointer(pointer = 0):
    """Ajusta ponteiro para proximo ponto a ser executado (curva)."""
    if pointer > 0:
        message = COMMAND_PRUserial485_set_curve_pointer + struct.pack(">I", pointer)
        remote_socket.sendall(message)
        answer = remote_socket.recv(1)
        if answer[0] == ANSWER_Ok:
            return

def PRUserial485_read_curve_pointer():
    """Leitura do ponteiro de curva (proximo ponto que sera executado)."""
    message = COMMAND_PRUserial485_read_curve_pointer
    remote_socket.sendall(message)
    answer = remote_socket.recv(5)
    if answer[0] == ANSWER_Ok:
        return(struck.unpack(">I", answer[1:]))



def PRUserial485_sync_start(sync_mode, delay, sync_address=0x00):
    """Inicia operação em modo síncrono."""
    if (sync_mode in AVAILABLE_SYNC_MODES) and (delay >= 0) and (sync_address >= 0):
        message = COMMAND_PRUserial485_sync_start + struct.pack("B", sync_mode) + \
                    struct.pack(">I", delay) + struct.pack("B", sync_address)
        remote_socket.sendall(message)
        answer = remote_socket.recv(1)
        if answer[0] == ANSWER_Ok:
            return


def PRUserial485_sync_stop():
    """Finaliza a operação em modo síncrono."""
    message = COMMAND_PRUserial485_sync_stop
    remote_socket.sendall(message)
    answer = remote_socket.recv(2)
    if answer[0] == ANSWER_Ok:
        return


def PRUserial485_sync_status():
    """Verifica se sincronismo via PRU está aguardando pulso."""
    message = COMMAND_PRUserial485_sync_status
    remote_socket.sendall(message)
    answer = remote_socket.recv(2)
    if answer[0] == ANSWER_Ok:
        if answer[1] == b'\x00':
            return False
        else:
            return True


def PRUserial485_read_pulse_count_sync():
     """Leitura do contador de pulsos - Sync."""
    message = COMMAND_PRUserial485_read_pulse_count_sync
    remote_socket.sendall(message)
    answer = remote_socket.recv(5)
    if answer[0] == ANSWER_Ok:
        return(struck.unpack(">I", answer[1:]))


def PRUserial485_clear_pulse_count_sync():
    """Zera contador de pulsos - Sync."""
    message = COMMAND_PRUserial485_clear_pulse_count_sync
    remote_socket.sendall(message)
    answer = remote_socket.recv(2)
    if answer[0] == ANSWER_Ok:
        return(ord(answer[1]))




def processThread(self):
    # Laço que executa indefinidamente
    while (True):
        # Retira a próxima operação da fila
        item = queue.get(block = True)
        item = item[1]

        # Verifica a operação a ser realizada
        if (item[0] == COMMAND_PRUserial485_open):
            res = PRUserial485_open(mode = item[1][0], baudrate = struct.unpack(">I", item[1][1:]))
            server_socket.sendall(ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_address):
            res = PRUserial485_address()
            server_socket.sendall(ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_close):
            PRUserial485_close()

        elif (item[0] == COMMAND_PRUserial485_write):
            timeout = struct.unpack(">f", item[1][:4])
            data = [chr(i) for i in item[1][4:]]
            res = PRUserial485_write(data, timeout)
            server_socket.sendall(ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_read):
            res = bytearray([ord(i) for i in PRUserial485_read()])
            server_socket.sendall(ANSWER_Ok + res)

        elif (item[0] == COMMAND_PRUserial485_curve):
            # TO BE IMPLEMENTED
            server_socket.sendall(ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_set_curve_block):
            PRUserial485_set_curve_block(ord(item[1][0]))






def ServerThread(self):

    while (True):
        try:
            # Cria o socket para o servidor TCP/IP
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("", 5000))
            server_socket.listen(1)
            sys.stdout.write(time_string() + "TCP/IP server on port 5000 started\n")
            sys.stdout.flush()

            while (True):
                # Espera pela conexão de um cliente
                sys.stdout.write(time_string() + "Waiting for connection\n")
                sys.stdout.flush()
                connection, client_info = server_socket.accept()

                # Imprime uma mensagem na tela informando uma nova conexão
                sys.stdout.write(time_string() + "Client " + client_info[0] + ":" + str(client_info[1]) + " connected\n")
                sys.stdout.flush()

                while (True):
                    # Message header - Operation command (1) + data size (4)
                    data = connection.recv(5)
                    if(data):
                        command = data[0]
                        data_size = struct.unpack(">I", data[1:])

                        # Get message
                        message = b''
                        while(data_size):
                            message += connection.recv(1)
                            data_size -= 1

                        # Put operation in Queue
                        queue.put((1, [command, message]))

                    else:
                        sys.stdout.write(time_string() + "Client " + client_info[0] + ":" + str(client_info[1]) + " disconnected\n")
                        sys.stdout.flush()
                        break
        except Exception:

            server_socket.close()

            sys.stdout.write(time_string() + "Connection problem. Error message:\n\n")
            traceback.print_exc(file = sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()

            time.sleep(5)





if (__name__ == '__main__'):

    sys.stdout.write("----- TCP/IP SERVER FOR PRUSERIAL485 -----\n")
    sys.stdout.write(time_string() + "Initialization.\n")
    sys.stdout.flush()

    # Create and start threads
    process = threading.Thread(target = processThread)
    server = threading.Thread(target = ServerThread)

    process.setDaemon(True)
    server.setDaemon(True)

    process.start()
    server.start()
