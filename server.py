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
import socket, time, sys, struct, threading, traceback
from queue import Queue
from PRUserial485 import *

# TCP port for PRUserial485 bridge
SERVER_PORT = 5000

# Initial message
sys.stdout.write("Ethernet bridge for PRUserial485\n")
sys.stdout.flush()


def time_string():
    return(time.strftime("%d/%m/%Y, %H:%M:%S - ", time.localtime()))


def processThread():
    # Laço que executa indefinidamente
    while (True):
        # Retira a próxima operação da fila
        item = queue.get(block = True)
        item[0] = struct.pack("B",item[0])
        answer = b''
        print(item)

        # Verifica a operação a ser realizada
        if (item[0] == COMMAND_PRUserial485_open):
            res = PRUserial485_open(baudrate = struct.unpack(">I", item[1][1:])[0],mode = item[1][0])
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_address):
            res = PRUserial485_address()
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_close):
            PRUserial485_close()
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_write):
            timeout = struct.unpack(">f", item[1][:4])[0]
            data = [chr(i) for i in item[1][4:]]
            print(timeout, data)
            res = PRUserial485_write(data, timeout)
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_read):
            res = bytearray([ord(i) for i in PRUserial485_read()])
            answer = (ANSWER_Ok + struct.pack(">H", len(res)) + res)

        elif (item[0] == COMMAND_PRUserial485_curve):
            # TO BE IMPLEMENTED
            block = item[1][0]
            curve_size = int((len(item[1])-1) / 16)
            print(curve_size)
            curves = []
            for curve in range (4):
                curves.append([struct.unpack(">f", item[1][4*i + 1:4*i+4 + 1])[0] for i in range((curve*curve_size), (curve+1)*curve_size)])
            print(curves)
            res = PRUserial485_curve(curves[0], curves[1], curves[2], curves[3], block)

            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_set_curve_block):
            PRUserial485_set_curve_block(item[1][0])
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_read_curve_block):
            res = PRUserial485_read_curve_block()
            answer = (ANSWER_Ok +  struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_set_curve_pointer):
            PRUserial485_set_curve_pointer(struct.unpack(">I", item[1])[0])
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_read_curve_pointer):
            res = PRUserial485_read_curve_pointer()
            answer = (ANSWER_Ok + struct.pack(">I", res))

        elif (item[0] == COMMAND_PRUserial485_sync_start):
            PRUserial485_sync_start(sync_mode = item[1][0], \
                                    delay = struct.unpack(">I", item[1][1:5])[0], \
                                    sync_address = item[1][5])
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_sync_stop):
            PRUserial485_sync_stop()
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_sync_status):
            if PRUserial485_sync_status():
                res = b'\x01'
            else:
                res = b'\x00'
            answer = (ANSWER_Ok + res)

        elif (item[0] == COMMAND_PRUserial485_read_pulse_count_sync):
            res = PRUserial485_read_pulse_count_sync()
            answer = (ANSWER_Ok + struct.pack(">I", res))

        elif (item[0] == COMMAND_PRUserial485_clear_pulse_count_sync):
            res = PRUserial485_clear_pulse_count_sync()
            answer = (ANSWER_Ok + struct.pack("B", res))


        connection.sendall(answer)


if (__name__ == '__main__'):

    sys.stdout.write("----- TCP/IP SERVER FOR PRUSERIAL485 -----\n")
    sys.stdout.write(time_string() + "Initialization.\n")
    sys.stdout.flush()

    queue = Queue()

    # Create and start threads
    process = threading.Thread(target = processThread)
    process.setDaemon(True)
    process.start()

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
                    # Message header - Operation command (1 byte) + data size (4 bytes)
                    data = connection.recv(5)
                    if(data):
                        command = data[0]
                        data_size = struct.unpack(">I", data[1:])[0]

                        # Get message
                        message = b''
                        while(data_size):
                            message += connection.recv(1)
                            data_size -= 1

                        # Put operation in Queue
                        queue.put([command, message])
                        print(command, message)

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
