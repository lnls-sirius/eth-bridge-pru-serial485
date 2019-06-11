#!/usr/bin/python-sirius
# -*- coding: utf-8 -*-
"""
Ethernet bridge for PRUserial485 library.
SERVER SIDE - BEAGLEBONE BLACK SCRIPT
Author: Patricia Nallin

Release:
11/jun/2019

"""

import socket
import time
import sys
import struct
import threading
import traceback
import os.path
import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.pardir,'common')))
from constants_PRUserial485_bridge import *
from functions_PRUserial485_bridge import *
from queue import Queue
from PRUserial485 import *

# Open only for memory mapping
PRUserial485_open(6,b'M')

# TCP port for PRUserial485 bridge - READ and WRITE functions
SERVER_PORT_RW = 5000
SERVER_PORT_GENERAL = 6000

# Initial message
sys.stdout.write("Ethernet bridge for PRUserial485 - READ/WRITE commands\n")
sys.stdout.flush()


def time_string():
    return(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S.%f") + " - ")

def payload_length(payload):
    """."""
    return(struct.pack("B", payload[0]) +
           struct.pack(">I", (len(payload)-1)) + payload[1:])

def processThread():
    # Infinite loop
    while (True):

        # Get next operation
        item = queue.get(block = True)
        item[0] = struct.pack("B",item[0])
        answer = b''

        # Verification and implementation
        if (item[0] == COMMAND_PRUserial485_write):
            timeout = struct.unpack(">f", item[1][:4])[0]
            data = [chr(i) for i in item[1][4:]]
            res = PRUserial485_write(data, timeout)
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_read):
            res = bytearray([ord(i) for i in PRUserial485_read()])
            answer = (ANSWER_Ok + res)

        answer = item[0] + answer[1:]
        connection.sendall(payload_length(answer))

#        sys.stdout.write(time_string() + "\n")
#        sys.stdout.write("Recebido: {} :: {}\n".format(PRUserial485_CommandName[item[0]], item))
#        sys.stdout.write("Enviado: {}\n\n\n".format(payload_length(answer)))
#        sys.stdout.flush()

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
            # Opens TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("", SERVER_PORT_RW))
            server_socket.listen(1)
            sys.stdout.write(time_string() + "TCP/IP server on port 5000 started\n")
            sys.stdout.flush()

            while(True):
                # Wait for client connection
                sys.stdout.write(time_string() + "Waiting for connection\n")
                sys.stdout.flush()
                connection, client_info = server_socket.accept()

                # New connection
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
                            for i in range(int(data_size / 4096)):
                                message += connection.recv(4096, socket.MSG_WAITALL)
                            message += connection.recv(int(data_size % 4096), socket.MSG_WAITALL)

                            # Put operation in Queue
                            queue.put([command, message])

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
