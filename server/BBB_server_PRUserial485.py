#!/usr/bin/python-sirius
# -*- coding: utf-8 -*-

"""
Ethernet bridge for PRUserial485 library.
SERVER SIDE - BEAGLEBONE BLACK SCRIPT
Author: Patricia Nallin

Release:
06/aug/2019
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
import PRUserial485 as _lib

# TCP port for PRUserial485 bridge - READ and WRITE functions
SERVER_PORT_RW = 5000
SERVER_PORT_GENERAL = 6000
DAEMON_PORT = 5500
connection_daemon = {SERVER_PORT_RW:"", SERVER_PORT_GENERAL:""}

# Initialize PRUserial485 - may be reinitialized if needed
_lib.PRUserial485_open(6,b'M')

# Initial message
sys.stdout.write("Ethernet bridge for PRUserial485 - GENERAL commands\n")
sys.stdout.flush()


def time_string():
    return(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S.%f") + " - ")

def payload_length(payload):
    """."""
    return(struct.pack("B", payload[0]) +
           struct.pack(">I", (len(payload)-1)) + payload[1:])

def processThread_general():
    while (True):
        # Get next operation
        item = queue_general.get(block = True)
        item[0] = struct.pack("B",item[0])
        client = item[2]
        answer = b''

        # Verification and implementation
        if (item[0] == COMMAND_PRUserial485_open):
            baudrate = struct.unpack(">I", item[1][1:])[0]
            mode = item[1][0]
            res = _lib.PRUserial485_open(baudrate,mode)
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_address):
            res = _lib.PRUserial485_address()
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_close):
            _lib.PRUserial485_close()
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_curve):
            block = item[1][0]
            curve_size = int((len(item[1])-1) / 16)
            curves = []
            for curve in range (4):
                curves.append([struct.unpack(">f", item[1][4*i + 1:4*i+4 + 1])[0] for i in range((curve*curve_size), (curve+1)*curve_size)])
            res = _lib.PRUserial485_curve(curves[0], curves[1], curves[2], curves[3], block)
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_set_curve_block):
            _lib.PRUserial485_set_curve_block(item[1][0])
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_read_curve_block):
            res = _lib.PRUserial485_read_curve_block()
            answer = (ANSWER_Ok +  struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_set_curve_pointer):
            new_pointer = struct.unpack(">I", item[1])[0]
            _lib.PRUserial485_set_curve_pointer(new_pointer)
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_read_curve_pointer):
            res = _lib.PRUserial485_read_curve_pointer()
            answer = (ANSWER_Ok + struct.pack(">I", res))

        elif (item[0] == COMMAND_PRUserial485_sync_start):
            sync_mode = item[1][0]
            delay = struct.unpack(">I", item[1][1:5])[0]
            sync_address = item[1][5]
            _lib.PRUserial485_sync_start(sync_mode, delay, sync_address)
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_sync_stop):
            _lib.PRUserial485_sync_stop()
            answer = (ANSWER_Ok)

        elif (item[0] == COMMAND_PRUserial485_sync_status):
            if _lib.PRUserial485_sync_status():
                res = b'\x01'
            else:
                res = b'\x00'
            answer = (ANSWER_Ok + res)

        elif (item[0] == COMMAND_PRUserial485_read_pulse_count_sync):
            res = _lib.PRUserial485_read_pulse_count_sync()
            answer = (ANSWER_Ok + struct.pack(">I", res))

        elif (item[0] == COMMAND_PRUserial485_clear_pulse_count_sync):
            res = _lib.PRUserial485_clear_pulse_count_sync()
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_version):
            answer = (ANSWER_Ok + _lib.__version__.encode())

        elif (item[0] == COMMAND_PRUserial485_server_eth_version):
            with open(version_file_path, 'r') as _f:
                server_version = _f.read().strip()
            server_version += ":" + subprocess.getoutput('git log --format=%h -1')
            answer = (ANSWER_Ok + server_version.encode())


        answer = item[0] + answer[1:]
        client.sendall(payload_length(answer))


def processThread_rw():
    while (True):
        # Get next operation
        item = queue_rw.get(block = True)
        item[0] = struct.pack("B",item[0])
        client = item[2]
        answer = b''

        # Verification and implementation
        if (item[0] == COMMAND_PRUserial485_write):
            timeout = struct.unpack(">f", item[1][:4])[0]
            data = [chr(i) for i in item[1][4:]]
            res = _lib.PRUserial485_write(data, timeout)
            answer = (ANSWER_Ok + struct.pack("B", res))

        elif (item[0] == COMMAND_PRUserial485_read):
            res = bytearray([ord(i) for i in _lib.PRUserial485_read()])
            answer = (ANSWER_Ok + res)

        answer = item[0] + answer[1:]
        client.sendall(payload_length(answer))


def connectionThread(conn_port):
    global connection_daemon
    while (True):
        try:
            # Opens TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("", conn_port))
            server_socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            server_socket.listen(1)
            sys.stdout.write(time_string() + "TCP/IP server on port {} started\n".format(conn_port))
            sys.stdout.flush()

            while(True):
                # Wait for client connection
                sys.stdout.write(time_string() + "Port {} waiting for connection\n".format(conn_port))
                sys.stdout.flush()
                connection_daemon[conn_port] = "Available"
                connection, client_info = server_socket.accept()
                connection_daemon[conn_port] = client_info[0]

                # New connection
                sys.stdout.write(time_string() + "Port {}: client {}:{} connected\n".format(conn_port, client_info[0], client_info[1]))
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
                        if len(message) == data_size:
                            if command == ord(COMMAND_PRUserial485_write) or command == ord(COMMAND_PRUserial485_read):
                                queue_rw.put([command, message, connection])
                            else:
                                queue_general.put([command, message, connection])

                    else:
                        sys.stdout.write(time_string() + "Client {}:{} disconnected on port {}.\n".format(client_info[0], client_info[1], conn_port))
                        sys.stdout.flush()
                        break

        except Exception:
            server_socket.close()
            sys.stdout.write(time_string() + "Connection problem on port {}. Error message:\n\n".format(conn_port))
            traceback.print_exc(file = sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(5)


def daemon_server(daemon_port):
    global daemon_socket
    client_info = [""]
    while (True):
        try:
            # Opens a Daemon TCP/IP socket - To signalize whether server is available
            daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            daemon_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            daemon_socket.bind(("", DAEMON_PORT))
            daemon_socket.listen(1)
            sys.stdout.write(time_string() + "TCP/IP daemon server on port {} started\n".format(DAEMON_PORT))
            sys.stdout.flush()

            while(True):
                # Wait for ports to be available
                while connection_daemon[SERVER_PORT_GENERAL] != "Available" or connection_daemon[SERVER_PORT_RW] != "Available":
                    time.sleep(1)

                # Reopen socket if connection is closed. Wait SERVER_PORTS get available
                if daemon_socket._closed:
                    while connection_daemon[SERVER_PORT_GENERAL] != "Available" or connection_daemon[SERVER_PORT_RW] != "Available":
                        time.sleep(1)
                    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    daemon_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    daemon_socket.bind(("", DAEMON_PORT))
                    daemon_socket.listen(1)


                # Wait for client connection
                if client_info[0] != "127.0.0.1":
                    sys.stdout.write(time_string() + "Daemon port {} available\n".format(DAEMON_PORT))
                    sys.stdout.flush()
                connection, client_info = daemon_socket.accept()

                # New connection
                if client_info[0] != "127.0.0.1":
                    sys.stdout.flush()

                # Close connection - if connection was forced
                if client_info[0] == "127.0.0.1":
                    daemon_socket.close()


        except Exception:
            daemon_socket.close()
            sys.stdout.write(time_string() + "Connection problem on daemon port {}. Error message:\n\n".format(DAEMON_PORT))
            traceback.print_exc(file = sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(1)





if (__name__ == '__main__'):

    sys.stdout.write("----- TCP/IP SERVER FOR PRUSERIAL485 -----\n")
    sys.stdout.write(time_string() + "Initialization.\n")
    sys.stdout.flush()

    queue_general = Queue()
    queue_rw = Queue()

    # Create and start process threads
    process_general = threading.Thread(target = processThread_general)
    process_general.setDaemon(True)
    process_general.start()

    process_rw = threading.Thread(target = processThread_rw)
    process_rw.setDaemon(True)
    process_rw.start()

    # Create and start connection threads
    connection_general = threading.Thread(target = connectionThread, args = [SERVER_PORT_GENERAL])
    connection_general.setDaemon(True)
    connection_general.start()

    connection_rw = threading.Thread(target = connectionThread, args = [SERVER_PORT_RW])
    connection_rw.setDaemon(True)
    connection_rw.start()


    # Daemon thread
    daemon_thread = threading.Thread(target = daemon_server, args = [DAEMON_PORT])
    daemon_thread.setDaemon(True)
    daemon_thread.start()

    time.sleep(1)

    while (True):
        while connection_daemon[SERVER_PORT_GENERAL] == "Available" and connection_daemon[SERVER_PORT_RW] == "Available":
            time.sleep(5)

        # If daemon_socket is  blocking on accept() after ports unavailable anymore, force a connection to close it.
        if (connection_daemon[SERVER_PORT_GENERAL] != "Available" or connection_daemon[SERVER_PORT_RW] != "Available") and not daemon_socket._closed:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', DAEMON_PORT))
            time.sleep(1)

        time.sleep(5)
