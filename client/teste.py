from PRUserial485 import *
import time

PRUserial485_open(115200,b'M')

while True:
	PRUserial485_write([b'\x01',b'\x10',b'\x00',b'\x01',b'\x00',b'\xee'],1000.0)
	PRUserial485_read()
	time.sleep(1)
