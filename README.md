## eth-bridge-pru-serial485
##### *Ethernet bridge for Beaglebone's PRUserial485 module*

This python module was developed to run PRUserial485 commands remotely in a Beaglebone Black from any other workstation, based on a socket connection (on port 5000).



### Server side - Beaglebone Black
Server side contents are available in folder **server**, which will be necessary to build the bridge to the BBB that will effectively run PRUserial485 commands.

Simple configuration: PRUserial485 library for BeagleboneBlack is needed (find it at [pru-serial485](http://github.com/lnls-sirius/pru-serial485) repo).

Once all pins are configured correctly, run script:

`python-sirius BBB_server_PRUserial485.py`or `python3 BBB_server_PRUserial485.py`


### Client side - another computer

Client side contents are in folder **client**, and will be needed on host computer, which will be linked to a Beaglebone Black.

In order to have this module on your system, enter the project folder and install it:

 - `cd client/`
 - `sudo python-sirius setup.py install`
<br>

#### Using the python module
In your python code, you can just:
```python
import PRUserial485
```
It is not needed to copy any library files to your project.
Package **siriuspy** is needed to get the server IP on the beaglebone

Before starting to use the library the name of the beaglebone to connect to
needs to be defined invoking
```python
PRUserial485.set_beaglebone_ip(bbbname=None)
```


---
#### Available Methods
Identical to [pru-serial485](http://github.com/lnls-sirius/pru-serial485) methods.

_**General Purpose**_

- ```PRUserial485_open(int baudrate, char mode)```

   PRU initialization. Shared memory configuration and loading binaries into PRU.  
   * _baudrate:_  
   RS485 serial desired baudrate. Available: 9600, 14400, 19200, 38400, 57600, 115200 bps and 6, 10, 12 Mbps
   * _mode:_  
   "M" for master and "S" for slave mode.


- ```PRUserial485_address()```

   Gets SERIALxxCON board address (hardware defined)
   Returns: integer value (0 to 31)


- ```PRUserial485_close()```

   Closes PRUs and memory mapping.


- ```PRUserial485_write(char_list data, float timeout)```

   Sending data through RS485 network  

   _*Parameters*_
  * _data:_  
  Python char list containing values to be transmitted through serial network.
  * _timeout:_  
  Maximum waiting time to start getting an answer, in milliseconds (ms). Minimum: 15ns / Maximum: 64s. If 0, does not wait for response. ATTENTION: in slave mode, this parameter is ignored.  

  _*Return*_
  * _MASTER MODE:_  
   Returns only after response received (valid response, timeout or ignored)
  * _SLAVE MODE:_  
   Returns just after data completely sent.


- ```PRUserial485_read()```

   Receiving data through RS485 network  

   _*Return*_: List of characters corresponding to data received.


_**Curves**_

- ```PRUserial485_curve(float_list curve1, float_list curve2, float_list curve3, float_list curve4, int block)```

   Storing curves into memory. Each curve correspond to a power supply in the crate.   

   _*Parameters*_
  * _curveX:_  
  Python float list containing curve points, up to 6250 points. Curves must all have same length.
  * _block:_  
  Identification of block which will be loaded with curve points. (0 to 3)  


- ```PRUserial485_set_curve_block(int block)```

   Selection of block which will be performed in next cycle. Default value is 0.   

   _*Parameters*_
  * _block:_  
  Identification of block (0 to 3)  


- ```PRUserial485_read_curve_block()```

   Read block identification which will be performed in next cycle.    

   _*Returns*_: Block indentification (0 to 3)


- ```PRUserial485_set_curve_pointer(int next_point)```

   Selection of point of curve that will be performed after the next sync pulse   

   _*Parameters*_
  * _next_point:_  
   index of next point (0 to (len(curve)-1))  


- ```PRUserial485_read_curve_pointer()```

   Read curve index (point) which will be sent in next sync pulse.    

   _*Returns*_: index of next point (0 to (len(curve)-1))


_**Sync Operation**_

- ```PRUserial485_sync_start(int sync_mode, float delay, int sync_address)```

   Sync mode operation.   

   _*Parameters*_
  * _sync_mode:_  
                 | 0x51 - Single curve sequence & Intercalated read messages  
                 | 0x5E - Single curve sequence & Read messages at End of curve  
                 | 0xC1 - Continuous curve sequence & Intercalated read messages  
                 | 0xCE - Continuous curve sequence & Read messages at End of curve  
                 | 0x5B - Single Sequence - Single Broadcast Function command
  * _delay:_  
  time between end of sync serial message and start of a normal message, when sending normal commands after sync pulses.
  * _sync_address:_  
  PS Controller address to which setpoints will be addressed to. Parameter only needed if sync_mode != 0x5B  


- ```PRUserial485_sync_stop()```

   Stops sync operation mode.   



- ```PRUserial485_sync_status()```

   Verifies whether PRU is waiting for a sync pulse or not    

   _*Returns*_: boolean True or False


- ```PRUserial485_read_pulse_count_sync()```

   Read number of sync pulses already received.    

   _*Returns*_: counting value (0 to (2^32 - 1))


- ```PRUserial485_clear_pulse_count_sync()```

   Clears pulse counting registers. Action is only performed if sync mode is disabled.
---
