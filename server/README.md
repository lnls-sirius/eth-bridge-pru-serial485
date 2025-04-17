# ETH-BRIDGE - SERVER APPLICATION
> **Patricia Nallin**  
> [patricia.nallin@lnls.br](patricia.nallin@lnls.br)
>
> LNLS - Brazilian Synchrotron Light Laboratory  
> CNPEM - Brazilian Center for Research in Energy and Materials  



This python module was developed to run PRUserial485 commands remotely in a Beaglebone Black from any other workstation/device, based on TCP/IP socket connections.

- **Port 5000**: for write/read commands, operations directly using serial RS485, which depends on the equipment response or serial line availability (blocking functions).
- **Port 6000**: for general commands, which only depends on BBB memory access and answer is always immediate.

To find out whether ports 5000 and 6000 are available for connecting, you may use `wait-for-it`.

### System service
Dependancy: PRUserial485 library for BeagleboneBlack is needed (find it at [pru-serial485](http://github.com/lnls-sirius/pru-serial485) repo).

For building it, enter the folder `server` and run `make install`. This will copy service file into BBB system.

Server service **is not launched automatically** every BBB booting. **Once all BBB pins are configured correctly**, start it:

`systemctl start eth-bridge-pru-serial485.service`


## Commands overview

Commands/replies for interfacing PRUserial485 with eth-bridge are byte-structured into 

`CODE (1 byte) | PAYLOAD SIZE (4 bytes, 32-bit int) | PAYLOAD (n bytes)`


Payload carries function arguments/returns.




----
### Write/Read Functions - Port 5000

| Function       | Code         | Payload       | Total payload length (bytes)
| :-            | :-            | :-            | :-            |
| `PRUserial485_write(timeout, bytes)`<br> *Send message through RS485 network*        | `\x03`| **- timeout [ms]:** float - 4 bytes - timeout for waiting to start receiving a reply <br> **- bytes:** uint8 - n bytes - message to be sent out through RS485| 4 + n |
| `PRUserial485_read()`<br> *Read RS485 input receive buffer*        | `\x04`| ---- | 0 |
| `PRUserial485_request(timeout, bytes)`<br> *Send message through RS485 network and read input buffer after receiving the reply*        | `\x11`| **- timeout [ms]:** float - 4 bytes - timeout for waiting to start receiving a reply <br> **- bytes:** uint8 - n bytes - message to be sent out through RS485| 4 + n |

----

### General Functions - Port 6000

| Function       | Code         | Payload       | Total payload length (bytes)
| :-            | :-            | :-            | :-            |
| `PRUserial485_open(baudrate, mode)`<br>*Open and configure PRUserial485 serial interface and memory mapping* | \x00 | **- baudrate:** uint16 - 2 bytes - baudrate for serial interface initialization <br> **- mode:** char/uint8 - 1 byte - mode for RS485 line. b'M' for master or b'S' for slave mode | 3 |
| TO DO | TODO | TODO | TODO |
| ... | ... | ... | ... |




### Example:
- Function: PRUserial485_open(6, b'M')
- eth-bridge code: \x00
- Arguments (3 bytes): 
    - baudrate: uint16 (6 -> \x0006)
    - mode: char (uint8) ('M' -> 'M' = \x4d)


Mapping into a eth-bridge command:
- **Function code:** \x00
- **Payload size:** \x00\x00\x00\x03
- **Payload:** \x00\x06 + \x4d
- **Function command:** `\x00\x00\x00\x00\x03\x00\x06\x4d`


Reply from eth-bridge for PRUserial485_open (1 byte):
- **Function code:** \x00
- **Payload size:** \x00\x00\x00\x01
- **Payload:** \x00 (PRUserial485_open return)
- **Reply command:** `\x00\x00\x00\x00\x01\x00`

----
