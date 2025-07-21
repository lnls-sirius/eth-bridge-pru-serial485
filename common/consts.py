# General
COMMAND_PRUserial485_open = b'\x00'
COMMAND_PRUserial485_address = b'\x01'
COMMAND_PRUserial485_close = b'\x02'
COMMAND_PRUserial485_write = b'\x03'
COMMAND_PRUserial485_read = b'\x04'
COMMAND_PRUserial485_request = b'\x11'

# Curves
COMMAND_PRUserial485_curve = b'\x05'
COMMAND_PRUserial485_set_curve_block = b'\x06'
COMMAND_PRUserial485_read_curve_block = b'\x07'
COMMAND_PRUserial485_set_curve_pointer = b'\x08'
COMMAND_PRUserial485_read_curve_pointer = b'\x09'

# Sync Operation
COMMAND_PRUserial485_sync_start = b'\x0a'
COMMAND_PRUserial485_sync_stop = b'\x0b'
COMMAND_PRUserial485_sync_status = b'\x0c'
COMMAND_PRUserial485_read_pulse_count_sync = b'\x0d'
COMMAND_PRUserial485_clear_pulse_count_sync = b'\x0e'

# BBB Library version
COMMAND_PRUserial485_version = b'\x0f'
COMMAND_PRUserial485_server_eth_version = b'\x10'


# Terminator
BRIDGE_Terminator = b'\x55'

# Answers
ANSWER_OK = b'\x21'
ANSWER_ERR = b'\x22'
ANSWER_NOQUEUE = b'\x23'

# Naming
PRUserial485_CommandName = {COMMAND_PRUserial485_open : "PRUserial485_open",
                                COMMAND_PRUserial485_address : "PRUserial485_address",
                                COMMAND_PRUserial485_close : "PRUserial485_close",
                                COMMAND_PRUserial485_write : "PRUserial485_write",
                                COMMAND_PRUserial485_read : "PRUserial485_read",
                                COMMAND_PRUserial485_request : "PRUserial485_request",
                                # Curves
                                COMMAND_PRUserial485_curve : "PRUserial485_curve",
                                COMMAND_PRUserial485_set_curve_block : "PRUserial485_set_curve_block",
                                COMMAND_PRUserial485_read_curve_block : "PRUserial485_read_curve_block",
                                COMMAND_PRUserial485_set_curve_pointer : "PRUserial485_set_curve_pointer",
                                COMMAND_PRUserial485_read_curve_pointer : "PRUserial485_read_curve_pointer",
                                # Sync Operation
                                COMMAND_PRUserial485_sync_start : "PRUserial485_sync_start",
                                COMMAND_PRUserial485_sync_stop : "PRUserial485_sync_stop",
                                COMMAND_PRUserial485_sync_status : "PRUserial485_sync_status",
                                COMMAND_PRUserial485_read_pulse_count_sync : "PRUserial485_read_pulse_count_sync",
                                COMMAND_PRUserial485_clear_pulse_count_sync : "PRUserial485_clear_pulse_count_sync"
}

# Grouping commands
COMMANDS = [
    COMMAND_PRUserial485_write,
    COMMAND_PRUserial485_read,
    COMMAND_PRUserial485_request
    ]

# Checking parameters
AVAILABLE_BAUDRATES = [9600, 14400, 19200, 38400, 57600, 115200, 1, 6, 10, 12]
AVAILABLE_MODES = [b'M', b'S']
AVAILABLE_CURVE_BLOCKS = [0, 1, 2, 3]
AVAILABLE_SYNC_MODES = [0x51, 0x5e, 0xc1, 0xce, 0x5b]


# Location
SERVER_FILES_PATH = "/root/eth-bridge-pru-serial485/server"
VERSION_FILE_PATH = "/root/eth-bridge-pru-serial485/client/VERSION"
LOG_FILE_PATH = "/var/log/eth-bridge.log"
