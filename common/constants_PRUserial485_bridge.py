# General
COMMAND_PRUserial485_open = b'\x00'
COMMAND_PRUserial485_address = b'\x01'
COMMAND_PRUserial485_close = b'\x02'
COMMAND_PRUserial485_write = b'\x03'
COMMAND_PRUserial485_read = b'\x04'

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

# Terminator
BRIDGE_Terminator = b'\x55'

# Answers
ANSWER_Ok = b'\x0f'





# Checking parameters
AVAILABLE_BAUDRATES = [9600, 14400, 19200, 38400, 57600, 115200, 6,10, 12]
AVAILABLE_MODES = [b'M', b'S']
AVAILABLE_CURVE_BLOCKS = [0, 1, 2, 3]
AVAILABLE_SYNC_MODES = [0x51, 0x5e, 0xc1, 0xce, 0x5b]
