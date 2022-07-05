"""PRUserial485 client module for BBB ethernet bridge"""

import os as _os
from .PRUserial485 import *

with open(_os.path.join(__path__[0], 'VERSION'), 'r') as _f:
    __version__ = _f.read().strip()
