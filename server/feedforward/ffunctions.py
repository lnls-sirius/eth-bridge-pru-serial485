"""Feedforward config functions"""

import json
import numpy as np
import os


ff_config_folder = "/root/ffconfig"
ff_config_file = "ff_config.json"



def load_config():
    """..."""
    if os.path.exists(ff_config_folder) and (ff_config_file in os.listdir(ff_config_folder)):
        with open(os.path.join(ff_config_folder,ff_config_file)) as f:
            config = json.load(f)
        return config
    else:
        return {}
    

def store_config(config):
    """..."""
    if not os.path.exists(ff_config_folder):
        os.mkdir(ff_config_folder)

    if "config" in config.keys():
        with open(os.path.join(ff_config_folder,ff_config_file), 'w') as f:
            json.dump(config, f)

    else:
        with open(os.path.join(ff_config_folder,ff_config_file), 'r') as f:
            stored_config = json.load(f)
        
        stored_config.update(config)
        with open(os.path.join(ff_config_folder,ff_config_file), 'w') as f:
            json.dump(stored_config, f)
        


def interpol(cfgsize, tables):
    """Interpol - if received table size is smaller than configured table size"""
    if len(tables[0]) != cfgsize:
        xrecv = [cfgsize*float(i)/(len(tables[0])-1) for i in range(len(tables[0]))]
        xcfg  = list(range(0, cfgsize))

        for table in range(4):
            tables[table] = list(np.interp(xcfg, xrecv, tables[table]))
        
        return tables