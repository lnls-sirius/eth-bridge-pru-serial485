from constants_PRUserial485_bridge import *
import time, sys, importlib
if importlib.find_loader('siriuspy'):
    from siriuspy.search import PSSearch

# FUNCAO PARA ENCONTRAR O IP A SE CONECTAR
def find_BBB_IP():
    return


def control_PRUserial485():
    bbbname = socket.gethostname().replace('--', ':')
    bsmp_devs = PSSearch.conv_bbbname_2_psnames(bbbname)
    psnames, bsmp_ids = zip(*bsmp_devs)
    return
