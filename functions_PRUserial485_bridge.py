from constants_PRUserial485_bridge import *
import time, sys, importlib
if importlib.find_loader('siriuspy'):
    from siriuspy.search import PSSearch

# FUNCAO PARA ENCONTRAR O IP A SE CONECTAR
def find_BBB_IP(BBB_NAME):    
    beaglebone_IP = {}
    with open("beaglebone-ip.txt", 'r') as fh:
        for curline in fh:
            if curline.startswith("#") or len(curline) <= 1:
                continue
            else:
                if len(curline.split()) == 1:
                    beaglebone_IP[curline.split()[0]] = ''
                else:
                    beaglebone_IP[curline.split()[0]] = curline.split()[1]

    if BBB_NAME in beaglebone_IP:
        BBB_IP = beaglebone_IP[BBB_NAME]
        return BBB_IP
    else:
        sys.stdout.write("Beaglebone Hostname/IP is not in the list\n")
        sys.stdout.flush()
        return None


def control_PRUserial485():
    bbbname = socket.gethostname().replace('--', ':')
    bsmp_devs = PSSearch.conv_bbbname_2_psnames(bbbname)
    psnames, bsmp_ids = zip(*bsmp_devs)
    return
