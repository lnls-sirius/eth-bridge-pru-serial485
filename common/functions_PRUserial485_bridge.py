"""Util functions."""

import sys
import importlib

#if importlib.find_loader('siriuspy'):
#    from siriuspy.csdevice.util import get_device_2_ioc_ip


def find_BBB_IP(BBB_NAME):
    """Return BBB IP."""
    dev2ips = get_device_2_ioc_ip()
    if BBB_NAME in dev2ips:
        return dev2ips[BBB_NAME]
    else:
        pstr = "Beaglebone Hostname '{}' is not in the list\n".format(BBB_NAME)
        sys.stdout.write(pstr)
        sys.stdout.flush()
        return ''
