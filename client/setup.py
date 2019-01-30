#!/usr/bin/env python3
"""Setup module."""

from setuptools import setup

with open('VERSION', 'r') as _f:
    __version__ = _f.read().strip()

print(__version__)

setup(
    name='PRUserial485',
    version=__version__,
    author='Patricia Nallin',
    description='PRUserial485 client module for BBB ethernet bridge',
    url='https://github.com/lnls-sirius/eth-bridge-pru-serial485',
    download_url='https://github.com/lnls-sirius/eth-bridge-pru-serial485',
    license='BSD',
    classifiers=[
        'Intended Audience :: Science/Research',
        'Programming Language :: Python',
        'Topic :: Scientific/Engineering'
    ],
    packages=['PRUserial485'],
    package_data={'PRUserial485': ['VERSION']}
)
