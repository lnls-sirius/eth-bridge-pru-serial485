import socket
import unittest
from PRUserial485 import EthBridgeClient


class TestConnect(unittest.TestCase):
    def test_attempt_connect_valid_ip(self):
        with self.assertRaises(socket.timeout):
            EthBridgeClient("10.128.101.121")

    def test_connect_invalid_ip(self):
        with self.assertRaises(ValueError):
            EthBridgeClient("10.0.99.0")


if __name__ == "__main__":
    unittest.main()
