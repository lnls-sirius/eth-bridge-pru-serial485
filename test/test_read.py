import unittest
from unittest.mock import MagicMock, patch
from PRUserial485 import EthBridgeClient

VALID_FIRMWARE_VERSION = b"!\x00\x11\x00\x80V0.43 2021-12-02V0.43 2021-12-02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001"
INVALID_FIRMWARE_VERSION = b"\x22\x00\x12"
INVALID_FIRMWARE_NOQUEUE = b"\x23"


def mock_socket(_):
    return True


class TestRead(unittest.TestCase):
    @classmethod
    @patch.object(EthBridgeClient, "connect_socket", mock_socket)
    def setUpClass(TestRequest):
        TestRequest._eth = EthBridgeClient(ip_address="10.128.101.199")

    def test_read_valid(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x04, VALID_FIRMWARE_VERSION)
        )
        self._eth.read()

    def test_read_invalid_command(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x05, VALID_FIRMWARE_VERSION)
        )
        with self.assertRaises(ValueError):
            self._eth.read()

    def test_read_invalid_response_timeout(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x04, INVALID_FIRMWARE_VERSION)
        )
        with self.assertRaises(TimeoutError):
            self._eth.read()

    def test_read_invalid_response_no_queue(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x04, INVALID_FIRMWARE_NOQUEUE)
        )
        with self.assertRaises(ValueError):
            self._eth.read()


if __name__ == "__main__":
    unittest.main()
