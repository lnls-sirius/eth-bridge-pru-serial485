import unittest
from unittest.mock import MagicMock, patch
from PRUserial485 import EthBridgeClient

VALID_FIRMWARE_VERSION = b"!\x00\x11\x00\x80V0.43 2021-12-02V0.43 2021-12-02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001"
INVALID_FIRMWARE_VERSION = b"\x22\x00\x12"


def mock_socket(_):
    return True


class TestRequest(unittest.TestCase):
    @classmethod
    @patch.object(EthBridgeClient, "connect_socket", mock_socket)
    def setUpClass(TestRequest):
        TestRequest._eth = EthBridgeClient(ip_address="10.128.101.199")

    def test_request_valid(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x11, VALID_FIRMWARE_VERSION)
        )
        self._eth.request("\x01\x10\x00\x01\x03\xeb", 5)

    def test_request_invalid_command(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x12, VALID_FIRMWARE_VERSION)
        )
        with self.assertRaises(ValueError):
            self._eth.request("\x01\x10\x00\x01\x03\xeb", 5)

    def test_request_invalid_response(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x11, INVALID_FIRMWARE_VERSION)
        )
        with self.assertRaises(TimeoutError):
            self._eth.request("\x01\x10\x00\x01\x03\xeb", 5)


if __name__ == "__main__":
    unittest.main()
