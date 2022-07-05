import unittest
from unittest.mock import MagicMock, patch
from PRUserial485 import EthBridgeClient

VALID_FIRMWARE_WRITE = b"\x21\x00"
INVALID_FIRMWARE_WRITE = b"\x22\x00"


def mock_socket(_):
    return True


class TestWrite(unittest.TestCase):
    @classmethod
    @patch.object(EthBridgeClient, "connect_socket", mock_socket)
    def setUpClass(TestRequest):
        TestRequest._eth = EthBridgeClient(ip_address="10.128.101.199")

    def test_write_valid(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x03, VALID_FIRMWARE_WRITE)
        )
        self._eth.write("\x01\x20\x00\x01\x03\xeb", 5)

    def test_write_invalid_command(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x05, VALID_FIRMWARE_WRITE)
        )
        with self.assertRaises(ValueError):
            self._eth.write("\x01\x20\x00\x01\x03\xeb", 5)

    def test_write_invalid_response(self):
        self._eth._send_communication_data = MagicMock(
            return_value=(0x03, INVALID_FIRMWARE_WRITE)
        )
        with self.assertRaises(TimeoutError):
            self._eth.write("\x01\x20\x00\x01\x03\xeb", 5)


if __name__ == "__main__":
    unittest.main()
