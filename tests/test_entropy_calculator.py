import unittest
from repo_scanner.scanner.entropy_calculator import EntropyCalculator


class TestEntropyCalculator(unittest.TestCase):
    def test_empty_data_is_zero(self):
        self.assertEqual(EntropyCalculator.calculate_entropy(b''), 0.0)

    def test_repeated_byte_is_zero_entropy(self):
        self.assertEqual(EntropyCalculator.calculate_entropy(b'aaaaaaaa'), 0.0)

    def test_random_bytes_have_high_entropy(self):
        data = bytes(range(256))
        self.assertGreater(EntropyCalculator.calculate_entropy(data), 7.9)

    def test_is_high_entropy_uses_config_default_threshold(self):
        self.assertTrue(EntropyCalculator.is_high_entropy(7.9))
        self.assertFalse(EntropyCalculator.is_high_entropy(3.0))

    def test_calculate_file_entropy_missing_file_returns_none(self):
        self.assertIsNone(EntropyCalculator.calculate_file_entropy('does_not_exist.bin'))


if __name__ == '__main__':
    unittest.main()
