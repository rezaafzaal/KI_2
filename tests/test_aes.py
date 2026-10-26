import os
import sys
import unittest

# biar bisa import aes.py dari root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aes import decrypt_block, encrypt_block, key_expansion, pad, unpad

# test vector FIPS-197 C.1
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


class TestAESBlock(unittest.TestCase):
    def test_encrypt_fips197_c1(self):
        w = key_expansion(KEY)
        self.assertEqual(encrypt_block(PLAINTEXT, w), CIPHERTEXT)

    def test_decrypt_fips197_c1(self):
        w = key_expansion(KEY)
        self.assertEqual(decrypt_block(CIPHERTEXT, w), PLAINTEXT)


class TestPadding(unittest.TestCase):
    def test_pad_unpad(self):
        for n in range(0, 40):
            data = b"a" * n
            padded = pad(data)
            self.assertEqual(len(padded) % 16, 0)
            self.assertEqual(unpad(padded), data)

    def test_pad_kelipatan_16(self):
        self.assertEqual(pad(b"a" * 16), b"a" * 16 + bytes([16] * 16))

    def test_unpad_tidak_valid(self):
        for salah in [b"", b"a" * 15, b"a" * 15 + b"\x00", b"a" * 15 + b"\x11",
                      b"a" * 14 + b"\x01\x02"]:
            with self.assertRaises(ValueError):
                unpad(salah)


if __name__ == "__main__":
    unittest.main()
