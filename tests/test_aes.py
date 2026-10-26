import os
import sys
import unittest

# supaya aes.py di root repo bisa di-import dari folder tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aes import decrypt_block, encrypt_block, key_expansion

# FIPS-197 Appendix C.1 (AES-128)
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


if __name__ == "__main__":
    unittest.main()
