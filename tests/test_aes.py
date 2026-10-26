import os
import sys
import unittest

# biar bisa import aes.py dari root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aes import (cbc_decrypt, cbc_encrypt, decrypt, decrypt_block, encrypt,
                 encrypt_block, key_expansion, pad, unpad)

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


class TestCBC(unittest.TestCase):
    def test_nist_sp800_38a(self):
        # NIST SP 800-38A F.2.1, 2 blok pertama
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                              "ae2d8a571e03ac9c9eb76fac45af8e51")
        hasil = cbc_encrypt(plain, key, iv)
        self.assertEqual(hasil[:16], iv)
        self.assertEqual(hasil[16:48].hex(), "7649abac8119b246cee98e9b12e9197d"
                                             "5086cb9b507219ee95db113a917678b2")

    def test_bolak_balik_3_blok(self):
        key = b"kuncirahasia1234"
        plain = b"a" * 40
        self.assertEqual(cbc_decrypt(cbc_encrypt(plain, key), key), plain)

    def test_iv_acak(self):
        key = b"kuncirahasia1234"
        self.assertNotEqual(cbc_encrypt(b"halo", key), cbc_encrypt(b"halo", key))

    def test_key_salah(self):
        c = cbc_encrypt(b"pesan rahasia", b"kuncirahasia1234")
        gagal = 0
        for i in range(50):
            try:
                if cbc_decrypt(c, b"kuncisalah%06d" % i) != b"pesan rahasia":
                    gagal += 1
            except ValueError:
                gagal += 1
        self.assertEqual(gagal, 50)


class TestAPI(unittest.TestCase):
    KEY = "kuncirahasia1234"

    def test_bolak_balik(self):
        for teks in ["", "halo", "a" * 16, "pesan yang lebih panjang dari 3 blok AES ya"]:
            self.assertEqual(decrypt(encrypt(teks, self.KEY), self.KEY), teks)

    def test_output_hex_dengan_iv(self):
        c = encrypt("halo", self.KEY)
        self.assertEqual(len(c), 64)  # 16 byte IV + 1 blok, dalam hex
        bytes.fromhex(c)

    def test_input_tidak_valid(self):
        c = encrypt("halo", self.KEY)
        salah = [
            lambda: encrypt("halo", "pendek"),
            lambda: encrypt("halo é", self.KEY),
            lambda: decrypt(c, "kunciyangsalah12"),
            lambda: decrypt("bukan hex", self.KEY),
            lambda: decrypt(c[:-2], self.KEY),
            lambda: decrypt(c[:32], self.KEY),
        ]
        for f in salah:
            with self.assertRaises(ValueError):
                f()


if __name__ == "__main__":
    unittest.main()
