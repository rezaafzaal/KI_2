# aes.py - STUB SEMENTARA
# Isi fungsi ini akan diganti AES-128 asli oleh Reza di branch feature/aes-mode.
# Nama fungsi dan parameternya JANGAN diubah.


def encrypt(plaintext: str, key: str) -> str:
    """plaintext ASCII + key ASCII 16 karakter -> ciphertext hex"""
    return plaintext.encode().hex()  # TODO: ganti dengan AES asli


def decrypt(cipher_hex: str, key: str) -> str:
    """ciphertext hex -> plaintext ASCII. Raise ValueError jika gagal."""
    return bytes.fromhex(cipher_hex).decode()