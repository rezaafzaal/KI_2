# utils.py - validasi key dan konversi ASCII/hex

KEY_LEN = 16


def validate_key(key: str) -> bytes:
    if not isinstance(key, str) or not key.isascii():
        raise ValueError("key harus ASCII")
    if len(key) != KEY_LEN:
        raise ValueError(f"key harus {KEY_LEN} karakter, sekarang {len(key)}")
    return key.encode("ascii")


def ascii_to_bytes(text: str) -> bytes:
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("plaintext harus ASCII")
    return text.encode("ascii")


def bytes_to_ascii(data: bytes) -> str:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("hasil dekripsi bukan ASCII (key salah?)")


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except (ValueError, TypeError):
        raise ValueError("ciphertext bukan hex yang valid")
