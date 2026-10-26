# aes_cli.py - tester AES-128-CBC interaktif, buat demo di luar chat

import aes
from utils import validate_key

MENU = """
1. ganti key
2. enkripsi
3. dekripsi
4. keluar"""


def main():
    key = None
    while True:
        print(MENU)
        print(f"key sekarang: {key if key else '(belum diisi)'}")
        try:
            pilih = input("pilih: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        try:
            if pilih == "1":
                baru = input("key baru (16 karakter ASCII): ")
                validate_key(baru)
                key = baru
                print("key diganti")
            elif pilih in ("2", "3") and key is None:
                print("isi key dulu (menu 1)")
            elif pilih == "2":
                plain = input("plaintext: ")
                cipher = aes.encrypt(plain, key)
                print(f"IV         = {cipher[:32]}")
                print(f"ciphertext = {cipher[32:]}")
                print(f"kirim      = {cipher}")
            elif pilih == "3":
                cipher = input("ciphertext hex (IV di depan): ").strip()
                print(f"plaintext  = {aes.decrypt(cipher, key)}")
            elif pilih == "4":
                break
            else:
                print("pilihan tidak ada")
        except ValueError as e:
            print(f"gagal: {e}")
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
