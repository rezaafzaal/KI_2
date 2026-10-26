# protocol.py - konstanta & helper untuk skenario key distribution (slide 13)
import json
import os
import secrets
import string

# ---- tipe pesan ----
STEP1 = "STEP1"   # Alice -> KDC : ID_A || ID_B || N1           (plaintext)
STEP2 = "STEP2"   # KDC -> Alice : E(Ka,[Ks||ID_A||ID_B||N1]) || E(Kb,[Ks||ID_A])
STEP3 = "STEP3"   # Alice -> Bob : E(Kb,[Ks||ID_A])             (tiket)
STEP4 = "STEP4"   # Bob -> Alice : E(Ks, N2)
STEP5 = "STEP5"   # Alice -> Bob : E(Ks, f(N2))
CHAT = "CHAT"     # Alice <-> Bob: E(Ks, pesan)
ERROR = "ERROR"   # pemberitahuan gagal (tanpa data rahasia)

# ---- default jaringan ----
KDC_PORT = 5000
BOB_PORT = 6000

# ---- kunci ----
KEY_LEN = 16                                        # AES-128 = 16 karakter ASCII
KEY_ALPHABET = string.ascii_letters + string.digits


def make_nonce():
    """Nonce acak 32 bit. Pakai secrets (CSPRNG), bukan random, supaya tidak bisa ditebak."""
    return secrets.randbits(32)


def f(n):
    """Fungsi transformasi nonce di langkah 5: f(N2) = N2 + 1."""
    return n + 1


def gen_session_key():
    """Session key Ks: 16 karakter ASCII acak (huruf + angka)."""
    return "".join(secrets.choice(KEY_ALPHABET) for _ in range(KEY_LEN))


def load_config():
    """Baca config.json kalau ada, kalau tidak pakai config.example.json."""
    path = "config.json" if os.path.exists("config.json") else "config.example.json"
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def log(who, msg):
    """Format log seragam supaya alur langkah 1-5 mudah diikuti saat demo."""
    print(f"[{who}] {msg}")
    


def ask(prompt, default=None):
    """input() dengan nilai default kalau user langsung Enter."""
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default


def ask_key(prompt):
    """Minta key sampai valid: tepat 16 karakter ASCII."""
    while True:
        key = input(f"{prompt} ({KEY_LEN} karakter ASCII): ")
        if len(key) == KEY_LEN and key.isascii():
            return key
        print(f"  key harus tepat {KEY_LEN} karakter ASCII, sekarang {len(key)} karakter")