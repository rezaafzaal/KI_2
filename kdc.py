# kdc.py - Key Distribution Center: melayani langkah (1) dan (2) skenario slide 13
import json
import socket
import threading

import aes
import protocol as p
from net import send_msg, recv_msg

master_keys = {}               # id entitas -> master key (Ka, Kb, ...), diisi saat runtime
keys_lock = threading.Lock()   # dict diakses dari thread menu dan thread client


def valid_key(key):
    return len(key) == p.KEY_LEN and key.isascii()


def handle_client(conn, addr):
    """Satu koneksi = satu permintaan session key."""
    try:
        msg = recv_msg(conn)
        if msg.get("type") != p.STEP1:
            send_msg(conn, {"type": p.ERROR, "reason": "pesan pertama harus STEP1"})
            return

        # (1) ID_A || ID_B || N1  -- plaintext
        id_a, id_b, n1 = msg["id_a"], msg["id_b"], msg["n1"]
        p.log("KDC", f"(1) dari {addr[0]}: ID_A={id_a}, ID_B={id_b}, N1={n1}")

        with keys_lock:
            ka = master_keys.get(id_a)
            kb = master_keys.get(id_b)
        if ka is None or kb is None:
            missing = id_a if ka is None else id_b
            send_msg(conn, {"type": p.ERROR, "reason": f"ID '{missing}' tidak terdaftar di KDC"})
            p.log("KDC", f"ditolak: ID '{missing}' tidak terdaftar")
            return

        # (2) E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
        ks = p.gen_session_key()
        for_alice = aes.encrypt(
            json.dumps({"ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1}), ka)
        ticket = aes.encrypt(json.dumps({"ks": ks, "id_a": id_a}), kb)
        send_msg(conn, {"type": p.STEP2, "for_alice": for_alice, "ticket": ticket})

        p.log("KDC", f"Ks baru untuk {id_a} <-> {id_b}: {ks}")
        p.log("KDC", f"(2) E(Ka,[Ks||ID_A||ID_B||N1]) = {for_alice}")
        p.log("KDC", f"(2) tiket E(Kb,[Ks||ID_A])     = {ticket}")
    except (ConnectionError, KeyError, ValueError) as e:
        p.log("KDC", f"error dari {addr[0]}: {e}")
    finally:
        conn.close()


def accept_loop(srv):
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


HELP = """Perintah:
  add <id> <key>   daftarkan / ganti master key (16 karakter ASCII)
  del <id>         hapus entitas
  list             tampilkan entitas terdaftar
  help             tampilkan bantuan ini
  quit             matikan KDC"""


def menu():
    print(HELP)
    while True:
        try:
            line = input("KDC> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()

        if cmd == "add" and len(parts) == 3:
            ident, key = parts[1], parts[2]
            if not valid_key(key):
                print(f"key harus tepat {p.KEY_LEN} karakter ASCII (sekarang {len(key)})")
                continue
            with keys_lock:
                existed = ident in master_keys
                master_keys[ident] = key
            print(f"master key '{ident}' {'diganti' if existed else 'didaftarkan'}")
        elif cmd == "del" and len(parts) == 2:
            with keys_lock:
                removed = master_keys.pop(parts[1], None)
            print("dihapus" if removed else "ID tidak ditemukan")
        elif cmd == "list":
            with keys_lock:
                ids = list(master_keys)
            print("terdaftar:", ", ".join(ids) if ids else "(kosong)")
        elif cmd == "help":
            print(HELP)
        elif cmd == "quit":
            break
        else:
            print("perintah tidak dikenal, ketik 'help'")


def main():
    cfg = p.load_config()
    default_port = cfg.get("kdc_port", p.KDC_PORT)
    host = input("Host bind [0.0.0.0]: ").strip() or "0.0.0.0"
    port_in = input(f"Port [{default_port}]: ").strip()
    port = int(port_in) if port_in else default_port

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    p.log("KDC", f"listening di {host}:{port}")

    threading.Thread(target=accept_loop, args=(srv,), daemon=True).start()
    menu()
    srv.close()
    p.log("KDC", "berhenti")


if __name__ == "__main__":
    main()