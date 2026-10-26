# bob.py - Responder B: terima tiket (3), kirim challenge N2 (4), verifikasi f(N2) (5)
import json
import socket

import aes
import protocol as p
from net import send_msg, recv_msg


def reject(conn, reason):
    send_msg(conn, {"type": p.ERROR, "reason": reason})
    p.log("BOB", f"DITOLAK: {reason}")
    return None


def handle_handshake(conn, kb):
    """Langkah 3-5. Mengembalikan (Ks, ID_A) kalau sukses, None kalau gagal."""
    m3 = recv_msg(conn)
    if m3.get("type") != p.STEP3:
        return reject(conn, "pesan pertama harus STEP3")

    # (3) E(Kb, [Ks || ID_A]) - hanya Bob yang bisa membuka tiket ini
    try:
        tiket = json.loads(aes.decrypt(m3["ticket"], kb))
        ks, id_a = tiket["ks"], tiket["id_a"]
    except (ValueError, KeyError):
        return reject(conn, "tiket tidak valid - Kb salah?")
    p.log("BOB", f"(3) tiket dari {id_a} dibuka, Ks = {ks}")

    # (4) E(Ks, N2)
    n2 = p.make_nonce()
    data4 = aes.encrypt(str(n2), ks)
    send_msg(conn, {"type": p.STEP4, "data": data4})
    p.log("BOB", f"(4) -> Alice: N2={n2}, E(Ks,N2) = {data4}")

    # (5) E(Ks, f(N2))
    m5 = recv_msg(conn)
    if m5.get("type") != p.STEP5:
        return reject(conn, "langkah 5 tidak diterima")
    try:
        nilai = int(aes.decrypt(m5["data"], ks))
    except ValueError:
        return reject(conn, "jawaban langkah 5 tidak bisa didekripsi")
    if nilai != p.f(n2):
        return reject(conn, f"f(N2) salah: dapat {nilai}, harusnya {p.f(n2)}")

    p.log("BOB", f"(5) f(N2)={nilai} cocok -> Handshake OK dengan {id_a}")
    return ks, id_a


def main():
    cfg = p.load_config()
    id_b = p.ask("ID Bob", "bob")
    kb = p.ask_key("Master key Kb")
    host = p.ask("Host bind", "0.0.0.0")
    port = int(p.ask("Port", cfg["bob_port"]))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    p.log("BOB", f"{id_b} menunggu di {host}:{port}  (Ctrl+C untuk berhenti)")

    try:
        while True:
            conn, addr = srv.accept()
            p.log("BOB", f"koneksi dari {addr[0]}")
            try:
                handle_handshake(conn, kb)
            except (ConnectionError, ValueError) as e:
                p.log("BOB", f"error: {e}")
            finally:
                conn.close()   # chat ditambahkan di branch feature/chat-cli
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()