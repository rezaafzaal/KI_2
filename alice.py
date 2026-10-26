# alice.py - Initiator A: minta Ks ke KDC (1-2), kirim tiket ke Bob (3), jawab challenge (4-5)
import json
import socket

import aes
import protocol as p
from net import send_msg, recv_msg


def get_session_key(kdc_addr, id_a, id_b, ka):
    """Langkah 1-2. Mengembalikan (Ks, tiket untuk Bob)."""
    with socket.create_connection(kdc_addr, timeout=10) as s:
        n1 = p.make_nonce()
        send_msg(s, {"type": p.STEP1, "id_a": id_a, "id_b": id_b, "n1": n1})
        p.log("ALICE", f"(1) -> KDC: ID_A={id_a}, ID_B={id_b}, N1={n1}")
        resp = recv_msg(s)

    if resp.get("type") == p.ERROR:
        raise RuntimeError(f"KDC menolak: {resp.get('reason')}")
    if resp.get("type") != p.STEP2:
        raise RuntimeError("balasan KDC tidak dikenal")

    p.log("ALICE", f"(2) <- KDC: for_alice = {resp['for_alice']}")
    try:
        isi = json.loads(aes.decrypt(resp["for_alice"], ka))
    except ValueError:
        raise RuntimeError("gagal mendekripsi balasan KDC - Ka salah?")

    if isi.get("n1") != n1:
        raise RuntimeError("N1 tidak cocok - kemungkinan replay, Ks ditolak")
    if isi.get("id_a") != id_a or isi.get("id_b") != id_b:
        raise RuntimeError("ID di balasan KDC tidak sesuai permintaan")

    p.log("ALICE", f"(2) N1 cocok, Ks diterima: {isi['ks']}")
    return isi["ks"], resp["ticket"]


def handshake_with_bob(bob_addr, ks, ticket):
    """Langkah 3-5. Mengembalikan socket yang sudah terautentikasi."""
    s = socket.create_connection(bob_addr, timeout=10)

    send_msg(s, {"type": p.STEP3, "ticket": ticket})
    p.log("ALICE", f"(3) -> Bob: tiket = {ticket}")

    m4 = recv_msg(s)
    if m4.get("type") == p.ERROR:
        raise RuntimeError(f"Bob menolak: {m4.get('reason')}")
    if m4.get("type") != p.STEP4:
        raise RuntimeError("balasan Bob tidak dikenal")
    n2 = int(aes.decrypt(m4["data"], ks))
    p.log("ALICE", f"(4) <- Bob: E(Ks,N2) = {m4['data']} -> N2={n2}")

    jawaban = aes.encrypt(str(p.f(n2)), ks)
    send_msg(s, {"type": p.STEP5, "data": jawaban})
    p.log("ALICE", f"(5) -> Bob: E(Ks,f(N2)) = {jawaban}  (f(N2)={p.f(n2)})")

    s.settimeout(None)
    return s


def main():
    cfg = p.load_config()
    id_a = p.ask("ID Alice", "alice")
    ka = p.ask_key("Master key Ka")
    id_b = p.ask("ID tujuan", "bob")
    kdc_addr = (p.ask("IP KDC", cfg["kdc_host"]),
                int(p.ask("Port KDC", cfg["kdc_port"])))
    bob_addr = (p.ask("IP Bob", cfg["bob_host"]),
                int(p.ask("Port Bob", cfg["bob_port"])))

    try:
        ks, ticket = get_session_key(kdc_addr, id_a, id_b, ka)
        sock = handshake_with_bob(bob_addr, ks, ticket)
    except (RuntimeError, ValueError, OSError) as e:
        p.log("ALICE", f"GAGAL: {e}")
        return

    p.log("ALICE", "handshake selesai, Ks siap dipakai untuk chat")
    sock.close()   # chat ditambahkan di branch feature/chat-cli


if __name__ == "__main__":
    main()