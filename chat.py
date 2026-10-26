# chat.py - chat dua arah terenkripsi Ks, dipakai Alice dan Bob setelah handshake
import threading

import aes
import protocol as p
from net import send_msg, recv_msg

HELP = """Perintah chat:
  <teks>          kirim pesan (dienkripsi Ks, dikirim sebagai hex)
  /show           tampilkan session key Ks yang sedang dipakai
  /key <16 char>  ganti Ks manual (lawan harus ganti ke key yang sama)
  /rekey          minta Ks baru ke KDC dan kirim tiketnya ke Bob (hanya Alice)
  /master <16>    ganti master key sendiri (Ka/Kb) untuk rekey berikutnya
  /help           tampilkan bantuan ini
  /quit           keluar"""


class Session:
    """Menyimpan Ks yang sedang aktif. Dipakai bersama oleh thread kirim dan thread terima."""

    def __init__(self, ks):
        self._ks = ks
        self._lock = threading.Lock()
        self.running = True

    def get(self):
        with self._lock:
            return self._ks

    def set(self, ks):
        with self._lock:
            self._ks = ks


def valid_key(key):
    return len(key) == p.KEY_LEN and key.isascii()


def receiver(sock, sess, me, peer, on_rekey):
    """Thread penerima: jalan terus di belakang, supaya bisa menerima sambil mengetik."""
    while sess.running:
        try:
            msg = recv_msg(sock)
        except (ConnectionError, OSError, ValueError):
            if sess.running:
                print(f"\n[koneksi dengan {peer} terputus, tekan Enter]")
                sess.running = False
            break

        tipe = msg.get("type")
        if tipe == p.CHAT:
            cipher = msg.get("data", "")
            print(f"\n[{peer}] cipher = {cipher}")
            try:
                print(f"[{peer}] plain  = {aes.decrypt(cipher, sess.get())}")
            except ValueError:
                print(f"[{peer}] GAGAL dekripsi - Ks kedua pihak berbeda?")
        elif tipe == p.REKEY and on_rekey:
            ks_baru = on_rekey(msg)
            if ks_baru:
                sess.set(ks_baru)
                print("\n[Ks diganti lewat rekey]")
        elif tipe == p.BYE:
            print(f"\n[{peer} keluar dari chat, tekan Enter]")
            sess.running = False
            break
        print(f"{me}> ", end="", flush=True)


def chat_loop(sock, ks, me, peer, rekey=None, on_rekey=None, set_master=None):
    """Thread utama: membaca input dan mengirim. Thread lain menerima."""
    sess = Session(ks)
    print(HELP)
    threading.Thread(target=receiver, args=(sock, sess, me, peer, on_rekey),
                     daemon=True).start()

    try:
        while sess.running:
            try:
                line = input(f"{me}> ")
            except (EOFError, KeyboardInterrupt):
                line = "/quit"
            if not sess.running:
                break
            if not line:
                continue

            if not line.startswith("/"):
                if not line.isascii():
                    print("pesan harus ASCII")
                    continue
                cipher = aes.encrypt(line, sess.get())
                send_msg(sock, {"type": p.CHAT, "data": cipher})
                print(f"[{me}] cipher = {cipher}")
                continue

            cmd, _, arg = line.partition(" ")
            arg = arg.strip()
            if cmd == "/help":
                print(HELP)
            elif cmd == "/show":
                print(f"Ks sekarang: {sess.get()}")
            elif cmd == "/key":
                if valid_key(arg):
                    sess.set(arg)
                    print(f"Ks diganti manual jadi {arg}. {peer} harus /key ke nilai yang sama.")
                else:
                    print(f"key harus tepat {p.KEY_LEN} karakter ASCII")
            elif cmd == "/rekey":
                if rekey is None:
                    print("rekey hanya bisa dari Alice")
                    continue
                try:
                    ks_baru, tiket = rekey()
                except (RuntimeError, ValueError, OSError) as e:
                    print(f"rekey gagal: {e}")
                    continue
                send_msg(sock, {"type": p.REKEY, "ticket": tiket})
                sess.set(ks_baru)
                print(f"Ks baru dari KDC: {ks_baru}, tiket dikirim ke {peer}")
            elif cmd == "/master":
                if set_master and valid_key(arg):
                    set_master(arg)
                    print("master key diganti, berlaku untuk rekey berikutnya")
                else:
                    print(f"pakai: /master <{p.KEY_LEN} karakter ASCII>")
            elif cmd == "/quit":
                try:
                    send_msg(sock, {"type": p.BYE})
                except OSError:
                    pass
                break
            else:
                print("perintah tidak dikenal, ketik /help")
    finally:
        sess.running = False
        sock.close()