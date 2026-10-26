# net.py - kirim/terima pesan JSON lewat TCP dengan prefix panjang 4 byte
import json
import struct

HEADER_SIZE = 4                  # panjang pesan dikirim sebagai unsigned int 4 byte
MAX_MSG_SIZE = 10 * 1024 * 1024  # batas 10 MB supaya header palsu tidak bikin hang


def recv_exact(sock, n):
    """Baca tepat n byte dari socket. recv() bisa mengembalikan data sepotong-sepotong."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:  # b'' berarti lawan bicara menutup koneksi
            raise ConnectionError("koneksi ditutup oleh peer")
        buf += chunk
    return buf


def send_msg(sock, obj):
    """dict -> JSON -> bytes, lalu kirim dengan 4 byte panjang di depannya."""
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack("!I", len(data))  # ! = big-endian (network order), I = uint32
    sock.sendall(header + data)


def recv_msg(sock):
    """Baca 4 byte panjang, lalu baca isi pesan sepanjang itu, kembalikan sebagai dict."""
    header = recv_exact(sock, HEADER_SIZE)
    (length,) = struct.unpack("!I", header)
    if length > MAX_MSG_SIZE:
        raise ValueError(f"pesan terlalu besar: {length} byte")
    data = recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))