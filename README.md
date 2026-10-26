# Tugas Keamanan Informasi: Key Distribution (KDC) + AES-128

| Nama | NRP | Bagian |
| --- | --- | --- |
| <Nama Reza> | <NRP Reza> | AES-128 manual (`aes.py`, `utils.py`, `aes_cli.py`, `tests/`) |
| <Nama Pasya> | <NRP Pasya> | Jaringan, KDC, handshake, chat (`net.py`, `protocol.py`, `kdc.py`, `alice.py`, `bob.py`, `chat.py`) |

## Arsitektur

Tiga entitas di tiga IP berbeda:

- **KDC** (port 5000): menyimpan master key Ka dan Kb, membuat session key Ks.
- **Bob** (port 6000): menunggu koneksi dari Alice.
- **Alice**: memulai permintaan ke KDC, lalu ke Bob.

Skenario key distribution:

| Langkah | Arah | Isi |
| --- | --- | --- |
| 1 | Alice → KDC | ID_A ‖ ID_B ‖ N1 (plaintext) |
| 2 | KDC → Alice | E(Ka, [Ks ‖ ID_A ‖ ID_B ‖ N1]) ‖ E(Kb, [Ks ‖ ID_A]) |
| 3 | Alice → Bob | E(Kb, [Ks ‖ ID_A]) (tiket) |
| 4 | Bob → Alice | E(Ks, N2) |
| 5 | Alice → Bob | E(Ks, f(N2)), f(N2) = N2 + 1 |

Setelah langkah 5, Alice dan Bob chat dua arah dengan E(Ks, pesan). Ciphertext ditampilkan dalam hex.

AES-128 diimplementasikan manual (key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey) dengan mode CBC, IV acak, dan padding PKCS#7. Implementasi diverifikasi dengan test vector FIPS-197 C.1.

## Format pesan jaringan

Setiap pesan dikirim sebagai 4 byte panjang (big-endian), diikuti JSON. Field yang terenkripsi berisi hex dengan format IV ‖ ciphertext.

## Cara menjalankan

Kebutuhan: Python 3.10+, tanpa library tambahan.

1. Salin `config.example.json` menjadi `config.json`, lalu isi IP KDC dan Bob. Bagian ini opsional, karena IP juga bisa diketik saat program meminta.
2. Di perangkat KDC:
   ```
   python kdc.py
   KDC> add alice <Ka 16 karakter>
   KDC> add bob <Kb 16 karakter>
   ```
3. Di perangkat Bob: `python bob.py`, lalu masukkan Kb.
4. Di perangkat Alice: `python alice.py`, lalu masukkan Ka serta IP KDC dan Bob.

Izinkan Python di Windows Firewall (Private network) pada perangkat KDC dan Bob.

## Perintah saat chat

| Perintah | Fungsi |
| --- | --- |
| `<teks>` | kirim pesan terenkripsi |
| `/show` | tampilkan Ks aktif |
| `/key <16 char>` | ganti Ks manual |
| `/rekey` | minta Ks baru ke KDC (hanya Alice) |
| `/master <16 char>` | ganti master key sendiri |
| `/quit` | keluar |

Master key di KDC bisa diganti saat program berjalan dengan `add <id> <key>`.

## Pengujian

- Unit test AES: `python -m unittest discover -s tests`
- Tester AES interaktif: `python aes_cli.py`
- Panduan Wireshark: [`docs/wireshark.md`](docs/wireshark.md)

## Keterbatasan

- Tiket tidak memakai timestamp, sehingga rentan replay kalau Ks lama bocor (serangan Denning–Sacco).
- `/rekey` tidak mengulang langkah 4–5.
- Ks dibatasi huruf dan angka ASCII, sehingga entropinya sekitar 95 bit, bukan 128 bit.