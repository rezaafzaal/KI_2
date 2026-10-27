# Panduan Wireshark - Demo KDC + AES

## Persiapan
1. Buka Wireshark sebagai Administrator.
2. Pilih interface yang memegang IP demo (Wi-Fi atau Ethernet), BUKAN loopback.
   Cek IP dengan `ipconfig` di tiap perangkat.
3. Pasang display filter:
   ```
   tcp.port == 5000 || tcp.port == 6000
   ```
   - 5000 = KDC, 6000 = Bob
   - Untuk mempersempit: `(tcp.port == 5000 || tcp.port == 6000) && ip.addr == <IP_Alice>`
4. Mulai capture SEBELUM menjalankan Alice.

## Format pesan di paket
Setiap pesan = 4 byte panjang (big-endian) + JSON.
Klik paket berisi data → panel bawah → bagian "Data" / payload.
Cara paling mudah membaca: klik kanan paket → Follow → TCP Stream.

## Yang harus terlihat di tiap langkah
| Langkah | Arah | Port | Yang terlihat di payload |
| --- | --- | --- | --- |
| (1) | Alice → KDC | 5000 | `"type": "STEP1"`, `id_a`, `id_b`, `n1` terbaca jelas (memang plaintext) |
| (2) | KDC → Alice | 5000 | `for_alice` dan `ticket` berupa hex acak |
| (3) | Alice → Bob | 6000 | `ticket` hex, sama persis dengan tiket di langkah 2 |
| (4) | Bob → Alice | 6000 | `data` hex = E(Ks, N2) |
| (5) | Alice → Bob | 6000 | `data` hex = E(Ks, f(N2)) |
| Chat | dua arah | 6000 | `"type": "CHAT"`, `data` hex; isi pesan TIDAK terbaca |

## Bukti Ks tidak pernah lewat jaringan dalam bentuk plaintext
1. Salin Ks yang dicetak di terminal KDC, misalnya `fxeL4RacFZLBImIB`.
2. Pasang filter:
   ```
   frame contains "fxeL4RacFZLBImIB"
   ```
3. Hasil yang benar: 0 paket.
4. Lakukan hal yang sama dengan isi salah satu pesan chat. Hasilnya juga harus 0 paket.

## Catatan
- Langkah 1 memang plaintext sesuai skenario. Ini bukan kebocoran, karena isinya hanya ID dan nonce.
- Kalau tidak ada paket sama sekali: cek interface, lalu cek apakah Windows Firewall memblokir Python (izinkan di Private network).