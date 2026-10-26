# Tugas 2 KI: Key Distribution (KDC) + AES

Tiga entitas pada tiga IP berbeda: **KDC**, **Alice**, **Bob**. AES-128 dan KDC ditulis manual (hanya modul bawaan Python). Tidak perlu `pip install`.

## File

| File | Peran |
| --- | --- |
| `aes.py` | AES-128 manual: S-Box, KeyExpansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, mode CBC + padding PKCS#7 |
| `kdc.py` | Server KDC, menyimpan master key tiap entitas, membuat session key |
| `alice.py` | Inisiator skenario, lalu chat dua arah dengan Bob |
| `bob.py` | Menunggu Alice, memverifikasi langkah 3-5, lalu chat dua arah |
| `common.py` | Helper socket, nonce, session key, loop chat |
| `test_aes.py` | Uji AES terhadap vektor resmi FIPS-197 |

## Skenario Key Distribution

Ka = master key Alice-KDC, Kb = master key Bob-KDC, Ks = session key. Ka dan Kb diinput saat program mulai (tidak di-hardcode). Ks dibuat acak oleh KDC.

1. Alice → KDC: `ID_A | ID_B | N1`
2. KDC → Alice: `E(Ka, [Ks | ID_B | N1 | E(Kb, [Ks | ID_A])])`
3. Alice → Bob: `E(Kb, [Ks | ID_A])`
4. Bob → Alice: `E(Ks, N2)`
5. Alice → Bob: `E(Ks, N2 - 1)`

Setelah langkah 5, setiap pesan dienkripsi AES dengan Ks. Plaintext dan key berformat ASCII, ciphertext ditampilkan dalam hex.

## Cara menjalankan (3 perangkat)

Urutan: KDC, Bob, lalu Alice. Ketiganya harus satu jaringan (hotspot HP lebih aman dari Wi-Fi kampus).

```bash
# Perangkat 1 (KDC): masukkan master key Alice lalu Bob
python3 kdc.py

# Perangkat 2 (Bob): masukkan master key Bob (sama dengan yang diberikan ke KDC)
python3 bob.py

# Perangkat 3 (Alice): argumen berupa ip[:port] KDC lalu Bob
python3 alice.py <IP_KDC> <IP_BOB>
```

Port default: KDC `5000`, Bob `6000`. Cek IP di macOS: `ipconfig getifaddr en0`.
Master key harus tepat 16 karakter ASCII.

## Perintah interaktif

| Di mana | Perintah | Fungsi |
| --- | --- | --- |
| Alice / Bob | teks biasa | kirim pesan terenkripsi |
| Alice | `/rekey` | ulangi langkah 1-5, session key baru |
| Alice | `/masterkey` | ganti master key Alice, lalu rekey otomatis |
| Bob | `/masterkey` | ganti master key Bob, berlaku di sesi berikutnya |
| Alice / Bob | `/key` | tampilkan session key |
| Alice / Bob | `/quit` | keluar |
| KDC | `key <ID> <16 karakter>` | ganti master key di KDC (harus sama dengan di Alice/Bob) |
| KDC | `show`, `quit` | lihat key / keluar |

Setelah Alice `/rekey`, terminal Bob akan menampilkan "Koneksi ditutup lawan bicara. Tekan Enter." Tekan Enter, lalu Bob siap menerima sesi baru.

## Test case yang bisa didemokan

- Key benar: langkah 1-5 sukses, chat dua arah jalan.
- Key Alice di Alice berbeda dari yang ada di KDC: dekripsi langkah 2 gagal, sesi tidak terbentuk.
- Ganti master key lewat `/masterkey` lalu `key Alice ...` di KDC, tanpa restart program.
- `/rekey`: session key berubah, ciphertext pesan yang sama ikut berubah.
- Kirim pesan yang sama dua kali: ciphertext berbeda karena IV acak (CBC).

## Wireshark

1. Pilih interface yang dipakai (macOS Wi-Fi: `en0`), jalankan capture sebelum program dimulai.
2. Display filter:
   - semua trafik tugas: `tcp.port == 5000 || tcp.port == 6000`
   - hanya KDC: `tcp.port == 5000`
   - hanya Alice-Bob: `tcp.port == 6000`
3. Klik kanan paket, **Follow → TCP Stream**: terlihat baris hex ciphertext, tidak ada plaintext maupun key.
4. Cocokkan hex langkah 1-5 di Wireshark dengan log di terminal. Langkah 1 berupa `Alice|Bob|<nonce>` karena memang tidak dienkripsi.

## Uji

```bash
python3 test_aes.py
```
