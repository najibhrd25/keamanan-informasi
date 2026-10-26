from aes import (decrypt_block, decrypt_text, encrypt_block, encrypt_text,
                 expand_key)

KEY = bytes(range(16))
PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHER = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

round_keys = expand_key(KEY)
assert encrypt_block(PLAIN, round_keys) == CIPHER
assert decrypt_block(CIPHER, round_keys) == PLAIN

secret = "KunciRahasia1234"
for text in ["a", "Halo Bob", "x" * 16, "Pesan rahasia Alice ke Bob 123!"]:
    assert decrypt_text(encrypt_text(text, secret), secret) == text

print("Semua tes AES lulus")
