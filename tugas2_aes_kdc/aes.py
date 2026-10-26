import os


def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def build_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ xtime(p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = build_sbox()
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


def expand_key(key):
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = words[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(11)]


def add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = s[4 * ((c + r) % 4) + r]
    return out


def inv_shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * ((c + r) % 4) + r] = s[4 * c + r]
    return out


def mix_columns(s):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3,
            a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3,
            a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3),
            gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2),
        ]
    return out


def inv_mix_columns(s):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [
            gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
            gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
            gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
            gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14),
        ]
    return out


def encrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[0])
    for r in range(1, 10):
        s = add_round_key(mix_columns(shift_rows(sub_bytes(s))), round_keys[r])
    s = add_round_key(shift_rows(sub_bytes(s)), round_keys[10])
    return bytes(s)


def decrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[10])
    for r in range(9, 0, -1):
        s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)), round_keys[r]))
    s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), round_keys[0])
    return bytes(s)


def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid")
    return data[:-n]


def encrypt(data, key, iv=None):
    round_keys = expand_key(key)
    prev = iv if iv is not None else os.urandom(16)
    out = bytearray(prev)
    data = pad(data)
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(block, round_keys)
        out += prev
    return bytes(out)


def decrypt(data, key):
    if len(data) < 32 or len(data) % 16:
        raise ValueError("panjang ciphertext tidak valid")
    round_keys = expand_key(key)
    prev = data[:16]
    out = bytearray()
    for i in range(16, len(data), 16):
        block = data[i:i + 16]
        plain = decrypt_block(block, round_keys)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    return unpad(bytes(out))


def is_valid_key(key):
    return len(key) == 16 and key.isascii() and key.isprintable()


def key_bytes(key):
    if not is_valid_key(key):
        raise ValueError("key harus 16 karakter ASCII")
    return key.encode("ascii")


def encrypt_text(text, key):
    return encrypt(text.encode("ascii"), key_bytes(key)).hex()


def decrypt_text(hex_text, key):
    return decrypt(bytes.fromhex(hex_text), key_bytes(key)).decode("ascii")
