import socket
import secrets
import string
import threading

from aes import encrypt_text, decrypt_text, is_valid_key

KDC_PORT = 5000
BOB_PORT = 6000


def parse_addr(text, default_port):
    host, _, port = text.partition(":")
    return host, int(port) if port else default_port


def ask_key(label):
    while True:
        key = input(f"Master key {label} (16 karakter ASCII): ")
        if is_valid_key(key):
            return key
        print("Key harus tepat 16 karakter ASCII.")


def open_reader(sock):
    return sock.makefile("r", encoding="ascii", newline="\n")


def send_line(sock, text):
    sock.sendall((text + "\n").encode("ascii"))


def recv_line(rfile):
    line = rfile.readline()
    if not line:
        raise ConnectionError("koneksi terputus")
    return line.strip()


def new_nonce():
    return f"{secrets.randbelow(10 ** 8):08d}"


def new_session_key():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16))


def chat(sock, rfile, session_key, me, peer, commands):
    closed = threading.Event()
    finished = threading.Event()

    def reader():
        while not finished.is_set():
            try:
                line = rfile.readline()
            except (OSError, ValueError):
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            print(f"\n[+] Ciphertext masuk: {line}")
            try:
                message = decrypt_text(line, session_key)
            except ValueError:
                print("[-] Dekripsi gagal")
            else:
                print(f"[{peer}] {message}")
            print(f"{me}> ", end="", flush=True)
        if not finished.is_set():
            closed.set()
            print("\n[!] Koneksi ditutup lawan bicara. Tekan Enter.")

    threading.Thread(target=reader, daemon=True).start()

    action = "closed"
    while True:
        try:
            text = input(f"{me}> ").strip()
        except (EOFError, KeyboardInterrupt):
            action = "/quit"
            break
        if closed.is_set():
            break
        if not text:
            continue
        if text.startswith("/"):
            name = text.split()[0]
            handler = commands.get(name)
            if handler is None:
                print("Perintah tersedia:", ", ".join(commands))
            elif handler():
                action = name
                break
            continue
        try:
            cipher_hex = encrypt_text(text, session_key)
        except ValueError:
            print("Plaintext hanya boleh karakter ASCII.")
            continue
        print(f"[*] Terkirim (Ciphertext): {cipher_hex}")
        try:
            send_line(sock, cipher_hex)
        except OSError:
            break

    finished.set()
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()
    return action
