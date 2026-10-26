import socket
import sys

from aes import decrypt_text, encrypt_text
from common import (BOB_PORT, KDC_PORT, ask_key, chat, new_nonce, open_reader,
                    parse_addr, recv_line, send_line)

ID_A = "Alice"
ID_B = "Bob"


def establish(kdc_addr, bob_addr, master_key):
    nonce = new_nonce()
    with socket.create_connection(kdc_addr, timeout=10) as kdc:
        send_line(kdc, f"{ID_A}|{ID_B}|{nonce}")
        print(f"[1] Alice -> KDC : {ID_A}|{ID_B}|{nonce}")
        reply = recv_line(open_reader(kdc))
    if reply.startswith("ERROR"):
        raise ValueError(reply)
    print(f"[2] KDC -> Alice : {reply}")
    session_key, id_b, nonce_back, for_bob = decrypt_text(reply, master_key).split("|")
    if id_b != ID_B or nonce_back != nonce:
        raise ValueError("ID atau nonce balasan KDC tidak cocok")
    print(f"    Session key diterima: {session_key}")

    sock = socket.create_connection(bob_addr, timeout=10)
    rfile = open_reader(sock)
    send_line(sock, for_bob)
    print(f"[3] Alice -> Bob : {for_bob}")
    challenge = recv_line(rfile)
    print(f"[4] Bob -> Alice : {challenge}")
    n2 = int(decrypt_text(challenge, session_key))
    answer = encrypt_text(str(n2 - 1), session_key)
    send_line(sock, answer)
    print(f"[5] Alice -> Bob : {answer}")
    sock.settimeout(None)
    return session_key, sock, rfile


def main():
    kdc_text = sys.argv[1] if len(sys.argv) > 1 else input("Alamat KDC (ip[:port]): ")
    bob_text = sys.argv[2] if len(sys.argv) > 2 else input("Alamat Bob (ip[:port]): ")
    kdc_addr = parse_addr(kdc_text, KDC_PORT)
    bob_addr = parse_addr(bob_text, BOB_PORT)
    state = {"key": ask_key("Alice")}

    def change_key():
        state["key"] = ask_key("Alice (baru)")
        print("Samakan juga di KDC: key Alice <key baru>")
        return True

    while True:
        try:
            session_key, sock, rfile = establish(kdc_addr, bob_addr, state["key"])
        except (ValueError, ConnectionError, OSError) as err:
            print(f"[-] Gagal membangun sesi: {err}")
            if input("Enter untuk coba lagi, /masterkey ganti key, q keluar: ").strip() == "q":
                break
            if input("Ganti master key? (y/n): ").strip() == "y":
                state["key"] = ask_key("Alice (baru)")
            continue
        print("Sesi aman terbentuk. Perintah: /rekey /masterkey /key /quit")
        commands = {
            "/rekey": lambda: True,
            "/masterkey": change_key,
            "/key": lambda: print(f"Session key: {session_key}") and False,
            "/quit": lambda: True,
        }
        if chat(sock, rfile, session_key, ID_A, ID_B, commands) == "/quit":
            break


if __name__ == "__main__":
    main()
