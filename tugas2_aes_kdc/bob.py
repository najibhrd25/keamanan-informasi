import socket
import sys

from aes import decrypt_text, encrypt_text
from common import (BOB_PORT, ask_key, chat, new_nonce, open_reader, recv_line,
                    send_line)

ID_B = "Bob"


def handshake(conn, rfile, master_key):
    for_bob = recv_line(rfile)
    print(f"[3] Alice -> Bob : {for_bob}")
    session_key, id_a = decrypt_text(for_bob, master_key).split("|")
    print(f"    Session key diterima: {session_key} (dari {id_a})")
    n2 = new_nonce()
    challenge = encrypt_text(n2, session_key)
    send_line(conn, challenge)
    print(f"[4] Bob -> Alice : {challenge}")
    answer = recv_line(rfile)
    print(f"[5] Alice -> Bob : {answer}")
    if int(decrypt_text(answer, session_key)) != int(n2) - 1:
        raise ValueError("jawaban nonce salah")
    return session_key, id_a


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else BOB_PORT
    state = {"key": ask_key("Bob")}

    def change_key():
        state["key"] = ask_key("Bob (baru)")
        print("Samakan juga di KDC: key Bob <key baru>. Berlaku di sesi berikutnya.")
        return False

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"Bob menunggu Alice di port {port}")

    while True:
        try:
            conn, addr = server.accept()
        except KeyboardInterrupt:
            break
        print(f"\nKoneksi dari {addr[0]}:{addr[1]}")
        try:
            conn.settimeout(10)
            rfile = open_reader(conn)
            session_key, id_a = handshake(conn, rfile, state["key"])
            conn.settimeout(None)
        except (ValueError, ConnectionError, OSError) as err:
            print(f"[-] Handshake gagal: {err}")
            conn.close()
            continue
        print("Sesi aman terbentuk. Perintah: /masterkey /key /quit")
        commands = {
            "/masterkey": change_key,
            "/key": lambda: print(f"Session key: {session_key}") and False,
            "/quit": lambda: True,
        }
        if chat(conn, rfile, session_key, ID_B, id_a, commands) == "/quit":
            break


if __name__ == "__main__":
    main()
