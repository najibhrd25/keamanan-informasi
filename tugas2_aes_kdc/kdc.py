import socket
import sys
import threading

from aes import encrypt_text, is_valid_key
from common import KDC_PORT, ask_key, new_session_key, open_reader, recv_line, send_line

master_keys = {}
lock = threading.Lock()


def handle(conn, addr):
    try:
        rfile = open_reader(conn)
        request = recv_line(rfile)
        print(f"\n[KDC] Langkah 1 dari {addr[0]}: {request}")
        id_a, id_b, nonce = request.split("|")
        with lock:
            key_a = master_keys.get(id_a)
            key_b = master_keys.get(id_b)
        if key_a is None or key_b is None:
            send_line(conn, "ERROR|identitas tidak dikenal")
            print("[KDC] Identitas tidak dikenal")
            return
        session_key = new_session_key()
        for_bob = encrypt_text(f"{session_key}|{id_a}", key_b)
        reply = encrypt_text(f"{session_key}|{id_b}|{nonce}|{for_bob}", key_a)
        send_line(conn, reply)
        print(f"[KDC] Session key dibuat: {session_key}")
        print(f"[KDC] Langkah 2 terkirim ke {id_a}: {reply}")
    except (ValueError, ConnectionError, OSError) as err:
        print(f"[KDC] Request gagal: {err}")
    finally:
        conn.close()


def serve(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else KDC_PORT
    master_keys["Alice"] = ask_key("Alice")
    master_keys["Bob"] = ask_key("Bob")
    threading.Thread(target=serve, args=(port,), daemon=True).start()
    print(f"KDC aktif di port {port}")
    print("Perintah: key <ID> <16 karakter> | show | quit")
    while True:
        try:
            parts = input("KDC> ").split()
        except (EOFError, KeyboardInterrupt):
            break
        if not parts:
            continue
        if parts[0] == "quit":
            break
        if parts[0] == "show":
            with lock:
                for name, key in master_keys.items():
                    print(f"{name}: {key}")
        elif parts[0] == "key" and len(parts) == 3 and is_valid_key(parts[2]):
            with lock:
                master_keys[parts[1]] = parts[2]
            print(f"Master key {parts[1]} diperbarui")
        else:
            print("Perintah tidak valid")


if __name__ == "__main__":
    main()
