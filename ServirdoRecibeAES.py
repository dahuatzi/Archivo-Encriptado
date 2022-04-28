import socket
import nacl.utils
import nacl.secret
from nacl.bindings import sodium_increment


host = "127.0.0.1"
puerto = 1000
FORMAT = "utf-8"
SIZE = 1024


def main():
    key = nacl.utils.randombytes_deterministic(
        nacl.secret.SecretBox.KEY_SIZE, b'3\xba\x8f\r]\x1c\xcbOsU\x12\xb6\x9c(\xcb\x94')

    box = nacl.secret.SecretBox(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, puerto))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Conexión recibida de {addr}")
            nonce = conn.recv(nacl.secret.SecretBox.NONCE_SIZE)

            file_data = b""
            while True:
                data = conn.recv(SIZE + box.MACBYTES)
                if len(data) == 0:
                    break
                elif len(data) % 16 != 0:
                    data += bytes(" " * (16 - (len(data) % 16)), FORMAT)

                file_data += box.decrypt(data, nonce)
                nonce = sodium_increment(nonce)

    with open("mandar/recibido.txt", "rb") as file:
        file.write(file_data)


if __name__ == "__main__":
    main()




