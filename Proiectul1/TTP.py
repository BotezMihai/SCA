import socket
import threading


def config():
    sck = socket.socket()
    print("Server")
    try:
        sck.bind(("127.0.0.2", 4321))
        sck.listen(5)
        return sck
    except Exception as e:
        raise SystemExit("Eroare la bind")


def on_new_client(client, connection):
    ip = connection[0]
    port = connection[1]
    print(f"S-a conectat un nou client cu adresa ip {ip}, si portul: {port}!")
    print("aici")
    while True:
        msg = client.recv(1024)
        if msg.decode() == 'exit':
            break
        print(f"Mesajul de la client: {msg.decode()}")
        reply = f"You told me: {msg.decode()}"
        client.sendall(reply.encode('utf-8'))
    print(f"Clientul cu adresa ip: {ip}, si portul: {port}, a iesit!")
    client.close()


def main(sck):
    while True:
        try:
            client, ip = sck.accept()
            print("aici")
            t = threading.Thread(target=on_new_client, args=(client, ip))
            t.start()
        except Exception as e:
            print(f"Eroare la acceptarea de noi clienti: {e}")


if __name__ == '__main__':
    print("Payment gateway")
    sck = config()
    main(sck)
    sck.close()