import socket
import threading


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                try:
                    s.sendall(b'HEAD / HTTP/1.1\r\n\r\n') if port in [80, 443] else None
                    banner = s.recv(1024).decode().strip()
                    if banner:
                        print(f"[+] Port {port} ouvert – Service détecté : {banner}")
                except socket.error:
                    pass
    except Exception as e:
        pass


def scan_ports(ip, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=grab_banner, args=(ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    ip = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    scan_ports(ip, start_port, end_port)