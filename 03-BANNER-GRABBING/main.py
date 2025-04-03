import socket
import threading

# Timeout global
socket.setdefaulttimeout(1)

# Résultats détectés
open_ports = []

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            try:
                # Requête spéciale pour HTTP
                if port in [80, 443]:
                    s.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                banner = s.recv(1024).decode(errors='ignore').strip()
                if banner:
                    print(f"[+] Port {port} ouvert – Service détecté : {banner}")
                    open_ports.append((port, banner))
                else:
                    # Port ouvert mais silencieux
                    pass
            except socket.timeout:
                pass
    except:
        pass  # Port fermé ou inaccessible

def scan_ports(ip, start_port, end_port):
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=grab_banner, args=(ip, port))
        t.start()
        threads.append(t)

    for thread in threads:
        thread.join()

    if not open_ports:
        print("Aucun service détecté sur cette plage de ports.")

if __name__ == "__main__":
    try:
        ip = input("Entrez l'adresse IP à scanner : ").strip()
        start_port = int(input("Port de début : ").strip())
        end_port = int(input("Port de fin : ").strip())

        print(f"\n[INFO] Scan de {ip} sur les ports {start_port} à {end_port}...\n")
        scan_ports(ip, start_port, end_port)

        # Bonus : Sauvegarde dans un fichier
        with open("resultats_banner.txt", "w") as f:
            for port, banner in open_ports:
                f.write(f"Port my{port} : {banner}\n")

    except KeyboardInterrupt:
        print("\n[INFO] Interruption par l'utilisateur.")
    except ValueError:
        print("[ERREUR] Ports invalides.")
