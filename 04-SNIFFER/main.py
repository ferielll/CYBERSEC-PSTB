from scapy.all import sniff, IP, TCP, UDP, ARP
from collections import defaultdict
import signal
import sys
import time

# Dictionnaires pour la détection
syn_packets = defaultdict(list)
arp_requests = defaultdict(int)

def packet_callback(pkt):
    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto

            if proto == 6 and TCP in pkt:
                print(f"[TCP] {src_ip} -> {dst_ip} | Flags: {pkt[TCP].flags}")
                detect_syn_scan(pkt)
            elif proto == 17 and UDP in pkt:
                print(f"[UDP] {src_ip} -> {dst_ip}")
        elif ARP in pkt:
            detect_arp(pkt)
    except Exception as e:
        print(f"Erreur lors de l'analyse du paquet : {e}")

def detect_syn_scan(pkt):
    if pkt[TCP].flags == 'S':
        syn_packets[pkt[IP].src].append(pkt[IP].dst)
        if len(syn_packets[pkt[IP].src]) > 10:  # seuil configurable
            print(f"[ALERTE] Scan SYN détecté depuis {pkt[IP].src}")

def detect_arp(pkt):
    if pkt[ARP].op == 1:  # ARP request
        sender = pkt[ARP].psrc
        arp_requests[sender] += 1
        if arp_requests[sender] > 5:  # seuil configurable
            print(f"[ALERTE] Requêtes ARP suspectes depuis {sender}")

def stop_sniffer(signal_received, frame):
    print("\n[INFO] Arrêt du sniffer proprement.")
    sys.exit(0)

def main():
    print("[INFO] Démarrage du sniffer... (CTRL+C pour arrêter)")
    signal.signal(signal.SIGINT, stop_sniffer)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
