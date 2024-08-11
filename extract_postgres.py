from scapy.all import *
import sys

def main(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        sys.exit(1)

    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.dport == 5432 or tcp_layer.sport == 5432:
                ip_layer = packet.getlayer(IP)
                print(f"Captured a PostgreSQL packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
                print(f"Payload: {bytes(tcp_layer.payload)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
