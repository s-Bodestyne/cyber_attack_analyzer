from scapy.all import rdpcap
from collections import Counter

def analyze_packets(pcap_file):
    # Read the packet capture file
    packets = rdpcap(pcap_file)

    # Count the number of packets by protocol
    protocols = [packet.sprintf("%IP.proto%") for packet in packets if packet.haslayer("IP")]
    protocol_count = Counter(protocols)

    # Count the source IP addresses
    src_ips = [packet.sprintf("%IP.src%") for packet in packets if packet.haslayer("IP")]
    src_ip_count = Counter(src_ips)

    print(f"\n=== Packet Analysis Results ===")
    print(f"Total Packets: {len(packets)}")
    print("\nProtocols detected:")
    for proto, count in protocol_count.items():
        print(f"{proto}: {count} packets")

    print("\nTop Source IPs:")
    for ip, count in src_ip_count.most_common(5):
        print(f"{ip}: {count} packets")

if __name__ == "__main__":
    pcap_file = input("Enter the path to your .pcap file: ")
    analyze_packets(pcap_file)
