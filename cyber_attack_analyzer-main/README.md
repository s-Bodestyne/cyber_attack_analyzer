# Cyber Attack Analyzer

A Python tool that analyzes packet captures (`.pcap` files) to detect potential cyber threats. This tool helps identify common protocols and top source IP addresses based on network traffic. It can also capture live packets for real-time analysis (with `Npcap` installed on Windows).

## Features
- **Analyze `.pcap` Files**: Easily analyze network traffic from packet captures.
- **Protocol Detection**: Shows a breakdown of different protocols found in the network traffic.
- **Top Source IPs**: Displays the most frequent source IP addresses in the packet capture.
- **Live Traffic Sniffing**: Capture live network traffic (requires `Npcap`).

## Installation

1. **Clone the repository**:
   Open your terminal (or Command Prompt on Windows) and run the following:
   git clone https://github.com/itsmevenusz/cyber_attack_analyzer.git 
   cd cyber_attack_analyzer

2. Install dependencies: Make sure you have Python installed. Then install the required library:
    pip install scapy
   
3. Optional (for live packet sniffing on Windows):
    Download and install Npcap from Npcap's official website.
    During installation, ensure that you check the option "Install Npcap in WinPcap API-compatible mode."

## Example Output:

=== Packet Analysis Results ===
Total Packets: 691

Protocols detected:
udp: 542 packets
tcp: 55 packets
170: 6 packets

Top Source IPs:
192.168.1.2: 428 packets
192.168.1.1: 49 packets
212.242.33.35: 30 packets

To sniff live traffic:
  1. Make sure Npcap is installed on your Windows machine.
  2. Run the tool and choose the live sniffing option:
    python analyzer.py

  3. Select the option to sniff live traffic. The tool will capture and display a summary of the first 10 packets.

## Future Enhancements

Suspicious IP Detection: Compare captured IPs with a list of known malicious IPs to flag potential threats.
Anomaly Detection: Add functionality to detect unusual packet patterns or unexpected protocols.
Packet Visualizations: Use Matplotlib to visualize traffic (e.g., packet distribution by protocol or source IP).

## Technologies Used

Python
Scapy: For packet manipulation and analysis.
Npcap: For live packet capturing (on Windows).

If you'd like to contribute to the project or suggest improvements, 
feel free to fork this repository and create a pull request. 
Contributions are always welcome!
