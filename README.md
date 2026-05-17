# 🔍 Basic Network Sniffer


A Python-based network packet sniffer that captures and analyzes network traffic in real-time. Built using the **Scapy** library, this tool provides detailed insights into network packets flowing through your system.

---

## ✨ Features

- 📡 **Real-time Packet Capture** — Sniff packets on any network interface
- 🏷️ **Protocol Detection** — Identifies TCP, UDP, ICMP, DNS, HTTP, HTTPS, SSH, FTP, SMTP, DHCP, ARP
- 🎨 **Color-Coded Output** — Easy-to-read terminal output with distinct colors per protocol
- 📊 **Live Statistics** — Tracks packet counts, protocol breakdown, and top IPs
- 🔎 **Payload Inspection** — Shows packet payload data (ASCII & hex)
- 🎯 **BPF Filters** — Apply Berkeley Packet Filters to capture specific traffic
- 💾 **PCAP Export** — Save captured packets to `.pcap` files for analysis in Wireshark

---

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- Root/sudo privileges (required for packet capturing)

### Setup
```bash
# Clone or navigate to the project directory
cd task1_network_sniffer

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

> ⚠️ **Note:** Packet sniffing requires root/sudo privileges.

### Basic Usage
```bash
# Capture packets on default interface (unlimited)
sudo python3 sniffer.py

# Capture on a specific interface
sudo python3 sniffer.py -i eth0

# Capture exactly 50 packets
sudo python3 sniffer.py -c 50

# Filter only TCP packets
sudo python3 sniffer.py -f "tcp"

# Filter DNS traffic
sudo python3 sniffer.py -f "udp port 53"

# Save captured packets to a file
sudo python3 sniffer.py -s capture.pcap

# Combine options
sudo python3 sniffer.py -i wlan0 -c 100 -f "tcp" -s output.pcap
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-i`, `--interface` | Network interface to sniff on | All interfaces |
| `-c`, `--count` | Number of packets to capture | Unlimited |
| `-f`, `--filter` | BPF filter expression | None (all traffic) |
| `-s`, `--save` | Save packets to .pcap file | Not saving |

---

## 📸 Sample Output

```
┌─[Packet #1]──[14:23:45.123]──[HTTP]
│
│  Source      : 192.168.1.100
│  Destination : 93.184.216.34
│  Protocol    : HTTP
│  Size        : 342 bytes
│  TTL         : 64
│  Src Port    : 52431
│  Dst Port    : 80
│  TCP Flags   : PA
│  Payload     : GET /index.html HTTP/1.1...
└───────────────────────────────────────────────────────

┌─[Packet #2]──[14:23:45.456]──[DNS]
│
│  Source      : 192.168.1.100
│  Destination : 8.8.8.8
│  Protocol    : DNS
│  Size        : 76 bytes
│  TTL         : 64
│  Src Port    : 43210
│  Dst Port    : 53
│  DNS Query   : www.example.com.
└───────────────────────────────────────────────────────
```

---

## 📊 Statistics Summary

After stopping the capture (Ctrl+C), a summary is displayed:

```
══════════════════════════════════════════════════════════════
  📊  PACKET CAPTURE SUMMARY
══════════════════════════════════════════════════════════════
  Total Packets Captured : 127
  Capture Duration       : 45.23 seconds
  Packets/Second         : 2.81

  Protocol Breakdown:
  ────────────────────────────────────────
    TCP          :    67  ██████████████████████
    UDP          :    34  ███████████
    DNS          :    15  █████
    ICMP         :     8  ██
    ARP          :     3  █

  Top 5 Source IPs:
  ────────────────────────────────────────
    192.168.1.100        : 89 packets
    10.0.0.1             : 23 packets
    ...
══════════════════════════════════════════════════════════════
```

---

## 📚 How It Works

1. **Packet Capture**: Uses Scapy's `sniff()` function to capture raw network packets
2. **Protocol Analysis**: Each packet is inspected layer-by-layer to determine its protocol
3. **Data Extraction**: Source/destination IPs, ports, flags, and payloads are extracted
4. **Display**: Information is formatted with colors and displayed in real-time
5. **Statistics**: A running count of protocols and IPs is maintained and shown at the end

---

## 🔒 Ethical Disclaimer

This tool is built for **educational purposes**. Network sniffing should only be performed on:
- Networks you own
- Networks you have explicit permission to monitor

Unauthorized packet sniffing is illegal and unethical.

---

## 👤 Author

**Faraz Aamir**  

---

## 📄 License

This project is for educational purposes.
# Basic_Network_Sniffer
