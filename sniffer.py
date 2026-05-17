#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           Basic Network Sniffer                  ║
║           Cyber Security Internship - Task 1                 ║
║           Author: Faraz Aamir                                ║
╚══════════════════════════════════════════════════════════════╝

A Python-based network packet sniffer that captures and analyzes
network traffic in real-time. Built using Scapy library.

Features:
    - Captures live network packets
    - Displays source/destination IPs
    - Identifies protocols (TCP, UDP, ICMP, DNS, HTTP, etc.)
    - Shows payload data (if available)
    - Color-coded output for easy reading
    - Packet statistics summary
    - Option to save captured packets to a file

Usage:
    sudo python3 sniffer.py                  # Sniff on default interface
    sudo python3 sniffer.py -i eth0          # Sniff on specific interface
    sudo python3 sniffer.py -c 50            # Capture 50 packets
    sudo python3 sniffer.py -f "tcp"         # Filter TCP packets only
    sudo python3 sniffer.py -s capture.pcap  # Save packets to file
"""

import argparse
import sys
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, ARP, conf
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""


# ─────────────────────────────────────────────────────────────
# Global Statistics Tracker
# ─────────────────────────────────────────────────────────────
class PacketStats:
    """Track statistics of captured packets."""

    def __init__(self):
        self.total_packets = 0
        self.protocol_count = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.dest_ips = defaultdict(int)
        self.start_time = time.time()

    def update(self, protocol, src_ip, dst_ip):
        """Update statistics with a new packet."""
        self.total_packets += 1
        self.protocol_count[protocol] += 1
        self.source_ips[src_ip] += 1
        self.dest_ips[dst_ip] += 1

    def display_summary(self):
        """Display a summary of captured packet statistics."""
        elapsed = time.time() - self.start_time
        print("\n")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'═' * 62}")
        print(f"  📊  PACKET CAPTURE SUMMARY")
        print(f"{'═' * 62}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Total Packets Captured : {Fore.GREEN}{self.total_packets}")
        print(f"{Fore.WHITE}  Capture Duration       : {Fore.GREEN}{elapsed:.2f} seconds")
        print(f"{Fore.WHITE}  Packets/Second         : {Fore.GREEN}{self.total_packets / max(elapsed, 1):.2f}")

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}  Protocol Breakdown:")
        print(f"  {'─' * 40}")
        for proto, count in sorted(self.protocol_count.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(count, 30)
            print(f"  {Fore.WHITE}  {proto:<12} : {Fore.GREEN}{count:>5}  {Fore.CYAN}{bar}")

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}  Top 5 Source IPs:")
        print(f"  {'─' * 40}")
        for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Fore.WHITE}  {ip:<20} : {Fore.GREEN}{count} packets")

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}  Top 5 Destination IPs:")
        print(f"  {'─' * 40}")
        for ip, count in sorted(self.dest_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Fore.WHITE}  {ip:<20} : {Fore.GREEN}{count} packets")

        print(f"\n{Fore.CYAN}{'═' * 62}\n")


# Initialize global stats
stats = PacketStats()


# ─────────────────────────────────────────────────────────────
# Protocol Detection
# ─────────────────────────────────────────────────────────────
def get_protocol_name(packet):
    """Determine the protocol name of a packet."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if sport == 80 or dport == 80:
            return "HTTP"
        elif sport == 443 or dport == 443:
            return "HTTPS"
        elif sport == 22 or dport == 22:
            return "SSH"
        elif sport == 21 or dport == 21:
            return "FTP"
        elif sport == 25 or dport == 25:
            return "SMTP"
        return "TCP"
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if sport == 53 or dport == 53:
            return "DNS"
        elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
            return "DHCP"
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    return "OTHER"


def get_protocol_color(protocol):
    """Return color based on protocol type."""
    colors = {
        "TCP": Fore.BLUE,
        "UDP": Fore.MAGENTA,
        "HTTP": Fore.GREEN,
        "HTTPS": Fore.GREEN,
        "DNS": Fore.YELLOW,
        "ICMP": Fore.RED,
        "SSH": Fore.CYAN,
        "FTP": Fore.CYAN,
        "SMTP": Fore.CYAN,
        "DHCP": Fore.YELLOW,
        "ARP": Fore.RED,
    }
    return colors.get(protocol, Fore.WHITE)


# ─────────────────────────────────────────────────────────────
# Packet Processing
# ─────────────────────────────────────────────────────────────
def process_packet(packet):
    """Process and display information about a captured packet."""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            size = len(packet)
            protocol = get_protocol_name(packet)
            color = get_protocol_color(protocol)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Update statistics
            stats.update(protocol, src_ip, dst_ip)

            # ── Header Line ──
            print(f"\n{Fore.CYAN}┌─[{Fore.WHITE}Packet #{stats.total_packets}{Fore.CYAN}]──[{Fore.WHITE}{timestamp}{Fore.CYAN}]──[{color}{protocol}{Fore.CYAN}]")
            print(f"{Fore.CYAN}│")

            # ── Source & Destination ──
            print(f"{Fore.CYAN}│  {Fore.WHITE}Source      : {Fore.GREEN}{src_ip}")
            print(f"{Fore.CYAN}│  {Fore.WHITE}Destination : {Fore.RED}{dst_ip}")
            print(f"{Fore.CYAN}│  {Fore.WHITE}Protocol    : {color}{protocol}")
            print(f"{Fore.CYAN}│  {Fore.WHITE}Size        : {Fore.YELLOW}{size} bytes")
            print(f"{Fore.CYAN}│  {Fore.WHITE}TTL         : {Fore.YELLOW}{ttl}")

            # ── Port Information (TCP/UDP) ──
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                print(f"{Fore.CYAN}│  {Fore.WHITE}Src Port    : {Fore.MAGENTA}{src_port}")
                print(f"{Fore.CYAN}│  {Fore.WHITE}Dst Port    : {Fore.MAGENTA}{dst_port}")
                print(f"{Fore.CYAN}│  {Fore.WHITE}TCP Flags   : {Fore.YELLOW}{flags}")

            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"{Fore.CYAN}│  {Fore.WHITE}Src Port    : {Fore.MAGENTA}{src_port}")
                print(f"{Fore.CYAN}│  {Fore.WHITE}Dst Port    : {Fore.MAGENTA}{dst_port}")

            elif packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
                type_name = icmp_types.get(icmp_type, f"Type {icmp_type}")
                print(f"{Fore.CYAN}│  {Fore.WHITE}ICMP Type   : {Fore.YELLOW}{type_name} (code: {icmp_code})")

            # ── DNS Query ──
            if packet.haslayer(DNS) and packet[DNS].qd:
                dns_query = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
                print(f"{Fore.CYAN}│  {Fore.WHITE}DNS Query   : {Fore.YELLOW}{dns_query}")

            # ── Payload Data ──
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    payload_text = payload.decode("utf-8", errors="replace")[:100]
                    # Only show printable characters
                    printable = ''.join(c if c.isprintable() else '.' for c in payload_text)
                    if printable.strip('.'):
                        print(f"{Fore.CYAN}│  {Fore.WHITE}Payload     : {Fore.WHITE}{printable}")
                except Exception:
                    hex_data = payload[:50].hex()
                    print(f"{Fore.CYAN}│  {Fore.WHITE}Payload(hex): {Fore.WHITE}{hex_data}")

            print(f"{Fore.CYAN}└{'─' * 55}")

        elif packet.haslayer(ARP):
            # Handle ARP packets (no IP layer)
            stats.update("ARP", packet[ARP].psrc, packet[ARP].pdst)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            op = "Request" if packet[ARP].op == 1 else "Reply"
            print(f"\n{Fore.CYAN}┌─[{Fore.WHITE}Packet #{stats.total_packets}{Fore.CYAN}]──[{Fore.WHITE}{timestamp}{Fore.CYAN}]──[{Fore.RED}ARP {op}{Fore.CYAN}]")
            print(f"{Fore.CYAN}│  {Fore.WHITE}Sender : {Fore.GREEN}{packet[ARP].psrc} ({packet[ARP].hwsrc})")
            print(f"{Fore.CYAN}│  {Fore.WHITE}Target : {Fore.RED}{packet[ARP].pdst} ({packet[ARP].hwdst})")
            print(f"{Fore.CYAN}└{'─' * 55}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error processing packet: {e}")


# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────
def print_banner():
    """Display the application banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ░█▀▀░█▀█░▀█▀░█▀▀░█▀▀░█▀▀░█▀▄                    ║
    ║   ░▀▀█░█░█░░█░░█▀▀░█▀▀░█▀▀░█▀▄                    ║
    ║   ░▀▀▀░▀░▀░▀▀▀░▀░░░▀░░░▀▀▀░▀░▀                    ║
    ║                                                      ║
    ║   🔍 Basic Network Sniffer v1.0                      ║
    ║   👤 Author: Faraz Aamir                             ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


# ─────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────
def main():
    """Main function to run the network sniffer."""
    parser = argparse.ArgumentParser(
        description="Network Sniffer - Capture and analyze network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniffer.py                  Sniff on default interface
  sudo python3 sniffer.py -i eth0          Sniff on specific interface
  sudo python3 sniffer.py -c 50            Capture 50 packets
  sudo python3 sniffer.py -f "tcp"         Filter TCP packets only
  sudo python3 sniffer.py -f "udp port 53" Filter DNS traffic
  sudo python3 sniffer.py -s capture.pcap  Save packets to file
        """
    )

    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", type=str, default=None,
                        help="BPF filter expression (e.g., 'tcp', 'udp port 53')")
    parser.add_argument("-s", "--save", type=str, default=None,
                        help="Save captured packets to a .pcap file")

    args = parser.parse_args()

    # Print the banner
    print_banner()

    # Display configuration
    print(f"{Fore.YELLOW}{Style.BRIGHT}  ⚙️  Configuration:")
    print(f"  {'─' * 45}")
    print(f"{Fore.WHITE}  Interface  : {Fore.GREEN}{args.interface or 'Default (all)'}")
    print(f"{Fore.WHITE}  Filter     : {Fore.GREEN}{args.filter or 'None (capture all)'}")
    print(f"{Fore.WHITE}  Count      : {Fore.GREEN}{args.count if args.count > 0 else 'Unlimited'}")
    print(f"{Fore.WHITE}  Save to    : {Fore.GREEN}{args.save or 'Not saving'}")
    print(f"\n{Fore.CYAN}  🚀 Starting packet capture... Press {Fore.RED}Ctrl+C{Fore.CYAN} to stop.\n")
    print(f"{Fore.CYAN}{'═' * 62}\n")

    # Build sniff kwargs
    sniff_kwargs = {
        "prn": process_packet,
        "store": True if args.save else False,
    }

    if args.interface:
        sniff_kwargs["iface"] = args.interface
    if args.count > 0:
        sniff_kwargs["count"] = args.count
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    try:
        # Start sniffing
        captured_packets = sniff(**sniff_kwargs)

        # Save to file if requested
        if args.save and captured_packets:
            from scapy.utils import wrpcap
            wrpcap(args.save, captured_packets)
            print(f"\n{Fore.GREEN}[✓] Packets saved to: {args.save}")

    except PermissionError:
        print(f"\n{Fore.RED}[✗] Permission denied! Please run with sudo:")
        print(f"{Fore.YELLOW}    sudo python3 sniffer.py")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Error: {e}")
        sys.exit(1)
    finally:
        # Always show statistics
        stats.display_summary()


if __name__ == "__main__":
    main()
