#!/usr/bin/env python3
"""
Packet Sniffer - captures live traffic, classifies TCP / UDP / ICMP,
prints source -> destination in real time, and logs every packet
(timestamp + size) to a CSV file for later traffic-pattern review.

Usage (needs admin/root):
    sudo python3 packet_sniffer.py
    sudo python3 packet_sniffer.py -i eth0 -c 200 -o capture.csv
    sudo python3 packet_sniffer.py -f "port 80"

Only capture traffic on networks you own or have permission to monitor.
"""

import argparse
import csv
import time
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

# --- Config for the simple port-scan heuristic -----------------------------
SCAN_WINDOW_SECONDS = 10     # look at the last N seconds
SCAN_PORT_THRESHOLD = 15     # distinct dest ports from one source => alert

# --- State ------------------------------------------------------------------
protocol_counts = Counter()
total_bytes = 0
port_activity = defaultdict(list)   # src_ip -> [(timestamp, dst_port), ...]
alerted_sources = set()


def classify(packet):
    """Return (protocol_name, src_port, dst_port) or None if not TCP/UDP/ICMP."""
    if packet.haslayer(TCP):
        return "TCP", packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return "UDP", packet[UDP].sport, packet[UDP].dport
    if packet.haslayer(ICMP):
        return "ICMP", "-", "-"
    return None


def get_ips(packet):
    """Return (src_ip, dst_ip) for IPv4 or IPv6 packets, else None."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return None


def check_port_scan(src_ip, dst_port, now):
    """Flag a source that hits many different ports in a short window."""
    if dst_port == "-" or src_ip in alerted_sources:
        return
    hits = port_activity[src_ip]
    hits.append((now, dst_port))
    # drop entries outside the window
    port_activity[src_ip] = hits = [h for h in hits if now - h[0] <= SCAN_WINDOW_SECONDS]
    distinct_ports = {port for _, port in hits}
    if len(distinct_ports) >= SCAN_PORT_THRESHOLD:
        alerted_sources.add(src_ip)
        print(f"\n[!] ALERT: possible port scan from {src_ip} "
              f"({len(distinct_ports)} ports in {SCAN_WINDOW_SECONDS}s)\n")


def make_handler(writer, csv_file):
    def handle(packet):
        global total_bytes

        result = classify(packet)
        ips = get_ips(packet)
        if result is None or ips is None:
            return

        proto, sport, dport = result
        src_ip, dst_ip = ips
        size = len(packet)
        now = time.time()
        timestamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Stats
        protocol_counts[proto] += 1
        total_bytes += size

        # Real-time display
        print(f"[{timestamp}] {proto:<4} {src_ip}:{sport} -> {dst_ip}:{dport}  ({size} bytes)")

        # Log to CSV
        writer.writerow([timestamp, proto, src_ip, sport, dst_ip, dport, size])
        csv_file.flush()

        # Suspicious-traffic heuristic
        if proto in ("TCP", "UDP"):
            check_port_scan(src_ip, dport, now)

    return handle


def print_summary():
    total = sum(protocol_counts.values())
    print("\n" + "=" * 50)
    print("Capture summary")
    print("=" * 50)
    print(f"Total packets : {total}")
    print(f"Total bytes   : {total_bytes}")
    for proto in ("TCP", "UDP", "ICMP"):
        count = protocol_counts[proto]
        pct = (count / total * 100) if total else 0
        print(f"  {proto:<5}: {count:>6}  ({pct:.1f}%)")
    if alerted_sources:
        print(f"Flagged sources: {', '.join(sorted(alerted_sources))}")


def main():
    parser = argparse.ArgumentParser(description="Simple Scapy packet sniffer")
    parser.add_argument("-i", "--iface", help="interface to sniff on (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp", "port 53", "host 192.168.1.5"')
    parser.add_argument("-o", "--output", default="packet_log.csv",
                        help="CSV log file (default: packet_log.csv)")
    args = parser.parse_args()

    print(f"[*] Sniffing on {args.iface or 'default interface'} "
          f"| filter: {args.filter or 'none'} | log: {args.output}")
    print("[*] Press Ctrl+C to stop.\n")

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "protocol", "src_ip", "src_port",
                         "dst_ip", "dst_port", "size_bytes"])
        try:
            sniff(
                iface=args.iface,
                filter=args.filter or None,
                prn=make_handler(writer, f),
                count=args.count,
                store=False,          # don't keep packets in memory
            )
        except PermissionError:
            print("[-] Permission denied. Run with sudo / as Administrator.")
            return
        except KeyboardInterrupt:
            pass

    print_summary()
    print(f"\n[*] Log saved to {args.output}")


if __name__ == "__main__":
    main()
