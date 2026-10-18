# Packet Sniffer

A lightweight network packet sniffer built with **Python** and **Scapy**. It captures live traffic, classifies packets as **TCP, UDP or ICMP**, shows source/destination IPs in real time, and logs the timestamp and size of every packet to a CSV file for traffic-pattern review.

## Features

- Live packet capture with Scapy (IPv4 and IPv6)
- Protocol classification: TCP, UDP, ICMP
- Real-time display of source and destination IP:port
- CSV logging of timestamp, protocol, endpoints and packet size
- Simple port-scan detection (alerts when one source hits many ports in a short window)
- End-of-capture summary with packet counts, percentages and total bytes
- Optional interface selection, packet count limit and BPF filters

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- **Windows:** [Npcap](https://npcap.com) installed
- Administrator / root privileges (required for packet capture)

## Installation

```bash
git clone https://github.com/<your-username>/packet-sniffer.git
cd packet-sniffer
pip install -r requirements.txt
```

## Usage

Run from an Administrator terminal (Windows) or with `sudo` (Linux/macOS):

```bash
python packet_sniffer.py                        # capture until Ctrl+C
python packet_sniffer.py -c 100                 # stop after 100 packets
python packet_sniffer.py -i "Wi-Fi" -o log.csv  # choose interface and log file
python packet_sniffer.py -f "tcp port 443"      # apply a BPF filter
```

| Option | Description |
|---|---|
| `-i`, `--iface` | Interface to sniff on (default: auto) |
| `-c`, `--count` | Number of packets to capture (0 = until Ctrl+C) |
| `-f`, `--filter` | BPF filter, e.g. `port 53`, `host 192.168.1.5` |
| `-o`, `--output` | CSV log file (default: `packet_log.csv`) |

## Example output

```
[2026-10-18 11:58:10.250] TCP  140.82.114.22:443 -> 192.168.1.9:49677  (78 bytes)
[2026-10-18 12:01:44.512] ICMP 192.168.1.9:- -> 142.250.183.174:-  (74 bytes)
[2026-10-18 12:01:51.903] UDP  192.168.1.9:60211 -> 192.168.1.1:53  (73 bytes)
```

CSV log format:

```
timestamp,protocol,src_ip,src_port,dst_ip,dst_port,size_bytes
```

## How it works

1. `sniff()` passes each captured packet to a handler.
2. The handler checks for TCP, UDP or ICMP layers and extracts the IPs and ports.
3. Each packet is printed, written to the CSV and counted.
4. For TCP/UDP, the handler tracks how many distinct destination ports each source contacts within a 10-second window, and raises an alert at 15 or more.

## Testing

With the sniffer running, generate traffic in another terminal:

```bash
ping google.com          # ICMP
nslookup example.com     # UDP (DNS)
curl https://example.com # TCP
```

## Future improvements

- Charts of traffic over time from the CSV (matplotlib)
- Top-talkers summary
- DNS query logging
- Reading from `.pcap` files for offline analysis

## Disclaimer

For educational use only. Capture traffic only on networks you own or have explicit permission to monitor.
