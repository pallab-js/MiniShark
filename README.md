# MiniShark

A lightweight CLI-based network analysis tool similar to tshark, built with Python3. MiniShark provides real-time packet capture, filtering, and analysis capabilities for network troubleshooting and monitoring.

## Features

### Core Features
- **Real-time Packet Capture**: Capture packets from any network interface
- **Offline PCAP Analysis**: Read and analyze pcap/pcapng files
- **Protocol Support**: TCP, UDP, ICMP, DNS, HTTP, TLS, QUIC, IPv6, ARP, VLAN
- **BPF Filtering**: Berkeley Packet Filter support with validation
- **Multiple Output Formats**: JSON, CSV, JSON Lines, PDML

### Advanced Features
- **TCP Stream Reassembly**: Reassemble and follow TCP streams
- **Protocol Hierarchy Statistics**: `-z phs` for protocol distribution
- **Conversation Tracking**: `-z conv` for IP conversations
- **Field Extraction**: `-T fields -e` for custom column output

### Performance
- **Multi-threaded Processing**: Fast processing of large capture files
- **Chunked Reading**: Memory-efficient processing of huge files
- **Quiet Mode**: `-q` to reduce console overhead
- **Configurable Buffer Size**: `-B` for kernel buffer tuning

### Protocol Enhancements
- Human-readable TCP flags (SYN, ACK, FIN, RST, etc.)
- MAC address extraction
- VLAN tag parsing
- HTTP method/URI/host extraction
- DNS query/response parsing
- TLS/QUIC port detection

## Installation

### Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (for packet capture)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/minishark.git
cd minishark

# Install dependencies
pip install -r requirements.txt

# Make the script executable (Unix/Linux/macOS)
chmod +x minishark.py
```

### Dependencies

- `scapy` - Packet manipulation and capture
- `colorama` - Cross-platform colored terminal output
- `tabulate` - Pretty-printed tables

## Usage

### Basic Usage

```bash
python minishark.py

# Capture on specific interface
python minishark.py -i eth0

# Capture specific number of packets
python minishark.py -c 100

# Apply BPF filter
python minishark.py -f "tcp port 80"

# Save output to file
python minishark.py -o capture.json --format json
```

### Command Line Options

```
usage: minishark.py [-h] [-i INTERFACE] [-r READ_FILE] [-c COUNT] [-f FILTER]
                    [-o OUTPUT] [-F {json,csv,jsonlines,pdml}]
                    [-T {json,csv,fields,pdml}] [-e FIELD] [--interfaces] [-v]
                    [-z STATISTICS] [-n] [-nn] [-q] [-s SNAPLEN]
                    [-B BUFFER_SIZE] [--promiscuous] [-w WRITE]

MiniShark - A CLI-based network analysis tool similar to tshark

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE          Network interface to capture on
  -r READ_FILE          Read packets from pcap/pcapng file
  -c COUNT              Number of packets to capture (0 = unlimited)
  -f FILTER             BPF filter expression
  -o OUTPUT             Output file to save packets
  -F {json,csv,jsonlines,pdml}  Output format (default: json)
  -T {json,csv,fields,pdml}     Output type for -o
  -e FIELD              Fields to export with -T fields (can be repeated)
  --interfaces          List available network interfaces
  -v, --verbose         Enable verbose logging
  -z STATISTICS         Show statistics: phs (protocol hierarchy), conv (conversations)
  -n, --no-name-resolution      Disable name resolution
  -nn, --no-any-resolution     Disable all name resolution
  -q, --quiet         Quiet mode - minimal output
  -s SNAPLEN           Snapshot length (default: 65535)
  -B BUFFER_SIZE       Kernel buffer size in KB
  --promiscuous        Put interface in promiscuous mode
  -w WRITE             Write captured packets to file
```

### Examples

#### 1. Basic Packet Capture
```bash
python minishark.py
```

#### 2. Capture HTTP Traffic
```bash
python minishark.py -f "tcp port 80"
```

#### 3. Capture Specific Host
```bash
python minishark.py -f "host 192.168.1.100"
```

#### 4. Save to File
```bash
python minishark.py -c 1000 -o traffic.json -F json

# Save to CSV format
python minishark.py -c 500 -o traffic.csv -F csv
```

#### 5. List Available Interfaces
```bash
python minishark.py --interfaces
```

#### 6. Advanced Filtering
```bash
python minishark.py -f "udp port 53"
python minishark.py -f "icmp"
python minishark.py -f "net 192.168.1.0/24"
```

#### 7. Offline PCAP Analysis
```bash
python minishark.py -r capture.pcap
python minishark.py -r capture.pcap -c 100
python minishark.py -r capture.pcap -f "tcp port 80"
```

#### 8. Protocol Hierarchy Statistics
```bash
python minishark.py -r capture.pcap -z phs
```

#### 9. Conversation Tracking
```bash
python minishark.py -r capture.pcap -z conv
```

#### 10. Field Extraction
```bash
python minishark.py -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port -e http.request.uri
python minishark.py -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e protocol -e info
```

#### 11. JSON Lines Export (for large files)
```bash
python minishark.py -r capture.pcap -o output.jsonl -F jsonlines
```

#### 12. Quiet Mode (for scripting)
```bash
python minishark.py -r capture.pcap -q -o output.json
```

#### 13. Performance Tuning
```bash
python minishark.py -r large_capture.pcap -B 4096 -s 65535
```

## Output Format

### Real-time Console Output
```
2024-01-15 10:30:15.123   192.168.1.100:54321 -> 8.8.8.8:53        UDP    512 DNS query
2024-01-15 10:30:15.124   8.8.8.8:53 -> 192.168.1.100:54321        UDP    128 DNS response
2024-01-15 10:30:15.125   192.168.1.100:443 -> 142.250.191.14:443  TCP   1024 HTTPS
```

### JSON Output
```json
[
  {
    "timestamp": "2024-01-15 10:30:15.123",
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP",
    "length": 512,
    "flags": "N/A",
    "info": "UDP 54321 -> 53"
  }
]
```

### Statistics Output
```
====================================== STATISTICS ======================================
Total Packets Captured: 1250

Protocols (packets):
  TCP              850 (68.0%)
  UDP              300 (24.0%)
  ICMP             100 ( 8.0%)

Top Source IPs:
  192.168.1.100: 500
  192.168.1.1: 200
  10.0.0.1: 150

Top Destination IPs:
  8.8.8.8: 300
  142.250.191.14: 200
  192.168.1.1: 150
```

### Protocol Hierarchy Output
```
====================================== PROTOCOL HIERARCHY ================================
Protocols (packets):
  TCP              850 (68.0%)
  UDP              300 (24.0%)
  ICMP             100 ( 8.0%)
  TLS              120
  DNS               80
  HTTP             150
```

## BPF Filter Examples

MiniShark supports Berkeley Packet Filter (BPF) syntax for advanced filtering:

- `tcp port 80` - TCP traffic on port 80
- `udp port 53` - DNS traffic
- `host 192.168.1.1` - Traffic to/from specific host
- `net 192.168.1.0/24` - Traffic to/from subnet
- `tcp and port 443` - HTTPS traffic
- `icmp` - ICMP packets only
- `tcp[tcpflags] & (tcp-syn|tcp-fin) != 0` - TCP SYN or FIN flags

## Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows
- **Privileges**: Root/Administrator access for packet capture
- **Memory**: Minimal (typically < 50MB)
- **CPU**: Low impact, suitable for average PCs

## Quick Reference

### Common Commands
```bash
# Basic capture
python minishark.py -i eth0 -c 100

# Offline analysis with statistics
python minishark.py -r capture.pcap -z phs,conv,io

# Export with specific format
python minishark.py -r capture.pcap -o output.json -F json
python minishark.py -r capture.pcap -o data.parquet -F parquet
python minishark.py -r capture.pcap -o data.xlsx -F excel

# Security features
python minishark.py -r capture.pcap --yara rules.yar
python minishark.py -r capture.pcap --threat

# Forensics
python minishark.py -r capture.pcap --carve --carve-dir ./carved
python minishark.py -r capture.pcap --dedup

# Performance tuning
python minishark.py -r large.pcap --max-memory 512 --packet-buffer-size 50000
```

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| MINISHARK_BUFFER_SIZE | Packet buffer size | 10000 |
| MINISHARK_MAX_MEMORY | Max memory in MB | 1024 |
| MINISHARK_NO_COLOR | Disable colors | false |

## Troubleshooting

### Permission Issues
```bash
# On Linux/macOS, run with sudo
sudo python minishark.py

# On Windows, run Command Prompt as Administrator
python minishark.py
```

### Interface Not Found
```bash
# List available interfaces
python minishark.py --interfaces

# Use specific interface
python minishark.py -i wlan0
```

### No Packets Captured
- Check if the interface is active
- Verify network connectivity
- Try different interface: `python minishark.py --interfaces`
- Check firewall settings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Scapy](https://scapy.net/) - The Python packet manipulation library
- Inspired by [Wireshark](https://www.wireshark.org/) and tshark
- Uses [Colorama](https://github.com/tartley/colorama) for cross-platform colored output

## Disclaimer

This tool is for educational and legitimate network analysis purposes only. Users are responsible for complying with applicable laws and regulations when using this tool. Always ensure you have proper authorization before capturing network traffic.