# MiniShark

A lightweight CLI-based network analysis tool similar to tshark, built with Python3. MiniShark provides real-time packet capture, filtering, and analysis capabilities for network troubleshooting and monitoring.

## Features

- **Real-time Packet Capture**: Capture packets from any network interface
- **Protocol Support**: TCP, UDP, ICMP, DNS, HTTP, and more
- **BPF Filtering**: Berkeley Packet Filter support for advanced filtering
- **Multiple Output Formats**: JSON, CSV, and real-time console output
- **Statistics**: Comprehensive packet statistics and analysis
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Lightweight**: Minimal dependencies, runs on any average PC
- **Color-coded Output**: Easy-to-read colored console output

## Installation

### Prerequisites

- Python 3.6 or higher
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
# Capture packets on default interface
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
usage: minishark.py [-h] [-i INTERFACE] [-c COUNT] [-f FILTER] [-o OUTPUT]
                   [--format {json,csv}] [--interfaces] [-v]

MiniShark - A CLI-based network analysis tool

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to capture on
  -c COUNT, --count COUNT
                        Number of packets to capture (0 = unlimited)
  -f FILTER, --filter FILTER
                        BPF filter expression
  -o OUTPUT, --output OUTPUT
                        Output file to save packets
  --format {json,csv}   Output format (default: json)
  --interfaces          List available network interfaces
  -v, --verbose         Enable verbose logging
```

### Examples

#### 1. Basic Packet Capture
```bash
# Capture all packets on default interface
python minishark.py
```

#### 2. Capture HTTP Traffic
```bash
# Capture only HTTP traffic (port 80)
python minishark.py -f "tcp port 80"
```

#### 3. Capture Specific Host
```bash
# Capture traffic to/from specific IP
python minishark.py -f "host 192.168.1.100"
```

#### 4. Save to File
```bash
# Capture 1000 packets and save to JSON
python minishark.py -c 1000 -o traffic.json --format json

# Save to CSV format
python minishark.py -c 500 -o traffic.csv --format csv
```

#### 5. List Available Interfaces
```bash
# Show all available network interfaces
python minishark.py --interfaces
```

#### 6. Advanced Filtering
```bash
# Capture DNS queries
python minishark.py -f "udp port 53"

# Capture ICMP packets
python minishark.py -f "icmp"

# Capture traffic between specific subnets
python minishark.py -f "net 192.168.1.0/24"
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
================================================== STATISTICS ==================================================
Total Packets Captured: 1250

Protocols:
  TCP: 850
  UDP: 300
  ICMP: 100

Top Source IPs:
  192.168.1.100: 500
  192.168.1.1: 200
  10.0.0.1: 150

Top Destination IPs:
  8.8.8.8: 300
  142.250.191.14: 200
  192.168.1.1: 150
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

- **Python**: 3.6 or higher
- **Operating System**: Linux, macOS, or Windows
- **Privileges**: Root/Administrator access for packet capture
- **Memory**: Minimal (typically < 50MB)
- **CPU**: Low impact, suitable for average PCs

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