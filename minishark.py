#!/usr/bin/env python3
"""
MiniShark - A CLI-based network analysis tool similar to tshark
Author: Open Source Community
License: MIT
"""

import argparse
import sys
import json
import csv
import time
import signal
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTP
except ImportError:
    print("Error: Required packages not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import init, Fore, Back, Style
    from tabulate import tabulate
except ImportError:
    print("Error: Required packages not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init()

class MiniShark:
    def __init__(self):
        self.packets = []
        self.running = False
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'source_ips': {},
            'dest_ips': {},
            'ports': {}
        }
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}Stopping packet capture...{Style.RESET_ALL}")
        self.running = False

    def get_protocol_name(self, packet) -> str:
        """Extract protocol name from packet"""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(HTTP):
            return "HTTP"
        else:
            return "Other"

    def get_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from a packet"""
        # Use UTC to avoid timezone issues
        timestamp = datetime.utcfromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        info = {
            'timestamp': timestamp,
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'protocol': self.get_protocol_name(packet),
            'length': len(packet),
            'flags': 'N/A',
            'info': 'N/A'
        }

        # Extract IP information
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst

        # Extract port information
        if packet.haslayer(TCP):
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = packet[TCP].flags
            info['info'] = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            info['info'] = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            info['info'] = f"ICMP type {packet[ICMP].type} code {packet[ICMP].code}"

        return info

    def update_stats(self, packet_info: Dict[str, Any]):
        """Update statistics"""
        self.stats['total_packets'] += 1
        
        # Protocol stats
        protocol = packet_info['protocol']
        self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
        
        # IP stats
        if packet_info['src_ip'] != 'N/A':
            self.stats['source_ips'][packet_info['src_ip']] = self.stats['source_ips'].get(packet_info['src_ip'], 0) + 1
        if packet_info['dst_ip'] != 'N/A':
            self.stats['dest_ips'][packet_info['dst_ip']] = self.stats['dest_ips'].get(packet_info['dst_ip'], 0) + 1
        
        # Port stats
        if packet_info['src_port'] != 'N/A':
            self.stats['ports'][packet_info['src_port']] = self.stats['ports'].get(packet_info['src_port'], 0) + 1
        if packet_info['dst_port'] != 'N/A':
            self.stats['ports'][packet_info['dst_port']] = self.stats['ports'].get(packet_info['dst_port'], 0) + 1

    def packet_callback(self, packet):
        """Callback function for packet capture"""
        if not self.running:
            return False
        
        try:
            packet_info = self.get_packet_info(packet)
            self.packets.append(packet_info)
            self.update_stats(packet_info)
            
            # Print packet info in real-time
            self.print_packet(packet_info)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
        
        return True

    def print_packet(self, packet_info: Dict[str, Any]):
        """Print packet information in a formatted way"""
        timestamp = packet_info['timestamp']
        src = f"{packet_info['src_ip']}:{packet_info['src_port']}"
        dst = f"{packet_info['dst_ip']}:{packet_info['dst_port']}"
        protocol = packet_info['protocol']
        length = packet_info['length']
        info = packet_info['info']
        
        # Color coding based on protocol
        if protocol == "TCP":
            color = Fore.GREEN
        elif protocol == "UDP":
            color = Fore.BLUE
        elif protocol == "ICMP":
            color = Fore.RED
        else:
            color = Fore.WHITE
        
        print(f"{color}{timestamp} {src:>20} -> {dst:<20} {protocol:>4} {length:>6} {info}{Style.RESET_ALL}")

    def capture_packets(self, interface: str = None, count: int = 0, filter_str: str = None):
        """Start packet capture"""
        self.running = True
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"{Fore.CYAN}Starting packet capture...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Press Ctrl+C to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        try:
            sniff(
                iface=interface,
                prn=self.packet_callback,
                count=count if count > 0 else 0,
                filter=filter_str,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
        finally:
            self.running = False

    def print_stats(self):
        """Print capture statistics"""
        print(f"\n{Fore.CYAN}{'='*50} STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Packets Captured: {self.stats['total_packets']}{Style.RESET_ALL}")
        
        if self.stats['protocols']:
            print(f"\n{Fore.YELLOW}Protocols:{Style.RESET_ALL}")
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {protocol}: {count}")
        
        if self.stats['source_ips']:
            print(f"\n{Fore.YELLOW}Top Source IPs:{Style.RESET_ALL}")
            for ip, count in sorted(self.stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ip}: {count}")
        
        if self.stats['dest_ips']:
            print(f"\n{Fore.YELLOW}Top Destination IPs:{Style.RESET_ALL}")
            for ip, count in sorted(self.stats['dest_ips'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ip}: {count}")

    def save_to_file(self, filename: str, format: str = 'json'):
        """Save captured packets to file"""
        if not self.packets:
            print(f"{Fore.RED}No packets to save{Style.RESET_ALL}")
            return
        
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(self.packets, f, indent=2)
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='') as f:
                    if self.packets:  # Additional safety check
                        writer = csv.DictWriter(f, fieldnames=self.packets[0].keys())
                        writer.writeheader()
                        writer.writerows(self.packets)
                    else:
                        # Create empty CSV with headers if no packets
                        writer = csv.DictWriter(f, fieldnames=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length', 'flags', 'info'])
                        writer.writeheader()
            else:
                print(f"{Fore.RED}Unsupported format: {format}{Style.RESET_ALL}")
                return
            
            print(f"{Fore.GREEN}Packets saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error saving to file: {e}")

    def list_interfaces(self):
        """List available network interfaces"""
        interfaces = get_if_list()
        print(f"{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
        for i, interface in enumerate(interfaces, 1):
            print(f"  {i}. {interface}")

def main():
    parser = argparse.ArgumentParser(
        description="MiniShark - A CLI-based network analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python minishark.py -i eth0                    # Capture on eth0 interface
  python minishark.py -c 100                    # Capture 100 packets
  python minishark.py -f "tcp port 80"          # Filter TCP port 80
  python minishark.py -o output.json -f json    # Save to JSON file
  python minishark.py --interfaces              # List available interfaces
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-f', '--filter', help='BPF filter expression')
    parser.add_argument('-o', '--output', help='Output file to save packets')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('--interfaces', action='store_true', help='List available network interfaces')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create MiniShark instance
    minishark = MiniShark()
    
    # List interfaces if requested
    if args.interfaces:
        minishark.list_interfaces()
        return
    
    # Start packet capture
    try:
        minishark.capture_packets(
            interface=args.interface,
            count=args.count,
            filter_str=args.filter
        )
        
        # Print statistics
        minishark.print_stats()
        
        # Save to file if requested
        if args.output:
            minishark.save_to_file(args.output, args.format)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Capture interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()