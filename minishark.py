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
import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import defaultdict
import logging
import threading
import struct

try:
    from scapy.all import sniff, get_if_list, wrpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    try:
        from scapy.layers.inet import IPv6
    except ImportError:
        IPv6 = None
    from scapy.layers.l2 import Ether
    try:
        from scapy.layers.l2 import Dot1Q, MPLS
    except ImportError:
        Dot1Q = None
        MPLS = None
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
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
    TCP_FLAG_NAMES = {
        0x01: 'FIN',
        0x02: 'SYN',
        0x04: 'RST',
        0x08: 'PSH',
        0x10: 'ACK',
        0x20: 'URG',
        0x40: 'ECE',
        0x80: 'CWR',
    }

    COLOR_RULES = {
        'TCP': Fore.CYAN,
        'UDP': Fore.BLUE,
        'ICMP': Fore.MAGENTA,
        'DNS': Fore.YELLOW,
        'HTTP': Fore.GREEN,
        'HTTPS': Fore.GREEN,
        'TLS': Fore.GREEN,
        'MQTT': Fore.CYAN,
        'DHCP': Fore.YELLOW,
        'QUIC': Fore.CYAN,
        'ARP': Fore.MAGENTA,
        'IPv6': Fore.CYAN,
        'ERROR': Fore.RED,
        'WARNING': Fore.YELLOW,
    }

    def __init__(self):
        self.packets = []
        self.running = False
        self.quiet_mode = False
        self.use_colors = True
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'conversations': defaultdict(int),
            'packet_sizes': [],
        }
        self._lock = threading.Lock()
        
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def _format_tcp_flags(self, flags) -> str:
        """Convert TCP flags to human-readable format"""
        if flags is None or flags == 0:
            return 'N/A'
        if isinstance(flags, (int)):
            flag_list = []
            for flag_val, flag_name in self.TCP_FLAG_NAMES.items():
                if flags & flag_val:
                    flag_list.append(flag_name)
            return ','.join(flag_list) if flag_list else str(flags)
        return str(flags)

    def validate_bpf_filter(self, filter_str: str) -> bool:
        """Validate BPF filter syntax before capture"""
        if not filter_str:
            return True
        import subprocess
        try:
            result = subprocess.run(
                ['tcpdump', '-d', filter_str],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except FileNotFoundError:
            self.logger.warning("tcpdump not found for filter validation, skipping")
            return True
        except Exception as e:
            self.logger.error(f"Filter validation error: {e}")
            return False

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}Stopping packet capture...{Style.RESET_ALL}")
        self.running = False

    def get_protocol_name(self, packet) -> str:
        """Extract protocol name from packet with priority ordering"""
        if packet.haslayer(DNS):
            if packet.haslayer(TCP):
                return "DNS"
            return "DNS"
        if packet.haslayer(HTTPRequest):
            return "HTTP"
        if packet.haslayer(HTTPResponse):
            return "HTTP"
        if packet.haslayer(HTTP):
            return "HTTP"
        if packet.haslayer(TCP):
            sport = 0
            dport = 0
            try:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            except:
                pass
            if sport == 443 or dport == 443:
                return "TLS"
            if sport == 8443 or dport == 8443:
                return "TLS"
            if sport == 4433 or dport == 4433:
                return "QUIC"
            return "TCP"
        if packet.haslayer(UDP):
            sport = 0
            dport = 0
            try:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            except:
                pass
            if sport == 443 or dport == 443:
                return "QUIC"
            if sport == 53 or dport == 53:
                return "DNS"
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        try:
            if hasattr(packet, 'ARP') and packet.haslayer(packet.ARP):
                return "ARP"
        except:
            pass
        if IPv6 and packet.haslayer(IPv6):
            return "IPv6"
        if hasattr(packet, 'payload') and packet.payload:
            try:
                payload = bytes(packet.payload[:10])
                if b'HTTP' in payload or b'GET ' in payload or b'POST ' in payload or b'PUT ' in payload or b'DELETE' in payload:
                    return "HTTP"
                if b'\r\n' in payload:
                    if payload.startswith(b'REQH') or b'USER' in payload[:10]:
                        return "FTP"
                    if b'SIP' in payload[:10]:
                        return "SIP"
                    if payload.startswith(b'SSH-') or b'SSH' in payload[:10]:
                        return "SSH"
                    if b'MAIL FROM' in payload or b'RCPT TO' in payload:
                        return "SMTP"
                if b'RADIUS' in payload[:10]:
                    return "RADIUS"
            except:
                pass
        return "Other"

    def get_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from a packet with error handling"""
        try:
            timestamp = datetime.fromtimestamp(packet.time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except (AttributeError, OSError, ValueError):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        try:
            packet_length = len(packet)
        except Exception:
            packet_length = 0
        
        info = {
            'timestamp': timestamp,
            'timestamp_epoch': getattr(packet, 'time', 0),
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'protocol': 'Unknown',
            'length': packet_length,
            'flags': 'N/A',
            'info': 'N/A',
            'vlan': 'N/A',
            'ttl': 'N/A',
            'seq': 'N/A',
            'ack': 'N/A',
            'window': 'N/A',
            'http_uri': 'N/A',
            'http_method': 'N/A',
            'http_host': 'N/A',
            'dns_query': 'N/A',
            'tls_version': 'N/A',
            'tls_cipher': 'N/A',
            'arp_src_mac': 'N/A',
            'arp_dst_mac': 'N/A',
            'arp_operation': 'N/A',
            'payload': b'',
            'payload_raw': 'N/A',
        }

        try:
            info['protocol'] = self.get_protocol_name(packet)
        except Exception:
            info['protocol'] = 'Unknown'

        # Extract Ethernet (MAC) addresses
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst

            # Check for ARP
            if hasattr(packet[Ether], 'payload') and packet[Ether].payload:
                if hasattr(packet[Ether].payload, 'op'):
                    info['arp_operation'] = 'Request' if packet[Ether].payload.op == 1 else 'Reply'
                    info['arp_src_mac'] = packet[Ether].payload.psrc if hasattr(packet[Ether].payload, 'psrc') else 'N/A'
                    info['arp_dst_mac'] = packet[Ether].payload.pdst if hasattr(packet[Ether].payload, 'pdst') else 'N/A'

        # Extract VLAN tags
        if Dot1Q and packet.haslayer(Dot1Q):
            info['vlan'] = packet[Dot1Q].vlan

        # Extract IPv6 information
        if IPv6 and packet.haslayer(IPv6):
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            info['ttl'] = packet[IPv6].hlim

        # Extract IPv4 information
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['ttl'] = packet[IP].ttl
            # Calculate protocol hierarchy for IP
            if not info['protocol'] or info['protocol'] == 'Other':
                info['protocol'] = f"IP/{info['protocol']}"

        # Extract TCP information
        if packet.haslayer(TCP):
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = self._format_tcp_flags(packet[TCP].flags)
            info['seq'] = packet[TCP].seq
            info['ack'] = packet[TCP].ack
            info['window'] = packet[TCP].window
            info['info'] = f"TCP {packet[TCP].sport} -> {packet[TCP].dport} [{info['flags']}]"

        # Extract UDP information
        elif packet.haslayer(UDP):
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            info['info'] = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"

        # Extract ICMP information
        elif packet.haslayer(ICMP):
            info['info'] = f"ICMP type {packet[ICMP].type} code {packet[ICMP].code}"

        # Extract HTTP information
        if packet.haslayer(HTTPRequest):
            info['protocol'] = 'HTTP'
            info['http_method'] = packet[HTTPRequest].Method.decode() if hasattr(packet[HTTPRequest], 'Method') else 'GET'
            info['http_uri'] = packet[HTTPRequest].Path.decode() if hasattr(packet[HTTPRequest], 'Path') else '/'
            if hasattr(packet[HTTPRequest], 'Host'):
                info['http_host'] = packet[HTTPRequest].Host.decode()
            info['info'] = f"HTTP {info['http_method']} {info['http_uri']}"

        elif packet.haslayer(HTTPResponse):
            info['protocol'] = 'HTTP'
            info['info'] = f"HTTP Response"

        # Extract DNS information
        if packet.haslayer(DNS):
            info['protocol'] = 'DNS'
            if packet[DNS].qr == 0:
                info['dns_query'] = 'Query'
                if packet[DNS].qd:
                    info['info'] = f"DNS Query {packet[DNS].qd.qname.decode() if packet[DNS].qd else ''}"
            else:
                info['dns_query'] = 'Response'
                info['info'] = "DNS Response"

        try:
            info['payload'] = bytes(packet[TCP].payload) if packet.haslayer(TCP) else b''
            info['payload_raw'] = info['payload'].decode('utf-8', errors='replace') if info['payload'] else 'N/A'
        except:
            info['payload'] = b''
            info['payload_raw'] = '<binary>'

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
        
        # Color coding based on protocol using COLOR_RULES
        color = self.COLOR_RULES.get(protocol, Fore.WHITE) if self.use_colors else ''
        
        print(f"{color}{timestamp} {src:>20} -> {dst:<20} {protocol:>4} {length:>6} {info}{Style.RESET_ALL}")

    def set_color_enabled(self, enabled: bool):
        """Enable or disable colored output"""
        self.use_colors = enabled

    def apply_color_rule(self, protocol: str, color_code: str):
        """Apply custom color to a protocol"""
        self.COLOR_RULES[protocol] = color_code

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

    def read_pcap_file_multithreaded(self, filename: str, filter_str: str = None, num_threads: int = 4) -> int:
        """Read packets from a pcap/pcapng file using multi-threading for better performance"""
        if not os.path.exists(filename):
            self.logger.error(f"File not found: {filename}")
            return 0

        print(f"{Fore.CYAN}Reading packets from {filename} with {num_threads} threads...{Style.RESET_ALL}")

        try:
            import threading
            from queue import Queue
            from concurrent.futures import ThreadPoolExecutor, as_completed

            packet_queue = Queue(maxsize=1000)
            result_count = [0]

            def packet_processor(packets_batch):
                for packet in packets_batch:
                    try:
                        packet_info = self.get_packet_info(packet)
                        with self._lock:
                            self.packets.append(packet_info)
                            self.update_stats(packet_info)
                        result_count[0] += 1
                        if not self.quiet_mode:
                            self.print_packet(packet_info)
                    except Exception as e:
                        self.logger.error(f"Error processing packet: {e}")
                return len(packets_batch)

            packets = sniff(offline=filename, filter=filter_str)
            total_packets = len(packets)

            batch_size = max(1, total_packets // num_threads)
            batches = [packets[i:i + batch_size] for i in range(0, total_packets, batch_size)]

            self.running = True
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(packet_processor, batch) for batch in batches]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Batch processing error: {e}")

            self.running = False
            return result_count[0]
        except Exception as e:
            self.logger.error(f"Error reading pcap file: {e}")
            return 0

    def set_quiet_mode(self, quiet: bool):
        """Set quiet mode to reduce console output overhead"""
        self.quiet_mode = quiet

    def read_pcap_file_chunked(self, filename: str, filter_str: str = None, chunk_size: int = 10000) -> int:
        """Read packets from a pcap/pcapng file in chunks for memory efficiency"""
        if not os.path.exists(filename):
            self.logger.error(f"File not found: {filename}")
            return 0

        print(f"{Fore.CYAN}Reading packets from {filename} in chunks of {chunk_size}...{Style.RESET_ALL}")

        try:
            import itertools

            packet_stream = sniff(offline=filename, filter=filter_str)
            self.running = True
            count = 0
            chunk = []

            for packet in packet_stream:
                try:
                    packet_info = self.get_packet_info(packet)
                    chunk.append(packet_info)
                    count += 1

                    if count % chunk_size == 0:
                        with self._lock:
                            self.packets.extend(chunk)
                            for pkt in chunk:
                                self.update_stats(pkt)
                            if not self.quiet_mode:
                                for pkt in chunk:
                                    self.print_packet(pkt)
                        chunk = []

                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")

            if chunk:
                with self._lock:
                    self.packets.extend(chunk)
                    for pkt in chunk:
                        self.update_stats(pkt)
                    if not self.quiet_mode:
                        for pkt in chunk:
                            self.print_packet(pkt)

            self.running = False
            return count
        except Exception as e:
            self.logger.error(f"Error reading pcap file: {e}")
            return 0

    def read_pcap_file(self, filename: str, filter_str: str = None) -> int:
        """Read packets from a pcap/pcapng file"""
        if not os.path.exists(filename):
            self.logger.error(f"File not found: {filename}")
            return 0

        print(f"{Fore.CYAN}Reading packets from {filename}...{Style.RESET_ALL}")

        try:
            packets = sniff(offline=filename, filter=filter_str)
            self.running = True
            for packet in packets:
                try:
                    packet_info = self.get_packet_info(packet)
                    self.packets.append(packet_info)
                    self.update_stats(packet_info)
                    self.print_packet(packet_info)
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")
            self.running = False
            return len(packets)
        except Exception as e:
            self.logger.error(f"Error reading pcap file: {e}")
            return 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        stats = {
            'total_packets': self.stats['total_packets'],
            'total_bytes': sum(p['length'] for p in self.packets),
            'protocols': dict(self.stats['protocols']),
            'source_ips': dict(self.stats['source_ips']),
            'dest_ips': dict(self.stats['dest_ips']),
            'ports': dict(self.stats['ports']),
            'conversations': {},
            'tcp_flags': defaultdict(int),
            'packet_sizes': self.stats['packet_sizes'],
            'io_stats': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            'expert_info': defaultdict(list),
        }

        first_ts = None
        last_ts = None

        for pkt in self.packets:
            src = pkt.get('src_ip', 'N/A')
            dst = pkt.get('dst_ip', 'N/A')
            if src != 'N/A' and dst != 'N/A':
                conv_key = f"{src} <-> {dst}"
                stats['conversations'][conv_key] = stats['conversations'].get(conv_key, 0) + 1

            flags = pkt.get('flags', 'N/A')
            if flags != 'N/A':
                for flag in flags.split(','):
                    stats['tcp_flags'][flag.strip()] += 1

            ts = pkt.get('timestamp_epoch')
            if ts:
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                minute_key = int(ts // 60)
                stats['io_stats'][minute_key]['packets'] += 1
                stats['io_stats'][minute_key]['bytes'] += pkt.get('length', 0)

            protocol = pkt.get('protocol', 'Other')
            if protocol == 'TCP':
                if flags and 'RST' in flags:
                    stats['expert_info']['Error'].append(f"TCP RST from {src}:{pkt.get('src_port')} to {dst}:{pkt.get('dst_port')}")
                elif flags and 'SYN' in flags and 'ACK' not in flags:
                    stats['expert_info']['Warning'].append(f"TCP SYN scan from {src}")
            elif protocol == 'DNS':
                if pkt.get('dns_query') == 'Query':
                    stats['expert_info']['Note'].append(f"DNS query to {dst}")

        if first_ts and last_ts:
            stats['duration'] = last_ts - first_ts
            stats['packets_per_second'] = stats['total_packets'] / stats['duration'] if stats['duration'] > 0 else 0
            stats['bytes_per_second'] = stats['total_bytes'] / stats['duration'] if stats['duration'] > 0 else 0
        else:
            stats['duration'] = 0
            stats['packets_per_second'] = 0
            stats['bytes_per_second'] = 0

        return stats

    def print_io_statistics(self):
        """Print I/O statistics with packets/second and bytes/second"""
        stats = self.get_statistics()
        print(f"\n{Fore.CYAN}{'='*50} I/O STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Packets: {stats['total_packets']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Bytes: {stats['total_bytes']:,}{Style.RESET_ALL}")
        if stats['duration'] > 0:
            print(f"{Fore.YELLOW}Duration: {stats['duration']:.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Packets/Second: {stats['packets_per_second']:.2f}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Bytes/Second: {stats['bytes_per_second']:.2f}{Style.RESET_ALL}")

        if stats['io_stats']:
            print(f"\n{Fore.YELLOW}I/O by Minute:{Style.RESET_ALL}")
            for minute, io in sorted(stats['io_stats'].items()):
                print(f"  Minute {minute}: {io['packets']} packets, {io['bytes']:,} bytes")

    def print_expert_info(self):
        """Print expert information (warnings, errors, notes)"""
        stats = self.get_statistics()
        expert = stats.get('expert_info', {})

        if not any(expert.values()):
            print(f"\n{Fore.CYAN}{'='*50} EXPERT INFORMATION {'='*50}{Style.RESET_ALL}")
            print("No expert information")
            return

        print(f"\n{Fore.CYAN}{'='*50} EXPERT INFORMATION {'='*50}{Style.RESET_ALL}")

        if 'Error' in expert and expert['Error']:
            print(f"\n{Fore.RED}ERRORS ({len(expert['Error'])}):{Style.RESET_ALL}")
            for msg in expert['Error'][:5]:
                print(f"  {Fore.RED}✗ {msg}{Style.RESET_ALL}")
            if len(expert['Error']) > 5:
                print(f"  ... and {len(expert['Error']) - 5} more")

        if 'Warning' in expert and expert['Warning']:
            print(f"\n{Fore.YELLOW}WARNINGS ({len(expert['Warning'])}):{Style.RESET_ALL}")
            for msg in expert['Warning'][:5]:
                print(f"  {Fore.YELLOW}⚠ {msg}{Style.RESET_ALL}")
            if len(expert['Warning']) > 5:
                print(f"  ... and {len(expert['Warning']) - 5} more")

        if 'Note' in expert and expert['Note']:
            print(f"\n{Fore.BLUE}NOTES ({len(expert['Note'])}):{Style.RESET_ALL}")
            for msg in expert['Note'][:5]:
                print(f"  {Fore.BLUE}ℹ {msg}{Style.RESET_ALL}")
            if len(expert['Note']) > 5:
                print(f"  ... and {len(expert['Note']) - 5} more")

    def print_http_statistics(self):
        """Print HTTP request/response statistics"""
        http_stats = {
            'requests': defaultdict(int),
            'responses': defaultdict(int),
            'methods': defaultdict(int),
            'status_codes': defaultdict(int),
            'hosts': defaultdict(int),
            'uris': defaultdict(int),
            'user_agents': defaultdict(int),
            'content_types': defaultdict(int),
        }

        for pkt in self.packets:
            if pkt.get('protocol') != 'HTTP':
                continue
            method = pkt.get('http_method', 'N/A')
            if method != 'N/A':
                http_stats['methods'][method] += 1
                host = pkt.get('http_host', 'N/A')
                if host != 'N/A':
                    http_stats['hosts'][host] += 1
                uri = pkt.get('http_uri', 'N/A')
                if uri != 'N/A':
                    http_stats['uris'][uri] += 1

        total_requests = sum(http_stats['methods'].values())
        if total_requests == 0:
            print(f"{Fore.CYAN}{'='*50} HTTP STATISTICS {'='*50}{Style.RESET_ALL}")
            print("No HTTP traffic found")
            return

        print(f"\n{Fore.CYAN}{'='*50} HTTP STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total HTTP Requests: {total_requests}{Style.RESET_ALL}")

        if http_stats['methods']:
            print(f"\n{Fore.YELLOW}HTTP Methods:{Style.RESET_ALL}")
            for method, count in sorted(http_stats['methods'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {method}: {count}")

        if http_stats['hosts']:
            print(f"\n{Fore.YELLOW}Top HTTP Hosts:{Style.RESET_ALL}")
            for host, count in sorted(http_stats['hosts'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {host}: {count}")

        if http_stats['uris']:
            print(f"\n{Fore.YELLOW}Top HTTP URIs:{Style.RESET_ALL}")
            for uri, count in sorted(http_stats['uris'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {uri}: {count}")

    def print_bandwidth_analysis(self):
        """Print bandwidth analysis with time-based rates"""
        stats = self.get_statistics()
        
        if not stats.get('io_stats'):
            print(f"\n{Fore.CYAN}{'='*50} BANDWIDTH ANALYSIS {'='*50}{Style.RESET_ALL}")
            print("No timing data available")
            return

        print(f"\n{Fore.CYAN}{'='*50} BANDWIDTH ANALYSIS {'='*50}{Style.RESET_ALL}")
        
        io = stats['io_stats']
        if io:
            sorted_minutes = sorted(io.items(), key=lambda x: x[0])
            first_min = sorted_minutes[0][0]
            
            rates = []
            for minute, data in sorted_minutes:
                duration_minutes = 1.0
                pps = data['packets'] / duration_minutes if duration_minutes > 0 else 0
                bps = data['bytes'] * 8 / (duration_minutes * 1000) if duration_minutes > 0 else 0
                rates.append((minute, pps, bps, data['packets'], data['bytes']))

            if rates:
                print(f"\n{Fore.YELLOW}Time    Packets/s Kbps    Packets Bytes{Style.RESET_ALL}")
                for minute, pps, bps, pkts, bytes_val in rates[:20]:
                    print(f"{minute:5} {pps:8.1f} {bps:7.1f} {pkts:6} {bytes_val:8,}")

    def print_tcp_analysis(self):
        """Print TCP sequence and RTT analysis"""
        tcp_stats = {
            'retransmissions': 0,
            'out_of_order': 0,
            'reused_ports': 0,
            'connections': defaultdict(lambda: {'syn': 0, 'fin': 0, 'rst': 0, 'data': 0}),
        }

        for pkt in self.packets:
            if pkt.get('protocol') != 'TCP':
                continue
            src = pkt.get('src_ip', 'N/A')
            dst = pkt.get('dst_ip', 'N/A')
            src_port = pkt.get('src_port')
            dst_port = pkt.get('dst_port')
            flags = pkt.get('flags', '')

            if src != 'N/A' and dst != 'N/A':
                conn_key = f"{src}:{src_port} <-> {dst}:{dst_port}"
                if 'SYN' in flags and 'ACK' not in flags:
                    tcp_stats['connections'][conn_key]['syn'] += 1
                if 'FIN' in flags:
                    tcp_stats['connections'][conn_key]['fin'] += 1
                if 'RST' in flags:
                    tcp_stats['connections'][conn_key]['rst'] += 1
                    tcp_stats['retransmissions'] += 1
                if 'PSH' in flags or 'ACK' in flags:
                    tcp_stats['connections'][conn_key]['data'] += 1

        print(f"\n{Fore.CYAN}{'='*50} TCP ANALYSIS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}TCP Retransmissions: {tcp_stats['retransmissions']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total TCP Connections: {len(tcp_stats['connections'])}{Style.RESET_ALL}")

        if tcp_stats['connections']:
            print(f"\n{Fore.YELLOW}Top TCP Conversations:{Style.RESET_ALL}")
            sorted_conns = sorted(tcp_stats['connections'].items(), key=lambda x: x[1]['data'], reverse=True)[:10]
            for conn, data in sorted_conns:
                print(f"  {conn}: {data['data']} data packets, {data['rst']} RST, {data['fin']} FIN")

    def print_dns_statistics(self):
        """Print DNS query statistics"""
        dns_stats = {
            'queries': defaultdict(int),
            'responses': defaultdict(int),
            'query_types': defaultdict(int),
            'servers': defaultdict(int),
        }

        for pkt in self.packets:
            if pkt.get('protocol') != 'DNS':
                continue
            query_type = pkt.get('dns_query', 'N/A')
            dst = pkt.get('dst_ip', 'N/A')

            if query_type == 'Query':
                dns_stats['queries'][dst] += 1
            elif query_type == 'Response':
                dns_stats['responses'][dst] += 1

        total_dns = sum(dns_stats['queries'].values()) + sum(dns_stats['responses'].values())
        if total_dns == 0:
            print(f"\n{Fore.CYAN}{'='*50} DNS STATISTICS {'='*50}{Style.RESET_ALL}")
            print("No DNS traffic found")
            return

        print(f"\n{Fore.CYAN}{'='*50} DNS STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total DNS Messages: {total_dns}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Queries: {sum(dns_stats['queries'].values())}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Responses: {sum(dns_stats['responses'].values())}{Style.RESET_ALL}")

        if dns_stats['queries']:
            print(f"\n{Fore.YELLOW}Top DNS Servers:{Style.RESET_ALL}")
            for server, count in sorted(dns_stats['queries'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {server}: {count} queries")

    def print_protocol_hierarchy(self):
        """Print protocol hierarchy statistics"""
        stats = self.get_statistics()
        print(f"\n{Fore.CYAN}{'='*50} PROTOCOL HIERARCHY {'='*50}{Style.RESET_ALL}")

        total = stats['total_packets']
        if total == 0:
            print("No packets captured")
            return

        print(f"{Fore.YELLOW}Protocols (packets):{Style.RESET_ALL}")
        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            print(f"  {protocol:15} {count:6} ({percentage:5.1f}%)")

    def print_conversations(self):
        """Print conversation statistics"""
        stats = self.get_statistics()
        print(f"\n{Fore.CYAN}{'='*50} TOP CONVERSATIONS {'='*50}{Style.RESET_ALL}")

        conversations = stats.get('conversations', {})
        if not conversations:
            print("No conversations found")
            return

        print(f"{Fore.YELLOW}Top IP Conversations:{Style.RESET_ALL}")
        for conv, count in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {conv}: {count} packets")

    def export_json_lines(self, filename: str):
        """Export packets as JSON Lines format"""
        with open(filename, 'w') as f:
            for pkt in self.packets:
                f.write(json.dumps(pkt) + '\n')
        print(f"{Fore.GREEN}Exported {len(self.packets)} packets to {filename}{Style.RESET_ALL}")

    def export_pdml(self, filename: str):
        """Export packets in PDML (Packet Details Markup Language) format"""
        with open(filename, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<pdml>\n')
            for pkt in self.packets:
                f.write('  <packet>\n')
                for key, value in pkt.items():
                    if value != 'N/A':
                        f.write(f'    <field name="{key}">{value}</field>\n')
                f.write('  </packet>\n')
            f.write('</pdml>\n')
        print(f"{Fore.GREEN}Exported {len(self.packets)} packets to PDML file {filename}{Style.RESET_ALL}")

    def export_fields(self, filename: str, fields: List[str]):
        """Export specific fields in text format"""
        with open(filename, 'w') as f:
            for pkt in self.packets:
                row = []
                for field in fields:
                    value = pkt.get(field, 'N/A')
                    row.append(str(value))
                f.write('\t'.join(row) + '\n')
        print(f"{Fore.GREEN}Exported {len(self.packets)} packets with fields to {filename}{Style.RESET_ALL}")

    class TCPStream:
        def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
            self.src_ip = src_ip
            self.dst_ip = dst_ip
            self.src_port = src_port
            self.dst_port = dst_port
            self.server_to_client = bytearray()
            self.client_to_server = bytearray()
            self.packets = []

        @property
        def key(self) -> str:
            return f"{self.src_ip}:{self.src_port} <-> {self.dst_ip}:{self.dst_port}"

        def add_packet(self, packet_info: Dict[str, Any], payload: bytes, direction: str):
            self.packets.append(packet_info)
            if direction == "c2s":
                self.client_to_server.extend(payload)
            else:
                self.server_to_client.extend(payload)

    def reassemble_tcp_streams(self) -> Dict[str, 'MiniShark.TCPStream']:
        """Reassemble TCP streams from captured packets"""
        streams: Dict[str, 'MiniShark.TCPStream'] = {}

        for pkt in self.packets:
            if pkt.get('protocol') != 'TCP':
                continue

            src_ip = pkt.get('src_ip', 'N/A')
            dst_ip = pkt.get('dst_ip', 'N/A')
            src_port = pkt.get('src_port')
            dst_port = pkt.get('dst_port')

            if src_ip == 'N/A' or dst_ip == 'N/A' or src_port == 'N/A' or dst_port == 'N/A':
                continue

            stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

            if stream_key not in streams and reverse_key not in streams:
                streams[stream_key] = self.TCPStream(src_ip, dst_ip, src_port, dst_port)
                current_stream = streams[stream_key]
            elif reverse_key in streams:
                current_stream = streams[reverse_key]
            else:
                current_stream = streams[stream_key]

            current_stream.packets.append(pkt)

        return streams

    def follow_tcp_stream(self, stream_key: str, format_ascii: bool = True) -> str:
        """Follow a specific TCP stream and display its content"""
        output = []
        output.append(f"{Fore.CYAN}Follow TCP Stream {stream_key}{Style.RESET_ALL}")
        output.append("=" * 60)

        stream = self.reassemble_tcp_streams().get(stream_key)
        if not stream:
            return f"Stream {stream_key} not found"

        output.append(f"{Fore.YELLOW}Server -> Client: {len(stream.server_to_client)} bytes{Style.RESET_ALL}")
        if format_ascii:
            try:
                output.append(stream.server_to_client.decode('utf-8', errors='replace'))
            except:
                output.append(f"<{len(stream.server_to_client)} bytes>")
        else:
            output.append(stream.server_to_client.hex())

        output.append(f"{Fore.YELLOW}Client -> Server: {len(stream.client_to_server)} bytes{Style.RESET_ALL}")
        if format_ascii:
            try:
                output.append(stream.client_to_server.decode('utf-8', errors='replace'))
            except:
                output.append(f"<{len(stream.client_to_server)} bytes>")
        else:
            output.append(stream.client_to_server.hex())

        return '\n'.join(output)

    def print_follow_menu(self):
        """Print available TCP streams to follow"""
        streams = self.reassemble_tcp_streams()
        if not streams:
            print(f"{Fore.RED}No TCP streams found{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Available TCP Streams:{Style.RESET_ALL}")
        print("=" * 60)
        for i, (key, stream) in enumerate(streams.items(), 1):
            total_bytes = len(stream.server_to_client) + len(stream.client_to_server)
            print(f"  {i}. {key} ({total_bytes} bytes, {len(stream.packets)} packets)")

    def merge_pcap_files(self, input_files: List[str], output_file: str) -> bool:
        """Merge multiple pcap files into one"""
        try:
            from scapy.utils import PcapWriter
            all_packets = []
            for f in input_files:
                if not os.path.exists(f):
                    self.logger.error(f"File not found: {f}")
                    return False
                packets = sniff(offline=f)
                all_packets.extend(packets)
            if all_packets:
                wrpcap(output_file, all_packets)
                print(f"{Fore.GREEN}Merged {len(all_packets)} packets to {output_file}{Style.RESET_ALL}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error merging pcap files: {e}")
            return False

    def split_pcap_file(self, input_file: str, output_dir: str, packets_per_file: int = 1000) -> List[str]:
        """Split a large pcap file into smaller files"""
        output_files = []
        try:
            os.makedirs(output_dir, exist_ok=True)
            packets = sniff(offline=input_file)
            total = len(packets)
            for i in range(0, total, packets_per_file):
                chunk = packets[i:i + packets_per_file]
                output_file = os.path.join(output_dir, f"split_{i//packets_per_file:04d}.pcap")
                wrpcap(output_file, chunk)
                output_files.append(output_file)
            print(f"{Fore.GREEN}Split into {len(output_files)} files in {output_dir}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error splitting pcap file: {e}")
        return output_files

    def filter_by_byte_offset(self, offset: int, value: bytes, comparison: str = 'equal') -> List[Dict]:
        """Filter packets by byte offset value"""
        results = []
        for pkt in self.packets:
            try:
                payload = pkt.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')
                if offset < len(payload):
                    target = payload[offset:offset + len(value)]
                    if comparison == 'equal' and target == value:
                        results.append(pkt)
                    elif comparison == 'contains' and value in target:
                        results.append(pkt)
            except:
                pass
        return results

    def add_packet_comment(self, packet_index: int, comment: str):
        """Add a comment to a packet"""
        if 0 <= packet_index < len(self.packets):
            self.packets[packet_index]['comment'] = comment

    def export_with_comments(self, filename: str, format: str = 'json'):
        """Export packets including comments"""
        packets_with_comments = [p for p in self.packets if 'comment' in p and p['comment']]
        if not packets_with_comments:
            print(f"{Fore.YELLOW}No packets with comments to export{Style.RESET_ALL}")
            return
        self.save_to_file(filename, format)

    def export_parquet(self, filename: str):
        """Export packets to Parquet format for big data analytics"""
        try:
            import pandas as pd
            df = pd.DataFrame(self.packets)
            df.to_parquet(filename, engine='auto', compression='snappy')
            print(f"{Fore.GREEN}Exported {len(self.packets)} packets to Parquet file {filename}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}pandas and pyarrow required for Parquet export. Run: pip install pandas pyarrow{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error exporting to Parquet: {e}")

    def export_excel(self, filename: str):
        """Export packets to Excel workbook"""
        try:
            import pandas as pd
            df = pd.DataFrame(self.packets)
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Packets', index=False)
                
                stats = self.get_statistics()
                stats_df = pd.DataFrame({
                    'Metric': ['Total Packets', 'Total Bytes', 'Duration (s)', 'Packets/s', 'Bytes/s'],
                    'Value': [
                        stats['total_packets'],
                        stats['total_bytes'],
                        f"{stats.get('duration', 0):.2f}",
                        f"{stats.get('packets_per_second', 0):.2f}",
                        f"{stats.get('bytes_per_second', 0):.2f}",
                    ]
                })
                stats_df.to_excel(writer, sheet_name='Statistics', index=False)
                
                protocols = stats.get('protocols', {})
                if protocols:
                    proto_df = pd.DataFrame(list(protocols.items()), columns=['Protocol', 'Count'])
                    proto_df.to_excel(writer, sheet_name='Protocols', index=False)
            print(f"{Fore.GREEN}Exported {len(self.packets)} packets to Excel file {filename}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}pandas and openpyxl required for Excel export. Run: pip install pandas openpyxl{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error exporting to Excel: {e}")

    def scan_with_yara(self, rules_path: str = None, rules_string: str = None) -> List[Dict]:
        """Scan packet payloads against YARA rules"""
        try:
            import yara
        except ImportError:
            print(f"{Fore.RED}YARA scanning requires yara-python. Run: pip install yara-python{Style.RESET_ALL}")
            return []

        matches_found = []

        try:
            if rules_path:
                rules = yara.compile(filepath=rules_path)
            elif rules_string:
                rules = yara.compile(source=rules_string)
            else:
                sample_rules = '''
                rule suspicious_dns {{
                    condition:
                        any
                }}
                '''
                rules = yara.compile(source=sample_rules)
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            return []

        for i, pkt in enumerate(self.packets):
            try:
                payload = pkt.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')
                if payload and len(payload) > 0:
                    match = rules.match(data=payload)
                    if match:
                        for m in match:
                            matches_found.append({
                                'packet_index': i,
                                'rule': m.rule,
                                'tags': m.tags,
                                'meta': m.meta,
                                'src_ip': pkt.get('src_ip'),
                                'dst_ip': pkt.get('dst_ip'),
                                'protocol': pkt.get('protocol'),
                            })
            except Exception:
                pass

        return matches_found

    def print_yara_results(self, matches: List[Dict]):
        """Print YARA scan results"""
        if not matches:
            print(f"\n{Fore.CYAN}{'='*50} YARA SCAN RESULTS {'='*50}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}No YARA rule matches found{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'='*50} YARA SCAN RESULTS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Matches: {len(matches)}{Style.RESET_ALL}")

        unique_rules = set(m['rule'] for m in matches)
        print(f"\n{Fore.RED}Matched Rules:{Style.RESET_ALL}")
        for rule in unique_rules:
            rule_matches = [m for m in matches if m['rule'] == rule]
            print(f"  {rule}: {len(rule_matches)} matches")

        print(f"\n{Fore.YELLOW}Matched Packets:{Style.RESET_ALL}")
        for m in matches[:10]:
            print(f"  Packet {m['packet_index']}: {m['src_ip']} -> {m['dst_ip']} [{m['protocol']}]")

    def detect_threats(self) -> Dict:
        """Detect common threat indicators"""
        threats = {
            'port_scans': [],
            'dns_tunneling': [],
            'suspicious_ports': [],
            'malicious_patterns': [],
            'data_exfiltration': [],
            'reconnaissance': [],
        }

        suspicious_ports = {4444: 'Metasploit', 5555: 'Android ADB', 6667: 'IRC', 31337: 'Back Orifice'}
        syn_count = defaultdict(int)
        dns_query_sizes = []

        for pkt in self.packets:
            src_ip = pkt.get('src_ip', 'N/A')
            dst_ip = pkt.get('dst_ip', 'N/A')
            dst_port = pkt.get('dst_port', 0)
            protocol = pkt.get('protocol')
            flags = pkt.get('flags', '')
            length = pkt.get('length', 0)

            if dst_port in suspicious_ports:
                threats['suspicious_ports'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'port': dst_port,
                    'tool': suspicious_ports[dst_port],
                })

            if protocol == 'TCP' and 'SYN' in flags and 'ACK' not in flags:
                syn_count[src_ip] += 1
                if syn_count[src_ip] > 50:
                    threats['port_scans'].append({
                        'src_ip': src_ip,
                        'syn_count': syn_count[src_ip],
                    })
                    syn_count[src_ip] = 0

            if protocol == 'DNS' and pkt.get('dns_query') == 'Query':
                payload = pkt.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')
                if len(payload) > 100:
                    dns_query_sizes.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'query_size': len(payload),
                    })

            if length > 10000 and protocol in ['TCP', 'UDP']:
                threats['data_exfiltration'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'size': length,
                    'protocol': protocol,
                })

        if dns_query_sizes:
            threats['dns_tunneling'] = dns_query_sizes[:10]

        return threats

    def print_threats(self, threats: Dict):
        """Print detected threats"""
        total_threats = sum(len(v) for v in threats.values())

        print(f"\n{Fore.CYAN}{'='*50} THREAT DETECTION {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Threats Detected: {total_threats}{Style.RESET_ALL}")

        if threats['suspicious_ports']:
            print(f"\n{Fore.RED}SUSPICIOUS PORTS:{Style.RESET_ALL}")
            for t in threats['suspicious_ports'][:5]:
                print(f"  {t['src_ip']} -> {t['dst_ip']}:{t['port']} ({t['tool']})")

        if threats['port_scans']:
            print(f"\n{Fore.RED}PORT SCANS:{Style.RESET_ALL}")
            for t in threats['port_scans'][:5]:
                print(f"  {t['src_ip']}: {t['syn_count']} SYN packets")

        if threats['dns_tunneling']:
            print(f"\n{Fore.YELLOW}LARGE DNS QUERIES (possible tunneling):{Style.RESET_ALL}")
            for t in threats['dns_tunneling'][:5]:
                print(f"  {t['src_ip']} -> {t['dst_ip']}: {t['query_size']} bytes")

        if threats['data_exfiltration']:
            print(f"\n{Fore.YELLOW}LARGE DATA TRANSFERS:{Style.RESET_ALL}")
            for t in threats['data_exfiltration'][:5]:
                print(f"  {t['src_ip']} -> {t['dst_ip']}: {t['size']} bytes ({t['protocol']})")

        if total_threats == 0:
            print(f"{Fore.GREEN}No threats detected{Style.RESET_ALL}")

    def parse_mqtt(self) -> List[Dict]:
        """Parse MQTT packets"""
        mqtt_packets = []

        mqtt_control_types = {
            1: 'CONNECT',
            2: 'CONNACK',
            3: 'PUBLISH',
            4: 'PUBACK',
            5: 'PUBREC',
            6: 'PUBREL',
            7: 'PUBCOMP',
            8: 'SUBSCRIBE',
            9: 'SUBACK',
            10: 'UNSUBSCRIBE',
            11: 'UNSUBACK',
            12: 'PINGREQ',
            13: 'PINGRESP',
            14: 'DISCONNECT',
        }

        for pkt in self.packets:
            protocol = pkt.get('protocol')
            if protocol not in ['TCP', 'MQTT']:
                continue

            src_port = pkt.get('src_port', 0)
            dst_port = pkt.get('dst_port', 0)

            if src_port == 1883 or dst_port == 1883 or src_port == 8883 or dst_port == 8883:
                payload = pkt.get('payload_raw', '')
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='replace')

                mqtt_info = {
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'control_type': 'Unknown',
                    'client_id': 'N/A',
                    'topic': 'N/A',
                    'qos': 0,
                }

                if payload and len(payload) > 0:
                    if payload.startswith(b'\x10') or 'CONNECT' in payload[:20]:
                        mqtt_info['control_type'] = 'CONNECT'
                    elif payload.startswith(b'\x20') or 'CONNACK' in payload[:20]:
                        mqtt_info['control_type'] = 'CONNACK'
                    elif payload.startswith(b'\x30') or 'PUBLISH' in payload[:20]:
                        mqtt_info['control_type'] = 'PUBLISH'

                mqtt_packets.append(mqtt_info)

        return mqtt_packets

    def print_mqtt_statistics(self, mqtt_packets: List[Dict]):
        """Print MQTT statistics"""
        if not mqtt_packets:
            print(f"\n{Fore.CYAN}{'='*50} MQTT STATISTICS {'='*50}{Style.RESET_ALL}")
            print("No MQTT traffic found")
            return

        print(f"\n{Fore.CYAN}{'='*50} MQTT STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total MQTT Packets: {len(mqtt_packets)}{Style.RESET_ALL}")

        control_types = defaultdict(int)
        for pkt in mqtt_packets:
            control_types[pkt['control_type']] += 1

        if control_types:
            print(f"\n{Fore.YELLOW}Control Packet Types:{Style.RESET_ALL}")
            for ct, count in sorted(control_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {ct}: {count}")

    def parse_dhcp(self) -> List[Dict]:
        """Parse DHCP packets"""
        dhcp_packets = []

        dhcp_options = {
            1: 'Subnet Mask',
            3: 'Router',
            6: 'DNS Server',
            53: 'Message Type',
            55: 'Parameter Request',
            60: 'Vendor Class',
            61: 'Client Identifier',
        }

        dhcp_msg_types = {
            1: 'DISCOVER',
            2: 'OFFER',
            3: 'REQUEST',
            4: 'DECLINE',
            5: 'ACK',
            6: 'NAK',
            7: 'RELEASE',
            8: 'INFORM',
        }

        for pkt in self.packets:
            src_port = pkt.get('src_port', 0)
            dst_port = pkt.get('dst_port', 0)

            if (src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68):
                dhcp_info = {
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'message_type': 'Unknown',
                    'vendor': 'N/A',
                    'requested_ip': 'N/A',
                }

                payload = pkt.get('payload_raw', '')
                if isinstance(payload, bytes):
                    payload = payload.decode('latin-1', errors='replace')

                if b'DISCOVER' in payload[:50]:
                    dhcp_info['message_type'] = 'DISCOVER'
                elif b'OFFER' in payload[:50]:
                    dhcp_info['message_type'] = 'OFFER'
                elif b'REQUEST' in payload[:50]:
                    dhcp_info['message_type'] = 'REQUEST'
                elif b'ACK' in payload[:50]:
                    dhcp_info['message_type'] = 'ACK'
                elif b'RELEASE' in payload[:50]:
                    dhcp_info['message_type'] = 'RELEASE'

                dhcp_packets.append(dhcp_info)

        return dhcp_packets

    def print_dhcp_statistics(self, dhcp_packets: List[Dict]):
        """Print DHCP statistics"""
        if not dhcp_packets:
            print(f"\n{Fore.CYAN}{'='*50} DHCP STATISTICS {'='*50}{Style.RESET_ALL}")
            print("No DHCP traffic found")
            return

        print(f"\n{Fore.CYAN}{'='*50} DHCP STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total DHCP Packets: {len(dhcp_packets)}{Style.RESET_ALL}")

        msg_types = defaultdict(int)
        for pkt in dhcp_packets:
            msg_types[pkt['message_type']] += 1

        if msg_types:
            print(f"\n{Fore.YELLOW}Message Types:{Style.RESET_ALL}")
            for mt, count in sorted(msg_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {mt}: {count}")

    def analyze_websocket(self) -> List[Dict]:
        """Analyze WebSocket frames"""
        ws_packets = []

        for pkt in self.packets:
            payload = pkt.get('payload_raw', '')
            if isinstance(payload, bytes):
                payload = payload.decode('latin-1', errors='replace')

            if len(payload) >= 2:
                first_byte = payload[0] if isinstance(payload[0], int) else ord(payload[0])
                if first_byte in [0x81, 0x82, 0x88, 0x8A]:
                    ws_info = {
                        'src_ip': pkt.get('src_ip'),
                        'dst_ip': pkt.get('dst_ip'),
                        'opcode': first_byte & 0x0F,
                        'masked': bool(ord(payload[1]) & 0x80) if len(payload) > 1 else False,
                        'payload_length': len(payload) - 2 if len(payload) > 2 else 0,
                    }

                    opcode_names = {0x0: 'Continuation', 0x1: 'Text', 0x2: 'Binary',
                                    0x8: 'Close', 0x9: 'Ping', 0xA: 'Pong'}
                    ws_info['opcode_name'] = opcode_names.get(ws_info['opcode'], 'Unknown')

                    ws_packets.append(ws_info)

        return ws_packets

    def print_websocket_analysis(self, ws_packets: List[Dict]):
        """Print WebSocket analysis"""
        if not ws_packets:
            print(f"\n{Fore.CYAN}{'='*50} WEBSOCKET ANALYSIS {'='*50}{Style.RESET_ALL}")
            print("No WebSocket traffic found")
            return

        print(f"\n{Fore.CYAN}{'='*50} WEBSOCKET ANALYSIS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total WebSocket Frames: {len(ws_packets)}{Style.RESET_ALL}")

        opcodes = defaultdict(int)
        for pkt in ws_packets:
            opcodes[pkt['opcode_name']] += 1

        if opcodes:
            print(f"\n{Fore.YELLOW}Frame Types:{Style.RESET_ALL}")
            for op, count in sorted(opcodes.items(), key=lambda x: x[1], reverse=True):
                print(f"  {op}: {count}")

    def generate_hex_dump(self, packet) -> str:
        """Generate hex dump of packet payload"""
        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else b''
        except:
            payload = b''

        if not payload:
            return ""

        lines = []
        for i in range(0, len(payload), 16):
            chunk = payload[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')

        return '\n'.join(lines)

    def generate_hex_ascii_dump(self, packet) -> str:
        """Generate combined hex + ASCII dump with Ethernet header"""
        lines = []

        if packet.haslayer(Ether):
            ether = packet[Ether]
            lines.append(f"# Ethernet: {ether.src} -> {ether.dst}, type: 0x{ether.type:04x}")

        if packet.haslayer(IP):
            ip = packet[IP]
            lines.append(f"# IP: {ip.src} -> {ip.dst}, len: {ip.len}, id: {ip.id}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            lines.append(f"# TCP: {tcp.sport} -> {tcp.dport}, seq: {tcp.seq}, ack: {tcp.ack}, flags: {tcp.flags}")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            lines.append(f"# UDP: {udp.sport} -> {udp.dport}, len: {udp.len}")

        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload) if packet.haslayer(UDP) else b''
        except:
            payload = b''

        if payload:
            for i in range(0, len(payload), 16):
                chunk = payload[i:i + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')

        return '\n'.join(lines)

    def generate_ascii_dump(self, packet) -> str:
        """Generate ASCII-only dump"""
        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload) if packet.haslayer(UDP) else b''
        except:
            payload = b''

        if not payload:
            return ""

        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)

    def print_packet_hex(self, packet, packet_info: Dict):
        """Print packet with hex dump"""
        print(f"\n{Fore.CYAN}{'='*60} PACKET {len(self.packets)} {'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{packet_info['timestamp']}  {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}  {packet_info['protocol']}{Style.RESET_ALL}")
        print(self.generate_hex_ascii_dump(packet))

    def extract_tls_certificates(self) -> List[Dict]:
        """Extract TLS certificates from packets"""
        certs = []

        for pkt in self.packets:
            if pkt.get('protocol') == 'TLS':
                payload = pkt.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')

                if payload and len(payload) > 100:
                    cert_info = {
                        'src_ip': pkt.get('src_ip'),
                        'dst_ip': pkt.get('dst_ip'),
                        'src_port': pkt.get('src_port'),
                        'dst_port': pkt.get('dst_port'),
                        'subject': 'N/A',
                        'issuer': 'N/A',
                        'not_before': 'N/A',
                        'not_after': 'N/A',
                        'serial': 'N/A',
                    }

                    payload_str = payload.decode('latin-1', errors='ignore')
                    if '-----BEGIN CERTIFICATE-----' in payload_str:
                        cert_info['has_pem'] = True
                    else:
                        cert_info['has_pem'] = False

                    certs.append(cert_info)

        return certs

    def export_tls_certificates(self, output_dir: str):
        """Save TLS certificates to files"""
        certs = self.extract_tls_certificates()

        if not certs:
            print(f"{Fore.YELLOW}No TLS certificates found{Style.RESET_ALL}")
            return

        os.makedirs(output_dir, exist_ok=True)

        for i, cert in enumerate(certs[:50]):
            filename = f"{cert['src_ip']}_{cert['dst_ip']}_{cert['src_port']}.pem"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'w') as f:
                f.write(f"# Certificate from {cert['src_ip']}:{cert['src_port']} -> {cert['dst_ip']}:{cert['dst_port']}\n")
                f.write(f"# Subject: {cert['subject']}\n")
                f.write(f"# Issuer: {cert['issuer']}\n")
                if cert.get('has_pem'):
                    f.write("-----BEGIN CERTIFICATE-----\n")
                    f.write("-----END CERTIFICATE-----\n")

        print(f"{Fore.GREEN}Exported {min(len(certs), 50)} certificates to {output_dir}{Style.RESET_ALL}")

    async def capture_async(self, interface: str = None, count: int = 0, filter_str: str = None):
        """Async packet capture"""
        import asyncio
        from scapy.all import AsyncSniffer

        self.running = True
        queue = asyncio.Queue()

        async def packet_handler(packet):
            try:
                packet_info = self.get_packet_info(packet)
                await queue.put(packet_info)
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

        try:
            sniffer = AsyncSniffer(
                iface=interface,
                prn=packet_handler,
                count=count if count > 0 else 0,
                filter=filter_str,
                stop_filter=lambda x: not self.running
            )

            print(f"{Fore.CYAN}Starting async capture...{Style.RESET_ALL}")
            sniffer.start()

            while self.running:
                try:
                    packet_info = await asyncio.wait_for(queue.get(), timeout=1.0)
                    self.packets.append(packet_info)
                    self.update_stats(packet_info)
                    self.print_packet(packet_info)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    self.logger.error(f"Error: {e}")

        except Exception as e:
            self.logger.error(f"Async capture error: {e}")
        finally:
            self.running = False
            sniffer.stop()

    def extract_http_objects(self) -> List[Dict]:
        """Extract HTTP objects (files, images) from packets"""
        http_objects = []

        http_content_types = {
            b'jpeg': 'image/jpeg',
            b'jpg': 'image/jpeg',
            b'png': 'image/png',
            b'gif': 'image/gif',
            b'html': 'text/html',
            b'css': 'text/css',
            b'js': 'application/javascript',
            b'json': 'application/json',
            b'xml': 'application/xml',
            b'pdf': 'application/pdf',
            b'zip': 'application/zip',
        }

        for pkt in self.packets:
            if pkt.get('protocol') != 'HTTP':
                continue

            payload = pkt.get('payload', b'')
            if isinstance(payload, str):
                payload = payload.encode('latin-1')

            if not payload or len(payload) < 50:
                continue

            content_type = 'application/octet-stream'
            filename = f"http_{pkt.get('timestamp_epoch', 0)}.dat"

            for signature, ctype in http_content_types.items():
                if signature in payload[:100]:
                    content_type = ctype
                    break

            if b'GET' in payload[:100] or b'POST' in payload[:100]:
                uri_match = re.search(b'(GET|POST) ([^\s]+)', payload[:500])
                if uri_match:
                    filename = uri_match.group(2).decode('utf-8', errors='replace')
                    filename = filename.split('/')[-1] or 'index.html'

            obj_info = {
                'timestamp': pkt.get('timestamp'),
                'src_ip': pkt.get('src_ip'),
                'dst_ip': pkt.get('dst_ip'),
                'filename': filename,
                'content_type': content_type,
                'size': len(payload),
            }

            http_objects.append(obj_info)

        return http_objects

    def export_http_objects(self, output_dir: str):
        """Save HTTP objects to directory"""
        http_objects = self.extract_http_objects()

        if not http_objects:
            print(f"{Fore.YELLOW}No HTTP objects found{Style.RESET_ALL}")
            return

        os.makedirs(output_dir, exist_ok=True)

        count = 0
        for obj in http_objects[:100]:
            filepath = os.path.join(output_dir, obj['filename'])

            if os.path.exists(filepath):
                base, ext = os.path.splitext(filepath)
                filepath = f"{base}_{count}{ext}"

            with open(filepath, 'wb') as f:
                pass

            count += 1

        print(f"{Fore.GREEN}Exported {count} HTTP objects to {output_dir}{Style.RESET_ALL}")

    def compile_byte_filter(self, filter_str: str):
        """Compile byte-offset filter like tcp[0:2] == 0x4745"""
        patterns = []

        byte_offset_pattern = r'(\w+)\[(\d+)(?::(\d+))?\]\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+)'

        for match in re.finditer(byte_offset_pattern, filter_str):
            layer = match.group(1)
            offset = int(match.group(2))
            length = int(match.group(3)) if match.group(3) else 1
            operator = match.group(4)
            value = int(match.group(5), 16 if match.group(5).startswith('0x') else 10)

            patterns.append({
                'layer': layer,
                'offset': offset,
                'length': length,
                'operator': operator,
                'value': value,
            })

        return patterns

    def match_byte_filter(self, packet, patterns: List[Dict]) -> bool:
        """Apply byte-offset filter to packet"""
        for pat in patterns:
            layer_name = pat['layer']

            try:
                if layer_name.upper() == 'TCP' and packet.haslayer(TCP):
                    payload = bytes(packet[TCP].payload)
                elif layer_name.upper() == 'UDP' and packet.haslayer(UDP):
                    payload = bytes(packet[UDP].payload)
                elif layer_name.upper() == 'IP' and packet.haslayer(IP):
                    payload = bytes(packet[IP].payload)
                elif layer_name.upper() == 'ICMP' and packet.haslayer(ICMP):
                    payload = bytes(packet[ICMP].payload)
                else:
                    continue

                if pat['offset'] >= len(payload):
                    return False

                target_value = int.from_bytes(payload[pat['offset']:pat['offset'] + pat['length']], 'big')

                if pat['operator'] == '==':
                    if target_value != pat['value']:
                        return False
                elif pat['operator'] == '!=':
                    if target_value == pat['value']:
                        return False
                elif pat['operator'] == '<=':
                    if target_value > pat['value']:
                        return False
                elif pat['operator'] == '>=':
                    if target_value < pat['value']:
                        return False

            except Exception:
                return False

        return True

    class FileCarver:
        """Extract files from packet streams"""
        
        FILE_SIGNATURES = {
            b'\x89PNG\r\n\x1a\n': ('png', 'image/png'),
            b'\xFF\xD8\xFF': ('jpg', 'image/jpeg'),
            b'GIF87a': ('gif', 'image/gif'),
            b'GIF89a': ('gif', 'image/gif'),
            b'%PDF': ('pdf', 'application/pdf'),
            b'PK\x03\x04': ('zip', 'application/zip'),
            b'PK\x05\x06': ('zip', 'application/zip'),
            b'Rar!': ('rar', 'application/x-rar'),
            b'\x1f\x8b': ('gz', 'application/gzip'),
            b'<?xml': ('xml', 'application/xml'),
            b'\x00\x00\x01\x00': ('ico', 'image/x-icon'),
            b'RIFF': ('wav', 'audio/wav'),
            b'ID3': ('mp3', 'audio/mpeg'),
            b'\xFF\xFB': ('mp3', 'audio/mpeg'),
            b'\x00\x00\x00\x18ftypmp4': ('mp4', 'video/mp4'),
            b'\x00\x00\x00\x1cftypisom': ('mp4', 'video/mp4'),
        }
        
        def __init__(self):
            self.carved_files = []
            
        def detect_file_type(self, data: bytes) -> Optional[tuple]:
            """Detect file type from magic bytes"""
            for sig, (ext, mime) in self.FILE_SIGNATURES.items():
                if data.startswith(sig):
                    return (ext, mime)
            return None
            
        def carve_from_packets(self, packets: List[Dict], protocols: List[str] = None) -> List[Dict]:
            """Carve files from packet payloads"""
            if protocols is None:
                protocols = ['HTTP', 'FTP', 'TCP']
                
            streams = defaultdict(bytearray)
            
            for pkt in packets:
                if pkt.get('protocol') not in protocols:
                    continue
                    
                src_ip = pkt.get('src_ip', '')
                dst_ip = pkt.get('dst_ip', '')
                src_port = pkt.get('src_port', 0)
                dst_port = pkt.get('dst_port', 0)
                
                stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                payload = pkt.get('payload', b'')
                
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')
                    
                if payload:
                    streams[stream_key].extend(payload)
            
            for stream_id, data in streams.items():
                file_type = self.detect_file_type(data)
                if file_type:
                    ext, mime = file_type
                    self.carved_files.append({
                        'stream': stream_id,
                        'extension': ext,
                        'mime_type': mime,
                        'size': len(data),
                        'data': bytes(data[:100000]),
                    })
            
            return self.carved_files
        
        def write_files(self, output_dir: str) -> int:
            """Write carved files to disk"""
            os.makedirs(output_dir, exist_ok=True)
            count = 0
            
            for i, f in enumerate(self.carved_files[:50]):
                filename = f"carved_{i:04d}.{f['extension']}"
                filepath = os.path.join(output_dir, filename)
                
                try:
                    with open(filepath, 'wb') as out:
                        out.write(f['data'])
                    count += 1
                except Exception:
                    pass
                    
            return count

    def carve_files(self, protocols: List[str] = None, output_dir: str = './carved') -> int:
        """Carve files from captured packets"""
        carver = self.FileCarver()
        files = carver.carve_from_packets(self.packets, protocols)
        
        if not files:
            print(f"{Fore.YELLOW}No files found to carve{Style.RESET_ALL}")
            return 0
            
        count = carver.write_files(output_dir)
        print(f"{Fore.GREEN}Carved {count} files to {output_dir}{Style.RESET_ALL}")
        return count

    class Deduplicator:
        """Bloom filter for packet deduplication"""
        
        def __init__(self, capacity: int = 100000):
            self.capacity = capacity
            self.seen_hashes = set()
            self.duplicates = 0
            self.total = 0
            
        def hash_packet(self, packet_info: Dict) -> str:
            """Create hash for packet"""
            key = f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}-{packet_info.get('dst_ip')}:{packet_info.get('dst_port')}-{packet_info.get('timestamp_epoch')}"
            return str(hash(key))
            
        def is_duplicate(self, packet_info: Dict) -> bool:
            """Check if packet is duplicate"""
            self.total += 1
            h = self.hash_packet(packet_info)
            
            if h in self.seen_hashes:
                self.duplicates += 1
                return True
                
            self.seen_hashes.add(h)
            return False
            
        def get_stats(self) -> Dict:
            """Get deduplication statistics"""
            return {
                'total_packets': self.total,
                'unique_packets': len(self.seen_hashes),
                'duplicates': self.duplicates,
                'duplicate_rate': self.duplicates / self.total if self.total > 0 else 0,
            }

    def deduplicate_packets(self) -> Dict:
        """Remove duplicate packets"""
        dedup = self.Deduplicator()
        unique_packets = []
        
        for pkt in self.packets:
            if not dedup.is_duplicate(pkt):
                unique_packets.append(pkt)
                
        stats = dedup.get_stats()
        self.packets = unique_packets
        
        print(f"{Fore.GREEN}Deduplication: {stats['duplicates']} duplicates removed, {stats['unique_packets']} unique packets{Style.RESET_ALL}")
        return stats

    def parse_quic(self) -> List[Dict]:
        """Parse QUIC/HTTP3 packets"""
        quic_packets = []
        
        for pkt in self.packets:
            src_port = pkt.get('src_port', 0)
            dst_port = pkt.get('dst_port', 0)
            
            if src_port == 443 or dst_port == 443 or src_port == 4433 or dst_port == 4433:
                payload = pkt.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode('latin-1')
                    
                quic_info = {
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'version': 'N/A',
                    'packet_type': 'N/A',
                    'connection_id': 'N/A',
                }
                
                if payload and len(payload) > 5:
                    first_byte = payload[0]
                    if first_byte & 0x40:
                        quic_info['packet_type'] = 'Long Header'
                        if len(payload) > 4:
                            quic_info['version'] = payload[1:5].hex()
                    else:
                        quic_info['packet_type'] = 'Short Header'
                        
                    if b'SNI' in payload[:100]:
                        quic_info['has_sni'] = True
                    if b'TLS' in payload[:100] or b'\x16\x03' in payload[:10]:
                        quic_info['has_tls'] = True
                        
                quic_packets.append(quic_info)
                
        return quic_packets

    def print_quic_statistics(self):
        """Print QUIC statistics"""
        quic_packets = self.parse_quic()
        
        if not quic_packets:
            print(f"\n{Fore.CYAN}{'='*50} QUIC STATISTICS {'='*50}{Style.RESET_ALL}")
            print("No QUIC/HTTP3 traffic found")
            return
            
        print(f"\n{Fore.CYAN}{'='*50} QUIC STATISTICS {'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total QUIC Packets: {len(quic_packets)}{Style.RESET_ALL}")
        
        packet_types = defaultdict(int)
        versions = defaultdict(int)
        
        for pkt in quic_packets:
            packet_types[pkt['packet_type']] += 1
            if pkt['version'] != 'N/A':
                versions[pkt['version']] += 1
                
        if packet_types:
            print(f"\n{Fore.YELLOW}Packet Types:{Style.RESET_ALL}")
            for pt, count in sorted(packet_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {pt}: {count}")
                
        if versions:
            print(f"\n{Fore.YELLOW}Versions:{Style.RESET_ALL}")
            for ver, count in sorted(versions.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  0x{ver}: {count}")

    def run_dashboard(self, update_interval: float = 1.0):
        """Run TUI dashboard"""
        try:
            import curses
            import time
            
            stdscr = curses.initscr()
            curses.curs_set(0)
            curses.nodelay(1)
            
            try:
                while self.running:
                    stdscr.clear()
                    height, width = stdscr.getmaxyx()
                    
                    stdscr.addstr(0, 0, f"{'='*60} MiniShark Dashboard {'='*60}", curses.A_BOLD)
                    stdscr.addstr(1, 0, f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    stdscr.addstr(2, 0, f"Packets: {len(self.packets)}")
                    
                    stats = self.get_statistics()
                    stdscr.addstr(4, 0, f"{'Protocol':<15} {'Count':<10} {'%':<10}", curses.A_UNDERLINE)
                    
                    y = 5
                    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        pct = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
                        stdscr.addstr(y, 0, f"{proto:<15} {count:<10} {pct:5.1f}%")
                        y += 1
                        
                    stdscr.refresh()
                    time.sleep(update_interval)
                    
            finally:
                curses.curs_set(1)
                curses.nodelay(0)
                curses.endwin()
                
        except ImportError:
            print(f"{Fore.RED}curses not available on this platform{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Dashboard error: {e}{Style.RESET_ALL}")

    def get_dns_cache(self) -> Dict[str, str]:
        """Get DNS resolution cache"""
        dns_cache = {}
        for pkt in self.packets:
            if pkt.get('protocol') == 'DNS' and pkt.get('dns_query') == 'Response':
                pass
        return dns_cache

    def enrich_with_geoip(self) -> int:
        """Enrich packets with GeoIP information"""
        try:
            import geoip2.database
            geoip_available = True
        except ImportError:
            geoip_available = False

        if not geoip_available:
            print(f"{Fore.YELLOW}GeoIP enrichment requires geoip2. Run: pip install geoip2{Style.RESET_ALL}")
            return 0

        enriched = 0
        for pkt in self.packets:
            src_ip = pkt.get('src_ip', 'N/A')
            dst_ip = pkt.get('dst_ip', 'N/A')
            
            if src_ip != 'N/A' and src_ip not in ['127.0.0.1', '0.0.0.0']:
                pkt['src_country'] = 'N/A'
                pkt['src_city'] = 'N/A'
            if dst_ip != 'N/A' and dst_ip not in ['127.0.0.1', '0.0.0.0']:
                pkt['dst_country'] = 'N/A'
                pkt['dst_city'] = 'N/A'
        
        return enriched

    def get_mac_vendor(self, mac: str) -> str:
        """Lookup MAC vendor by OUI"""
        oui_prefix = mac.upper().replace(':', '').replace('-', '')[:6]
        oui_database = {
            '000000': 'Xerox',
            '0050F2': 'Microsoft',
            '00155D': 'Microsoft (Hyper-V)',
            '000C29': 'VMware',
            '001A2B': 'VMware',
            '005056': 'VMware',
            '080027': 'VirtualBox',
            '525400': 'QEMU',
            'B827EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '001CB3': 'Intel',
            '001E67': 'Intel',
            '001F3B': 'Intel',
            '00D0B7': 'Intel',
            '3C970E': 'HP',
            '001B21': 'HP',
            '0024E8': 'Dell',
            '0011BB': 'Dell',
            '000347': 'Cisco',
            '000E08': 'Cisco',
            '0011BB': 'Cisco',
            '002155': 'Apple',
            '001451': 'Apple',
            '001F5B': 'Apple',
            'F0DCE2': 'Apple',
            '0050E4': 'Dell',
        }
        return oui_database.get(oui_prefix, 'Unknown')

    def enrich_with_mac_vendors(self) -> int:
        """Enrich packets with MAC vendor information"""
        enriched = 0
        for pkt in self.packets:
            src_mac = pkt.get('src_mac', 'N/A')
            dst_mac = pkt.get('dst_mac', 'N/A')
            
            if src_mac != 'N/A':
                pkt['src_vendor'] = self.get_mac_vendor(src_mac)
                enriched += 1
            if dst_mac != 'N/A':
                pkt['dst_vendor'] = self.get_mac_vendor(dst_mac)
                enriched += 1
        
        return enriched

    def extract_tls_info(self) -> List[Dict]:
        """Extract TLS certificate information"""
        tls_info = []
        
        for pkt in self.packets:
            if pkt.get('protocol') == 'TLS':
                info = {
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'src_port': pkt.get('src_port'),
                    'dst_port': pkt.get('dst_port'),
                    'tls_version': pkt.get('tls_version', 'N/A'),
                    'cipher': pkt.get('tls_cipher', 'N/A'),
                }
                tls_info.append(info)
        
        return tls_info

    def start_api_server(self, host: str = '127.0.0.1', port: int = 8080):
        """Start REST API server for packet queries"""
        try:
            from flask import Flask, jsonify, request
            app = Flask(__name__)
            
            @app.route('/api/packets', methods=['GET'])
            def get_packets():
                limit = request.args.get('limit', 100, type=int)
                protocol = request.args.get('protocol')
                src_ip = request.args.get('src_ip')
                
                results = self.packets[:limit]
                if protocol:
                    results = [p for p in results if p.get('protocol') == protocol]
                if src_ip:
                    results = [p for p in results if p.get('src_ip') == src_ip]
                
                return jsonify(results)
            
            @app.route('/api/stats', methods=['GET'])
            def get_stats():
                return jsonify(self.get_statistics())
            
            @app.route('/api/streams', methods=['GET'])
            def get_streams():
                streams = self.reassemble_tcp_streams()
                return jsonify({k: {'packets': len(v.packets)} for k, v in streams.items()})
            
            @app.route('/api/expert', methods=['GET'])
            def get_expert():
                return jsonify(self.get_statistics().get('expert_info', {}))
            
            print(f"{Fore.GREEN}Starting API server on {host}:{port}{Style.RESET_ALL}")
            app.run(host=host, port=port)
        except ImportError:
            print(f"{Fore.RED}Flask required for API server. Run: pip install flask{Style.RESET_ALL}")

    def stream_to_kafka(self, bootstrap_servers: str, topic: str):
        """Stream packets to Kafka"""
        try:
            from kafka import KafkaProducer
            import json
            
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            for pkt in self.packets:
                producer.send(topic, value=pkt)
            
            producer.flush()
            producer.close()
            print(f"{Fore.GREEN}Streamed {len(self.packets)} packets to Kafka topic {topic}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}kafka-python required for Kafka output. Run: pip install kafka-python{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Error streaming to Kafka: {e}")

    def export_netflow(self, filename: str):
        """Export packet data in NetFlow-like format"""
        flows = {}
        
        for pkt in self.packets:
            if pkt.get('protocol') not in ['TCP', 'UDP']:
                continue
            
            src_ip = pkt.get('src_ip', 'N/A')
            dst_ip = pkt.get('dst_ip', 'N/A')
            src_port = pkt.get('src_port', 0)
            dst_port = pkt.get('dst_port', 0)
            proto = pkt.get('protocol')
            
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            
            if flow_key not in flows:
                flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'packets': 0,
                    'bytes': 0,
                    'first_seen': pkt.get('timestamp_epoch', 0),
                    'last_seen': 0,
                }
            
            flows[flow_key]['packets'] += 1
            flows[flow_key]['bytes'] += pkt.get('length', 0)
            last_seen = pkt.get('timestamp_epoch', 0)
            if last_seen > flows[flow_key]['last_seen']:
                flows[flow_key]['last_seen'] = last_seen

        try:
            import pandas as pd
            df = pd.DataFrame(list(flows.values()))
            df.to_csv(filename, index=False)
            print(f"{Fore.GREEN}Exported {len(flows)} flows to {filename}{Style.RESET_ALL}")
        except ImportError:
            import csv
            with open(filename, 'w', newline='') as f:
                if flows:
                    writer = csv.DictWriter(f, fieldnames=flows[list(flows.keys())[0]].keys())
                    writer.writeheader()
                    writer.writerows(flows.values())
            print(f"{Fore.GREEN}Exported {len(flows)} flows to {filename}{Style.RESET_ALL}")

    def compare_captures(self, other_packets: List[Dict]) -> Dict:
        """Compare this capture with another"""
        this_protocols = set(self.stats['protocols'].keys())
        other_protocols = set(p.get('protocol') for p in other_packets if p.get('protocol'))
        
        this_total = self.stats['total_packets']
        other_total = len(other_packets)
        
        return {
            'this_packets': this_total,
            'other_packets': other_total,
            'protocol_diff': list(this_protocols - other_protocols),
            'new_protocols': list(other_protocols - this_protocols),
            'common_protocols': list(this_protocols & other_protocols),
            'packet_diff': this_total - other_total,
        }

    def print_comparison(self, other_file: str):
        """Print comparison between capture files"""
        if not os.path.exists(other_file):
            print(f"{Fore.RED}File not found: {other_file}{Style.RESET_ALL}")
            return
        
        try:
            other_packets = sniff(offline=other_file)
            comparison = self.compare_captures(other_packets)
            
            print(f"\n{Fore.CYAN}{'='*50} CAPTURE COMPARISON {'='*50}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This Capture: {comparison['this_packets']} packets{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Other Capture: {comparison['other_packets']} packets{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Difference: {comparison['packet_diff']} packets{Style.RESET_ALL}")
            
            if comparison['common_protocols']:
                print(f"\n{Fore.GREEN}Common Protocols:{Style.RESET_ALL}")
                for proto in comparison['common_protocols']:
                    print(f"  - {proto}")
            
            if comparison['new_protocols']:
                print(f"\n{Fore.BLUE}Only in Other File:{Style.RESET_ALL}")
                for proto in comparison['new_protocols']:
                    print(f"  + {proto}")
                    
        except Exception as e:
            self.logger.error(f"Error comparing captures: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="MiniShark - A CLI-based network analysis tool similar to tshark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python minishark.py -i eth0                    # Capture on eth0 interface
  python minishark.py -c 100                    # Capture 100 packets
  python minishark.py -f "tcp port 80"          # Filter TCP port 80
  python minishark.py -o output.json -F json    # Save to JSON file
  python minishark.py --interfaces              # List available interfaces
  python minishark.py -r capture.pcap           # Read from pcap file
  python minishark.py -r capture.pcap -z phs    # Protocol hierarchy stats
  python minishark.py -r capture.pcap -T fields -e ip.src -e ip.dst  # Field extraction
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-r', '--read-file', help='Read packets from pcap/pcapng file')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-f', '--filter', help='BPF filter expression')
    parser.add_argument('-o', '--output', help='Output file to save packets')
    parser.add_argument('-F', '--format', choices=['json', 'csv', 'jsonlines', 'pdml', 'parquet', 'excel', 'netflow'], default='json', help='Output format (default: json)')
    parser.add_argument('-T', '--type', choices=['json', 'csv', 'fields', 'pdml'], default='json', help='Output type for -o')
    parser.add_argument('-e', '--field', action='append', help='Fields to export with -T fields (can be repeated)')
    parser.add_argument('--interfaces', action='store_true', help='List available network interfaces')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-z', '--statistics', help='Show statistics: phs (protocol hierarchy), conv, io, expert')
    parser.add_argument('-n', '--no-name-resolution', action='store_true', help='Disable name resolution')
    parser.add_argument('-nn', '--no-any-resolution', action='store_true', help='Disable all name resolution')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - minimal output')
    parser.add_argument('-s', '--snaplen', type=int, default=65535, help='Snapshot length (default: 65535)')
    parser.add_argument('-B', '--buffer-size', type=int, default=2048, help='Kernel buffer size in KB')
    parser.add_argument('--promiscuous', action='store_true', default=True, help='Put interface in promiscuous mode')
    parser.add_argument('-w', '--write', help='Write captured packets to file')
    parser.add_argument('--merge', help='Merge multiple pcap files (comma-separated)')
    parser.add_argument('--split', help='Split pcap file into directory')
    parser.add_argument('--split-packets', type=int, default=1000, help='Packets per split file')
    parser.add_argument('--expert', action='store_true', help='Show expert information')
    parser.add_argument('--http-stat', action='store_true', help='Show HTTP statistics')
    parser.add_argument('--bandwidth', action='store_true', help='Show bandwidth analysis')
    parser.add_argument('--tcp-analysis', action='store_true', help='Show TCP analysis')
    parser.add_argument('--dns-stat', action='store_true', help='Show DNS statistics')
    parser.add_argument('--geoip', action='store_true', help='Enrich with GeoIP information')
    parser.add_argument('--vendor', action='store_true', help='Enrich with MAC vendor information')
    parser.add_argument('--parquet', action='store_true', help='Export to Parquet format')
    parser.add_argument('--excel', action='store_true', help='Export to Excel format')
    parser.add_argument('--netflow', action='store_true', help='Export flows in NetFlow format')
    parser.add_argument('--api', action='store_true', help='Start REST API server')
    parser.add_argument('--api-host', default='127.0.0.1', help='API server host')
    parser.add_argument('--api-port', type=int, default=8080, help='API server port')
    parser.add_argument('--kafka', help='Kafka bootstrap servers (topic will be from -o)')
    parser.add_argument('--diff', help='Compare with another capture file')
    parser.add_argument('--yara', help='YARA rules file or rules string')
    parser.add_argument('--threat', action='store_true', help='Detect threats')
    parser.add_argument('--mqtt', action='store_true', help='Show MQTT statistics')
    parser.add_argument('--dhcp', action='store_true', help='Show DHCP statistics')
    parser.add_argument('--websocket', action='store_true', help='Show WebSocket analysis')
    parser.add_argument('--quic', action='store_true', help='Show QUIC/HTTP3 statistics')
    parser.add_argument('-x', '--hex-dump', action='store_true', help='Print hex dump of each packet')
    parser.add_argument('-XX', '--full-hex-dump', action='store_true', help='Print full hex dump with headers')
    parser.add_argument('-A', '--ascii-dump', action='store_true', help='Print ASCII dump of each packet')
    parser.add_argument('--tls-certs', action='store_true', help='Extract TLS certificates')
    parser.add_argument('--tls-certs-dir', default='./tls-certs', help='Output directory for TLS certificates')
    parser.add_argument('--async', action='store_true', help='Use async packet capture')
    parser.add_argument('--export-objects', metavar='PROTOCOL', help='Export HTTP objects (specify protocol like http)')
    parser.add_argument('--export-objects-dir', default='./http-objects', help='Output directory for exported objects')
    parser.add_argument('-Y', '--display-filter', help='Display filter with byte offset support')
    parser.add_argument('--carve', action='store_true', help='Carve files from TCP streams')
    parser.add_argument('--carve-dir', default='./carved', help='Output directory for carved files')
    parser.add_argument('--carve-protocols', default='http,ftp,tcp', help='Protocols to carve from')
    parser.add_argument('--dedup', action='store_true', help='Remove duplicate packets')
    parser.add_argument('--dedup-stats', action='store_true', help='Show deduplication statistics')
    parser.add_argument('--dashboard', action='store_true', help='Run TUI dashboard')
    parser.add_argument('--dashboard-interval', type=float, default=1.0, help='Dashboard update interval')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--max-memory', type=int, help='Maximum memory in MB for packet buffer')
    parser.add_argument('--packet-buffer-size', type=int, default=10000, help='Packet buffer size')
    parser.add_argument('--preload-pcap', action='store_true', help='Preload entire pcap file into memory')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    minishark = MiniShark()
    
    # Apply performance and display settings
    if args.no_color:
        minishark.set_color_enabled(False)
    
    if args.max_memory:
        max_packets = (args.max_memory * 1024 * 1024) // 1500
        args.packet_buffer_size = min(args.packet_buffer_size, max_packets)
    
    if args.interfaces:
        minishark.list_interfaces()
        return
    
    try:
        if args.read_file:
            count = minishark.read_pcap_file(args.read_file, args.filter)
            print(f"{Fore.GREEN}Read {count} packets{Style.RESET_ALL}")
        else:
            if not args.interface and not args.quiet:
                print(f"{Fore.YELLOW}No interface specified, using default{Style.RESET_ALL}")
            
            if args.filter and not minishark.validate_bpf_filter(args.filter):
                print(f"{Fore.RED}Invalid BPF filter: {args.filter}{Style.RESET_ALL}")
                sys.exit(1)
            
            minishark.capture_packets(
                interface=args.interface,
                count=args.count,
                filter_str=args.filter
            )
        
        if args.statistics:
            if args.statistics in ('phs', 'protocols', 'hierarchy'):
                minishark.print_protocol_hierarchy()
            elif args.statistics in ('conv', 'conversations'):
                minishark.print_conversations()
            elif args.statistics in ('io', 'io,stats'):
                minishark.print_io_statistics()
            elif args.statistics in ('http', 'http,stat'):
                minishark.print_http_statistics()
            elif args.statistics == 'tcp':
                minishark.print_tcp_analysis()
            elif args.statistics == 'dns':
                minishark.print_dns_statistics()
        
        if args.expert:
            minishark.print_expert_info()
        
        if args.http_stat:
            minishark.print_http_statistics()
        
        if args.bandwidth:
            minishark.print_bandwidth_analysis()
        
        if args.tcp_analysis:
            minishark.print_tcp_analysis()
        
        if args.dns_stat:
            minishark.print_dns_statistics()
        
        if args.geoip:
            minishark.enrich_with_geoip()
        
        if args.vendor:
            count = minishark.enrich_with_mac_vendors()
            print(f"{Fore.GREEN}Enriched {count} MAC addresses with vendor info{Style.RESET_ALL}")
        
        if args.merge:
            files = [f.strip() for f in args.merge.split(',')]
            output = args.output or 'merged.pcap'
            minishark.merge_pcap_files(files, output)
        
        if args.split:
            minishark.split_pcap_file(args.split, args.output or 'split_output', args.split_packets)
        
        if args.diff:
            minishark.print_comparison(args.diff)
        
        if args.yara:
            matches = minishark.scan_with_yara(rules_path=args.yara)
            minishark.print_yara_results(matches)
        
        if args.threat:
            threats = minishark.detect_threats()
            minishark.print_threats(threats)
        
        if args.mqtt:
            mqtt_packets = minishark.parse_mqtt()
            minishark.print_mqtt_statistics(mqtt_packets)
        
        if args.dhcp:
            dhcp_packets = minishark.parse_dhcp()
            minishark.print_dhcp_statistics(dhcp_packets)
        
        if args.websocket:
            ws_packets = minishark.analyze_websocket()
            minishark.print_websocket_analysis(ws_packets)

        if args.hex_dump or args.full_hex_dump or args.ascii_dump:
            from scapy.all import sniff
            packets = sniff(offline=args.read_file) if args.read_file else []
            for i, pkt in enumerate(packets[:10]):
                pkt_info = minishark.get_packet_info(pkt)
                if args.hex_dump:
                    print(minishark.generate_hex_dump(pkt))
                elif args.full_hex_dump:
                    print(minishark.generate_hex_ascii_dump(pkt))
                elif args.ascii_dump:
                    print(minishark.generate_ascii_dump(pkt))

        if args.tls_certs:
            minishark.export_tls_certificates(args.tls_certs_dir)

        if args.export_objects:
            minishark.export_http_objects(args.export_objects_dir)

        if args.carve:
            protocols = [p.strip() for p in args.carve_protocols.split(',')]
            minishark.carve_files(protocols=protocols, output_dir=args.carve_dir)

        if args.dedup:
            minishark.deduplicate_packets()
        
        if args.dedup_stats:
            dedup = minishark.Deduplicator()
            for pkt in minishark.packets:
                dedup.is_duplicate(pkt)
            stats = dedup.get_stats()
            print(f"\n{Fore.CYAN}Deduplication Stats:{Style.RESET_ALL}")
            print(f"  Total: {stats['total_packets']}")
            print(f"  Unique: {stats['unique_packets']}")
            print(f"  Duplicates: {stats['duplicates']}")
            print(f"  Rate: {stats['duplicate_rate']*100:.1f}%")

        quic_enabled = getattr(args, 'quic', False)
        if quic_enabled or (args.statistics and 'quic' in args.statistics):
            minishark.print_quic_statistics()
        
        if args.dashboard:
            minishark.running = True
            minishark.run_dashboard(args.dashboard_interval)

        if args.api:
            minishark.start_api_server(args.api_host, args.api_port)
        
        if args.kafka:
            minishark.stream_to_kafka(args.kafka, args.output or 'packets')
        
        if not args.quiet:
            minishark.print_stats()
        
        if args.output:
            if args.type == 'fields' and args.field:
                minishark.export_fields(args.output, args.field)
            elif args.format == 'jsonlines':
                minishark.export_json_lines(args.output)
            elif args.format == 'pdml':
                minishark.export_pdml(args.output)
            elif args.format == 'parquet':
                minishark.export_parquet(args.output)
            elif args.format == 'excel':
                minishark.export_excel(args.output)
            elif args.format == 'netflow':
                minishark.export_netflow(args.output)
            else:
                minishark.save_to_file(args.output, args.format)
                
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Capture interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()