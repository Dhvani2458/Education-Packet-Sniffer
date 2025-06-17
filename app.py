#!/usr/bin/env python3
"""
Educational Packet Sniffer Tool
ETHICAL USE ONLY - For learning network protocols and security concepts
Only use on networks you own or have explicit permission to monitor

Required: pip install flask scapy flask-socketio
Note: May require root/admin privileges to capture packets
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import threading
import time
import json
from datetime import datetime
import socket
import os
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet_sniffer_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables for packet capture control
capture_active = False
capture_thread = None
packet_count = 0
captured_packets = []

# Ethical use banner
ETHICAL_BANNER = """
========================================================
EDUCATIONAL PACKET SNIFFER TOOL
========================================================
⚠️  ETHICAL USE ONLY ⚠️

This tool is for educational purposes only:
• Only use on networks you own
• Only use with explicit written permission
• Respect privacy and legal boundaries
• Use for learning network protocols and security

Unauthorized network monitoring may violate laws.
By using this tool, you agree to use it responsibly.
========================================================
"""

def print_banner():
    print(ETHICAL_BANNER)

def get_protocol_name(packet):
    """Extract protocol name from packet"""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    else:
        return "OTHER"

def get_port_info(packet):
    """Extract port information"""
    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    return src_port, dst_port

def get_payload_preview(packet, max_length=100):
    """Extract and preview payload data"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            # Try to decode as text
            text_payload = payload.decode('utf-8', errors='ignore')
            # Remove non-printable characters
            text_payload = ''.join(char if char.isprintable() else '.' for char in text_payload)
            return text_payload[:max_length] + ("..." if len(text_payload) > max_length else "")
        except:
            # Return hex representation if text decoding fails
            hex_payload = payload.hex()
            return hex_payload[:max_length] + ("..." if len(hex_payload) > max_length else "")
    return ""

def packet_handler(packet):
    """Process captured packets"""
    global packet_count, captured_packets
    
    if not capture_active:
        return
    
    packet_count += 1
    
    # Extract basic packet information
    packet_info = {
        'id': packet_count,
        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'protocol': get_protocol_name(packet),
        'length': len(packet),
        'src_ip': '',
        'dst_ip': '',
        'src_port': '',
        'dst_port': '',
        'payload_preview': '',
        'flags': '',
        'info': ''
    }
    
    # Extract IP layer information
    if packet.haslayer(IP):
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        
        # Get port information
        src_port, dst_port = get_port_info(packet)
        if src_port:
            packet_info['src_port'] = str(src_port)
        if dst_port:
            packet_info['dst_port'] = str(dst_port)
        
        # Get payload preview
        packet_info['payload_preview'] = get_payload_preview(packet)
        
        # TCP specific information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = []
            if tcp_layer.flags.S: flags.append('SYN')
            if tcp_layer.flags.A: flags.append('ACK')
            if tcp_layer.flags.F: flags.append('FIN')
            if tcp_layer.flags.R: flags.append('RST')
            if tcp_layer.flags.P: flags.append('PSH')
            if tcp_layer.flags.U: flags.append('URG')
            packet_info['flags'] = ','.join(flags)
            
            # Common port identification
            port_services = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                23: 'Telnet', 25: 'SMTP', 53: 'DNS', 110: 'POP3',
                143: 'IMAP', 993: 'IMAPS', 995: 'POP3S'
            }
            if dst_port in port_services:
                packet_info['info'] = port_services[dst_port]
    
    # ARP specific information
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        packet_info['src_ip'] = arp_layer.psrc
        packet_info['dst_ip'] = arp_layer.pdst
        packet_info['info'] = f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
    
    # Store packet (keep only last 1000 packets to manage memory)
    captured_packets.append(packet_info)
    if len(captured_packets) > 1000:
        captured_packets.pop(0)
    
    # Emit packet to connected clients
    socketio.emit('new_packet', packet_info)

def start_packet_capture(interface=None, filter_str=""):
    """Start packet capture in a separate thread"""
    global capture_active
    
    try:
        capture_active = True
        print(f"Starting packet capture on interface: {interface or 'default'}")
        print(f"Filter: {filter_str or 'none'}")
        
        # Start sniffing
        sniff(
            iface=interface,
            prn=packet_handler,
            filter=filter_str if filter_str else None,
            stop_filter=lambda x: not capture_active,
            store=0  # Don't store packets in memory (we handle them in packet_handler)
        )
    except Exception as e:
        print(f"Error during packet capture: {e}")
        capture_active = False
        socketio.emit('capture_error', {'error': str(e)})

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_active, capture_thread, packet_count, captured_packets
    
    if capture_active:
        return jsonify({'error': 'Capture already running'}), 400
    
    data = request.get_json()
    interface = data.get('interface', '')
    filter_str = data.get('filter', '')
    
    # Reset counters
    packet_count = 0
    captured_packets = []
    
    # Start capture thread
    capture_thread = threading.Thread(
        target=start_packet_capture,
        args=(interface if interface else None, filter_str)
    )
    capture_thread.daemon = True
    capture_thread.start()
    
    return jsonify({'message': 'Capture started successfully'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global capture_active
    
    if not capture_active:
        return jsonify({'error': 'No capture running'}), 400
    
    capture_active = False
    return jsonify({'message': 'Capture stopped successfully'})

@app.route('/get_packets')
def get_packets():
    """Get captured packets"""
    return jsonify({
        'packets': captured_packets,
        'total_count': packet_count,
        'capture_active': capture_active
    })

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    """Clear captured packets"""
    global captured_packets, packet_count
    captured_packets = []
    packet_count = 0
    return jsonify({'message': 'Packets cleared successfully'})

@app.route('/get_interfaces')
def get_interfaces():
    """Get available network interfaces"""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('status', {'capture_active': capture_active, 'packet_count': packet_count})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

def is_admin():
    try:
        return os.getuid() == 0  # Unix/Linux
    except AttributeError:
        # Windows check
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

if __name__ == '__main__':
    print_banner()
    
    # Check if running as root/admin (required for packet capture)
    if not is_admin():
        print("\n⚠️  WARNING: This tool may require root/administrator privileges to capture packets.")
        print("   → On Linux/Mac: Try running with sudo → sudo python app.py")
        print("   → On Windows: Run Command Prompt as Administrator\n")
    
    print("Starting Packet Sniffer Web Interface...")
    print("Access the tool at: http://localhost:5000")
    print("\nRemember: Use this tool ethically and only on networks you own!")

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)