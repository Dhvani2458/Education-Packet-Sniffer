from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import time
import json
from datetime import datetime
import socket
import struct

app = Flask(__name__)

# Global variables to store packet data
captured_packets = []
is_capturing = False
capture_thread = None
packet_count = 0
MAX_PACKETS = 1000  # Limit to prevent memory issues

# Ethical usage banner
ETHICAL_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                    ETHICAL USAGE NOTICE                      ║
║                                                              ║
║  This packet sniffer is for EDUCATIONAL PURPOSES ONLY        ║
║                                                              ║
║  ⚠️  LEGAL REQUIREMENTS:                                    ║
║  • Only use on networks you own                              ║
║  • Obtain explicit written permission before monitoring      ║
║  • Comply with local laws and regulations                    ║
║  • Respect privacy and confidentiality                       ║
║                                                              ║
║  ⚠️  PROHIBITED USES:                                       ║ 
║  • Unauthorized network monitoring                           ║
║  • Intercepting private communications                       ║
║  • Any malicious or illegal activities                       ║
║                                                              ║
║  By using this tool, you agree to use it responsibly         ║
║  and in accordance with applicable laws.                     ║
╚══════════════════════════════════════════════════════════════╝
"""

def get_protocol_name(protocol_num):
    """Convert protocol number to human-readable name"""
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    return protocols.get(protocol_num, f'Protocol-{protocol_num}')

def extract_payload_preview(packet):
    """Extract and sanitize payload data for preview"""
    if Raw in packet:
        payload = bytes(packet[Raw])
        # Only show printable characters and limit length
        preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:50])
        return preview if preview else '[Binary Data]'
    return '[No Payload]'

def get_service_name(port, protocol):
    """Get common service name for port"""
    services = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 587: 'SMTP-TLS'
    }
    return services.get(port, f'{protocol}-{port}')

def packet_handler(packet):
    """Handle captured packets"""
    global captured_packets, packet_count
    
    if packet_count >= MAX_PACKETS:
        return
    
    if IP in packet:
        packet_info = {
            'id': packet_count,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': get_protocol_name(packet[IP].proto),
            'length': len(packet),
            'ttl': packet[IP].ttl,
            'payload_preview': extract_payload_preview(packet),
            'flags': []
        }
        
        # Add protocol-specific information
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info.update({
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'service': get_service_name(tcp_layer.dport, 'TCP'),
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack,
                'window': tcp_layer.window
            })
            
            # TCP flags
            flags = []
            if tcp_layer.flags & 0x01: flags.append('FIN')
            if tcp_layer.flags & 0x02: flags.append('SYN')
            if tcp_layer.flags & 0x04: flags.append('RST')
            if tcp_layer.flags & 0x08: flags.append('PSH')
            if tcp_layer.flags & 0x10: flags.append('ACK')
            if tcp_layer.flags & 0x20: flags.append('URG')
            packet_info['flags'] = flags
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info.update({
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'service': get_service_name(udp_layer.dport, 'UDP'),
                'udp_length': udp_layer.len
            })
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_info.update({
                'icmp_type': icmp_layer.type,
                'icmp_code': icmp_layer.code,
                'service': f'ICMP-{icmp_layer.type}'
            })
        
        captured_packets.append(packet_info)
        packet_count += 1

def start_capture(interface=None, filter_str=None):
    """Start packet capture in a separate thread"""
    global is_capturing, capture_thread
    
    if is_capturing:
        return False
    
    is_capturing = True
    
    def capture_packets():
        try:
            print(f"Starting packet capture on interface: {interface or 'default'}")
            if filter_str:
                print(f"Using filter: {filter_str}")
            
            sniff(
                iface=interface,
                prn=packet_handler,
                filter=filter_str,
                stop_filter=lambda x: not is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
            stop_capture()
    
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    return True

def stop_capture():
    """Stop packet capture"""
    global is_capturing
    is_capturing = False

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/start_capture', methods=['POST'])
def api_start_capture():
    """API endpoint to start capture"""
    data = request.get_json() or {}
    interface = data.get('interface')
    filter_str = data.get('filter', '')
    
    success = start_capture(interface, filter_str)
    return jsonify({
        'success': success,
        'message': 'Capture started' if success else 'Capture already running'
    })

@app.route('/api/stop_capture', methods=['POST'])
def api_stop_capture():
    """API endpoint to stop capture"""
    stop_capture()
    return jsonify({'success': True, 'message': 'Capture stopped'})

@app.route('/api/packets')
def api_packets():
    """Get captured packets"""
    return jsonify({
        'packets': captured_packets[-100:],  # Return last 100 packets
        'total_count': len(captured_packets),
        'is_capturing': is_capturing
    })

@app.route('/api/clear_packets', methods=['POST'])
def api_clear_packets():
    """Clear captured packets"""
    global captured_packets, packet_count
    captured_packets.clear()
    packet_count = 0
    return jsonify({'success': True, 'message': 'Packets cleared'})

@app.route('/api/status')
def api_status():
    """Get capture status"""
    return jsonify({
        'is_capturing': is_capturing,
        'packet_count': len(captured_packets)
    })

# HTML Template (inline for simplicity)
@app.route('/template')
def get_template():
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Educational Packet Sniffer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #1a1a1a; 
            color: #00ff00; 
            line-height: 1.4; 
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            background: #000; 
            padding: 20px; 
            border: 2px solid #00ff00; 
            margin-bottom: 20px; 
            border-radius: 5px;
        }
        .controls { 
            background: #2a2a2a; 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 5px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        .controls input, .controls button { 
            padding: 8px 12px; 
            background: #000; 
            color: #00ff00; 
            border: 1px solid #00ff00; 
            border-radius: 3px;
        }
        .controls button { cursor: pointer; }
        .controls button:hover { background: #00ff00; color: #000; }
        .controls button:disabled { opacity: 0.5; cursor: not-allowed; }
        .status { 
            background: #2a2a2a; 
            padding: 10px; 
            margin-bottom: 20px; 
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-indicator { 
            padding: 5px 10px; 
            border-radius: 3px; 
            font-weight: bold;
        }
        .status-capturing { background: #ff4444; }
        .status-stopped { background: #444; }
        .packet-table { 
            background: #2a2a2a; 
            border-radius: 5px; 
            overflow: hidden;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
        }
        th, td { 
            padding: 8px; 
            text-align: left; 
            border-bottom: 1px solid #444; 
            font-size: 12px;
        }
        th { 
            background: #000; 
            position: sticky; 
            top: 0; 
            z-index: 10;
        }
        tr:hover { background: #3a3a3a; }
        .protocol-tcp { color: #ff6b6b; }
        .protocol-udp { color: #4ecdc4; }
        .protocol-icmp { color: #ffe66d; }
        .flags { font-size: 10px; }
        .payload { 
            max-width: 200px; 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap;
            font-family: monospace;
        }
        .warning { 
            background: #ff4444; 
            color: white; 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 5px; 
            text-align: center;
        }
        .scroll-container { 
            max-height: 600px; 
            overflow-y: auto; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Educational Packet Sniffer</h1>
            <p>Network Analysis Tool for Learning Purposes</p>
        </div>
        
        <div class="warning">
            ⚠️ <strong>EDUCATIONAL USE ONLY</strong> - Ensure you have permission to monitor this network
        </div>
        
        <div class="controls">
            <input type="text" id="interface" placeholder="Interface (e.g., eth0, wlan0)" />
            <input type="text" id="filter" placeholder="BPF Filter (e.g., tcp port 80)" />
            <button id="startBtn" onclick="startCapture()">Start Capture</button>
            <button id="stopBtn" onclick="stopCapture()" disabled>Stop Capture</button>
            <button onclick="clearPackets()">Clear Packets</button>
        </div>
        
        <div class="status">
            <div>
                Status: <span id="status" class="status-indicator status-stopped">STOPPED</span>
            </div>
            <div>
                Packets Captured: <span id="packetCount">0</span>
            </div>
        </div>
        
        <div class="packet-table">
            <div class="scroll-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Dest IP</th>
                            <th>Protocol</th>
                            <th>Src Port</th>
                            <th>Dst Port</th>
                            <th>Service</th>
                            <th>Flags</th>
                            <th>Length</th>
                            <th>Payload Preview</th>
                        </tr>
                    </thead>
                    <tbody id="packetTableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let capturing = false;
        let updateInterval;

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const statusEl = document.getElementById('status');
                    const countEl = document.getElementById('packetCount');
                    
                    if (data.is_capturing) {
                        statusEl.textContent = 'CAPTURING';
                        statusEl.className = 'status-indicator status-capturing';
                    } else {
                        statusEl.textContent = 'STOPPED';
                        statusEl.className = 'status-indicator status-stopped';
                    }
                    
                    countEl.textContent = data.packet_count;
                    capturing = data.is_capturing;
                    
                    document.getElementById('startBtn').disabled = capturing;
                    document.getElementById('stopBtn').disabled = !capturing;
                });
        }

        function updatePackets() {
            fetch('/api/packets')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('packetTableBody');
                    tbody.innerHTML = '';
                    
                    data.packets.forEach(packet => {
                        const row = document.createElement('tr');
                        const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
                        
                        row.innerHTML = `
                            <td>${packet.id}</td>
                            <td>${packet.timestamp}</td>
                            <td>${packet.src_ip}</td>
                            <td>${packet.dst_ip}</td>
                            <td class="${protocolClass}">${packet.protocol}</td>
                            <td>${packet.src_port || '-'}</td>
                            <td>${packet.dst_port || '-'}</td>
                            <td>${packet.service || '-'}</td>
                            <td class="flags">${packet.flags ? packet.flags.join(',') : '-'}</td>
                            <td>${packet.length}</td>
                            <td class="payload">${packet.payload_preview}</td>
                        `;
                        tbody.appendChild(row);
                    });
                });
        }

        function startCapture() {
            const interface = document.getElementById('interface').value;
            const filter = document.getElementById('filter').value;
            
            fetch('/api/start_capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface, filter })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateInterval = setInterval(updatePackets, 1000);
                }
            });
        }

        function stopCapture() {
            fetch('/api/stop_capture', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (updateInterval) {
                        clearInterval(updateInterval);
                    }
                });
        }

        function clearPackets() {
            fetch('/api/clear_packets', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    updatePackets();
                });
        }

        // Update status every 2 seconds
        setInterval(updateStatus, 2000);
        updateStatus();
        updatePackets();
    </script>
</body>
</html>
    '''

# Create the template directory and file
import os
if not os.path.exists('templates'):
    os.makedirs('templates')

with open('templates/index.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Educational Packet Sniffer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #1a1a1a; 
            color: #00ff00; 
            line-height: 1.4; 
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            background: #000; 
            padding: 20px; 
            border: 2px solid #00ff00; 
            margin-bottom: 20px; 
            border-radius: 5px;
        }
        .controls { 
            background: #2a2a2a; 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 5px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        .controls input, .controls button { 
            padding: 8px 12px; 
            background: #000; 
            color: #00ff00; 
            border: 1px solid #00ff00; 
            border-radius: 3px;
        }
        .controls button { cursor: pointer; }
        .controls button:hover { background: #00ff00; color: #000; }
        .controls button:disabled { opacity: 0.5; cursor: not-allowed; }
        .status { 
            background: #2a2a2a; 
            padding: 10px; 
            margin-bottom: 20px; 
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-indicator { 
            padding: 5px 10px; 
            border-radius: 3px; 
            font-weight: bold;
        }
        .status-capturing { background: #ff4444; }
        .status-stopped { background: #444; }
        .packet-table { 
            background: #2a2a2a; 
            border-radius: 5px; 
            overflow: hidden;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
        }
        th, td { 
            padding: 8px; 
            text-align: left; 
            border-bottom: 1px solid #444; 
            font-size: 12px;
        }
        th { 
            background: #000; 
            position: sticky; 
            top: 0; 
            z-index: 10;
        }
        tr:hover { background: #3a3a3a; }
        .protocol-tcp { color: #ff6b6b; }
        .protocol-udp { color: #4ecdc4; }
        .protocol-icmp { color: #ffe66d; }
        .flags { font-size: 10px; }
        .payload { 
            max-width: 200px; 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap;
            font-family: monospace;
        }
        .warning { 
            background: #ff4444; 
            color: white; 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 5px; 
            text-align: center;
        }
        .scroll-container { 
            max-height: 600px; 
            overflow-y: auto; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Educational Packet Sniffer</h1>
            <p>Network Analysis Tool for Learning Purposes</p>
        </div>
        
        <div class="warning">
            ⚠️ <strong>EDUCATIONAL USE ONLY</strong> - Ensure you have permission to monitor this network
        </div>
        
        <div class="controls">
            <input type="text" id="interface" placeholder="Interface (e.g., eth0, wlan0)" />
            <input type="text" id="filter" placeholder="BPF Filter (e.g., tcp port 80)" />
            <button id="startBtn" onclick="startCapture()">Start Capture</button>
            <button id="stopBtn" onclick="stopCapture()" disabled>Stop Capture</button>
            <button onclick="clearPackets()">Clear Packets</button>
        </div>
        
        <div class="status">
            <div>
                Status: <span id="status" class="status-indicator status-stopped">STOPPED</span>
            </div>
            <div>
                Packets Captured: <span id="packetCount">0</span>
            </div>
        </div>
        
        <div class="packet-table">
            <div class="scroll-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Dest IP</th>
                            <th>Protocol</th>
                            <th>Src Port</th>
                            <th>Dst Port</th>
                            <th>Service</th>
                            <th>Flags</th>
                            <th>Length</th>
                            <th>Payload Preview</th>
                        </tr>
                    </thead>
                    <tbody id="packetTableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let capturing = false;
        let updateInterval;

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const statusEl = document.getElementById('status');
                    const countEl = document.getElementById('packetCount');
                    
                    if (data.is_capturing) {
                        statusEl.textContent = 'CAPTURING';
                        statusEl.className = 'status-indicator status-capturing';
                    } else {
                        statusEl.textContent = 'STOPPED';
                        statusEl.className = 'status-indicator status-stopped';
                    }
                    
                    countEl.textContent = data.packet_count;
                    capturing = data.is_capturing;
                    
                    document.getElementById('startBtn').disabled = capturing;
                    document.getElementById('stopBtn').disabled = !capturing;
                });
        }

        function updatePackets() {
            fetch('/api/packets')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('packetTableBody');
                    tbody.innerHTML = '';
                    
                    data.packets.forEach(packet => {
                        const row = document.createElement('tr');
                        const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
                        
                        row.innerHTML = `
                            <td>${packet.id}</td>
                            <td>${packet.timestamp}</td>
                            <td>${packet.src_ip}</td>
                            <td>${packet.dst_ip}</td>
                            <td class="${protocolClass}">${packet.protocol}</td>
                            <td>${packet.src_port || '-'}</td>
                            <td>${packet.dst_port || '-'}</td>
                            <td>${packet.service || '-'}</td>
                            <td class="flags">${packet.flags ? packet.flags.join(',') : '-'}</td>
                            <td>${packet.length}</td>
                            <td class="payload">${packet.payload_preview}</td>
                        `;
                        tbody.appendChild(row);
                    });
                });
        }

        function startCapture() {
            const interface = document.getElementById('interface').value;
            const filter = document.getElementById('filter').value;
            
            fetch('/api/start_capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface, filter })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateInterval = setInterval(updatePackets, 1000);
                }
            });
        }

        function stopCapture() {
            fetch('/api/stop_capture', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (updateInterval) {
                        clearInterval(updateInterval);
                    }
                });
        }

        function clearPackets() {
            fetch('/api/clear_packets', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    updatePackets();
                });
        }

        // Update status every 2 seconds
        setInterval(updateStatus, 2000);
        updateStatus();
        updatePackets();
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    print(ETHICAL_BANNER)
    print("\n🚀 Starting Educational Packet Sniffer...")
    print("📋 Requirements:")
    print("   • Run with sudo/administrator privileges")
    print("   • Install dependencies: pip install flask scapy")
    print("   • Use only on networks you own or have permission to monitor")
    print("\n🌐 Access the web interface at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n👋 Shutting down packet sniffer...")
        stop_capture()