// Educational Packet Sniffer - Frontend JavaScript

class PacketSniffer {
    constructor() {
        this.socket = null;
        this.packets = [];
        this.captureActive = false;
        this.displayPaused = false;
        this.packetCount = 0;
        
        this.initializeElements();
        this.initializeSocket();
        this.bindEvents();
        this.loadInterfaces();
        
        // Show ethical use reminder on load
        this.showEthicalReminder();
    }
    
    initializeElements() {
        // Control elements
        this.startBtn = document.getElementById('start-capture');
        this.stopBtn = document.getElementById('stop-capture');
        this.clearBtn = document.getElementById('clear-packets');
        this.pauseBtn = document.getElementById('pause-display');
        this.exportBtn = document.getElementById('export-packets');
        this.refreshBtn = document.getElementById('refresh-interfaces');
        
        // Input elements
        this.interfaceSelect = document.getElementById('interface-select');
        this.filterInput = document.getElementById('packet-filter');
        
        // Status elements
        this.captureStatus = document.getElementById('capture-status');
        this.packetCountEl = document.getElementById('packet-count');
        this.connectionStatus = document.getElementById('connection-status');
        
        // Table elements
        this.packetTable = document.getElementById('packet-table');
        this.packetTbody = document.getElementById('packet-tbody');
        
        // Modal elements
        this.modal = document.getElementById('packet-modal');
        this.modalClose = document.querySelector('.close');
        this.basicInfo = document.getElementById('basic-info');
        this.payloadPreview = document.getElementById('payload-preview');
    }
    
    initializeSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.updateConnectionStatus(true);
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.updateConnectionStatus(false);
        });
        
        this.socket.on('new_packet', (packet) => {
            this.handleNewPacket(packet);
        });
        
        this.socket.on('status', (status) => {
            this.captureActive = status.capture_active;
            this.packetCount = status.packet_count;
            this.updateUI();
        });
        
        this.socket.on('capture_error', (error) => {
            this.showError('Capture Error: ' + error.error);
            this.captureActive = false;
            this.updateUI();
        });
    }
    
    bindEvents() {
        // Control buttons
        this.startBtn.addEventListener('click', () => this.startCapture());
        this.stopBtn.addEventListener('click', () => this.stopCapture());
        this.clearBtn.addEventListener('click', () => this.clearPackets());
        this.pauseBtn.addEventListener('click', () => this.togglePause());
        this.exportBtn.addEventListener('click', () => this.exportPackets());
        this.refreshBtn.addEventListener('click', () => this.loadInterfaces());
        
        // Modal events
        this.modalClose.addEventListener('click', () => this.closeModal());
        window.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.closeModal();
            }
        });
        
        // Table row click events
        this.packetTbody.addEventListener('click', (e) => {
            const row = e.target.closest('tr');
            if (row) {
                const packetId = parseInt(row.dataset.packetId);
                this.showPacketDetails(packetId);
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 's':
                        e.preventDefault();
                        if (this.captureActive) {
                            this.stopCapture();
                        } else {
                            this.startCapture();
                        }
                        break;
                    case 'c':
                        e.preventDefault();
                        this.clearPackets();
                        break;
                    case 'p':
                        e.preventDefault();
                        this.togglePause();
                        break;
                }
            }
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }
    
    async loadInterfaces() {
        try {
            const response = await fetch('/get_interfaces');
            const data = await response.json();
            
            if (data.interfaces) {
                this.interfaceSelect.innerHTML = '<option value="">Default Interface</option>';
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    this.interfaceSelect.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Failed to load interfaces:', error);
            this.showError('Failed to load network interfaces');
        }
    }
    
    async startCapture() {
        const interface = this.interfaceSelect.value;
        const filter = this.filterInput.value.trim();
        
        try {
            const response = await fetch('/start_capture', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    interface: interface,
                    filter: filter
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.captureActive = true;
                this.updateUI();
                this.showSuccess('Packet capture started successfully');
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Failed to start capture: ' + error.message);
        }
    }
    
    async stopCapture() {
        try {
            const response = await fetch('/stop_capture', {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.captureActive = false;
                this.updateUI();
                this.showSuccess('Packet capture stopped');
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Failed to stop capture: ' + error.message);
        }
    }
    
    async clearPackets() {
        try {
            const response = await fetch('/clear_packets', {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.packets = [];
                this.packetCount = 0;
                this.packetTbody.innerHTML = '';
                this.updateUI();
                this.showSuccess('Packets cleared');
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Failed to clear packets: ' + error.message);
        }
    }
    
    togglePause() {
        this.displayPaused = !this.displayPaused;
        this.pauseBtn.innerHTML = this.displayPaused ? 
            '<i class="fas fa-play"></i> Resume Display' : 
            '<i class="fas fa-pause"></i> Pause Display';
        
        if (this.displayPaused) {
            this.pauseBtn.classList.remove('btn-secondary');
            this.pauseBtn.classList.add('btn-warning');
        } else {
            this.pauseBtn.classList.remove('btn-warning');
            this.pauseBtn.classList.add('btn-secondary');
        }
    }
    
    handleNewPacket(packet) {
        this.packets.push(packet);
        this.packetCount = packet.id;
        
        // Keep only last 1000 packets in memory
        if (this.packets.length > 1000) {
            this.packets.shift();
        }
        
        if (!this.displayPaused) {
            this.addPacketToTable(packet);
        }
        
        this.updateUI();
    }
    
    addPacketToTable(packet) {
        const row = document.createElement('tr');
        row.dataset.packetId = packet.id;
        row.className = 'packet-row-new';
        
        const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
        
        row.innerHTML = `
            <td>${packet.id}</td>
            <td>${packet.timestamp}</td>
            <td class="${protocolClass}">${packet.protocol}</td>
            <td>${packet.src_ip}</td>
            <td>${packet.src_port}</td>
            <td>${packet.dst_ip}</td>
            <td>${packet.dst_port}</td>
            <td>${packet.length}</td>
            <td>${packet.flags}</td>
            <td>${packet.info}</td>
        `;
        
        // Add to top of table
        this.packetTbody.insertBefore(row, this.packetTbody.firstChild);
        
        // Remove old rows to maintain performance
        while (this.packetTbody.children.length > 500) {
            this.packetTbody.removeChild(this.packetTbody.lastChild);
        }
        
        // Auto-scroll to top
        const container = document.querySelector('.packet-table-container');
        container.scrollTop = 0;
    }
    
    showPacketDetails(packetId) {
        const packet = this.packets.find(p => p.id === packetId);
        if (!packet) return;
        
        // Basic info
        this.basicInfo.innerHTML = `
            <strong>Packet ID:</strong> ${packet.id}<br>
            <strong>Timestamp:</strong> ${packet.timestamp}<br>
            <strong>Protocol:</strong> ${packet.protocol}<br>
            <strong>Source:</strong> ${packet.src_ip}:${packet.src_port}<br>
            <strong>Destination:</strong> ${packet.dst_ip}:${packet.dst_port}<br>
            <strong>Length:</strong> ${packet.length} bytes<br>
            <strong>Flags:</strong> ${packet.flags}<br>
            <strong>Info:</strong> ${packet.info}
        `;
        
        // Payload preview
        this.payloadPreview.textContent = packet.payload_preview || 'No payload data available';
        
        this.modal.style.display = 'block';
    }
    
    closeModal() {
        this.modal.style.display = 'none';
    }
    
    exportPackets() {
        if (this.packets.length === 0) {
            this.showError('No packets to export');
            return;
        }
        
        const headers = ['ID', 'Timestamp', 'Protocol', 'Source IP', 'Source Port', 
                        'Destination IP', 'Destination Port', 'Length', 'Flags', 'Info'];
        
        let csv = headers.join(',') + '\n';
        
        this.packets.forEach(packet => {
            const row = [
                packet.id,
                `"${packet.timestamp}"`,
                packet.protocol,
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
                packet.length,
                `"${packet.flags}"`,
                `"${packet.info}"`
            ];
            csv += row.join(',') + '\n';
        });
        
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `packets_${new Date().getTime()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        this.showSuccess('Packets exported successfully');
    }
    
    updateUI() {
        // Update capture status
        this.captureStatus.textContent = this.captureActive ? 'Active' : 'Inactive';
        this.captureStatus.className = this.captureActive ? 'status-active' : 'status-inactive';
        
        // Update packet count
        this.packetCountEl.textContent = this.packetCount;
        
        // Update button states
        this.startBtn.disabled = this.captureActive;
        this.stopBtn.disabled = !this.captureActive;
    }
    
    updateConnectionStatus(connected) {
        this.connectionStatus.textContent = connected ? 'Connected' : 'Disconnected';
        this.connectionStatus.className = connected ? 'status-active' : 'status-inactive';
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success');
    }
    
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
            ${message}
        `;
        
        // Add styles
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '15px 20px',
            borderRadius: '8px',
            color: 'white',
            backgroundColor: type === 'success' ? '#27ae60' : '#e74c3c',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            zIndex: '10000',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            maxWidth: '400px',
            fontSize: '14px',
            fontWeight: '500'
        });
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
        
        // Click to dismiss
        notification.addEventListener('click', () => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        });
    }
    
    showEthicalReminder() {
        // Show ethical use reminder dialog
        setTimeout(() => {
            const reminder = document.createElement('div');
            reminder.innerHTML = `
                <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                           background: rgba(0,0,0,0.8); z-index: 10001; display: flex; 
                           align-items: center; justify-content: center;">
                    <div style="background: white; padding: 30px; border-radius: 10px; 
                               max-width: 500px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                        <h3 style="color: #e74c3c; margin-bottom: 20px;">
                            <i class="fas fa-shield-alt"></i> Ethical Use Reminder
                        </h3>
                        <p style="margin-bottom: 20px; line-height: 1.6;">
                            This packet sniffer is for <strong>educational purposes only</strong>.
                            <br><br>
                            By using this tool, you agree to:
                            <br>• Only monitor networks you own
                            <br>• Obtain explicit permission before use
                            <br>• Respect privacy and legal boundaries
                            <br>• Use for learning purposes only
                        </p>
                        <button onclick="this.parentElement.parentElement.remove()" 
                                style="background: #3498db; color: white; border: none; 
                                       padding: 12px 24px; border-radius: 6px; cursor: pointer; 
                                       font-weight: 600;">
                            I Understand and Agree
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(reminder);
        }, 1000);
    }
}

// Initialize the packet sniffer when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PacketSniffer();
});

// Add some global utility functions
window.formatBytes = function(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

window.formatTime = function(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
};