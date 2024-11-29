import sys
import socket
import psutil
import netifaces
import threading
import subprocess
import wmi
import nmap
import winreg
from scapy.all import *
from scapy.layers.l2 import arping
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class NetworkManager(QMainWindow):
    scan_complete = pyqtSignal()
    device_found = pyqtSignal(str, str, str)
    
    def __init__(self):
        super().__init__()
        self.title = 'Network Manager Pro'
        self.connected_devices = {}
        self.scanning = False
        self.scan_threads = []
        self.max_workers = 10
        self.nm = nmap.PortScanner()
        self.initUI()
        self.device_found.connect(self.add_device_to_table)
        self.scan_complete.connect(self.on_scan_complete)
        
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(100, 100, 1000, 600)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel('Network Interface:')
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_interfaces())
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        
        refresh_button = QPushButton('Refresh Interfaces')
        refresh_button.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_button)
        
        layout.addLayout(interface_layout)
        
        # Device table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            'IP Address', 'MAC Address', 'Hostname', 
            'Device Type', 'Status', 'Bandwidth Limit'
        ])
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.device_table)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('Scan Network')
        self.scan_button.clicked.connect(self.scan_network)
        
        limit_button = QPushButton('Set Bandwidth Limit')
        limit_button.clicked.connect(self.set_bandwidth_limit)
        
        block_button = QPushButton('Block Device')
        block_button.clicked.connect(self.block_device)
        
        export_button = QPushButton('Export Devices')
        export_button.clicked.connect(self.export_devices)
        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(limit_button)
        button_layout.addWidget(block_button)
        button_layout.addWidget(export_button)
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        main_widget.setLayout(layout)

    def get_interfaces(self):
        interfaces = []
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    interfaces.append(iface)
        except Exception as e:
            self.statusBar.showMessage(f'Error getting interfaces: {str(e)}')
        return interfaces

    def refresh_interfaces(self):
        self.interface_combo.clear()
        self.interface_combo.addItems(self.get_interfaces())
        self.statusBar.showMessage('Interfaces refreshed')

    def get_hostname_advanced(self, ip):
        hostname = "Unknown"
        methods = [
            self._dns_lookup,
            self._netbios_lookup,
            self._nmap_lookup,
            self._wmi_lookup,
            self._mdns_lookup
        ]
        
        for method in methods:
            try:
                result = method(ip)
                if result and result != "Unknown":
                    hostname = result
                    break
            except:
                continue
                
        return hostname
        
    def _dns_lookup(self, ip):
        return socket.gethostbyaddr(ip)[0]
        
    def _netbios_lookup(self, ip):
        try:
            cmd = f"nbtstat -A {ip}"
            output = subprocess.check_output(cmd, shell=True, timeout=2).decode('utf-8')
            for line in output.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    return line.split()[0].strip()
        except:
            pass
        return None
        
    def _nmap_lookup(self, ip):
        try:
            result = self.nm.scan(ip, arguments='-sn -R')
            if 'hostnames' in result['scan'][ip]:
                return result['scan'][ip]['hostnames'][0]['name']
        except:
            pass
        return None
        
    def _wmi_lookup(self, ip):
        try:
            c = wmi.WMI(ip)
            system = c.Win32_ComputerSystem()[0]
            return system.Name
        except:
            pass
        return None
        
    def _mdns_lookup(self, ip):
        try:
            cmd = f"dns-sd -Q {ip}"
            output = subprocess.check_output(cmd, shell=True, timeout=2).decode('utf-8')
            if output:
                return output.split()[0]
        except:
            pass
        return None

    def scan_network(self):
        if self.scanning:
            self.scanning = False
            for thread in self.scan_threads:
                thread.join(timeout=1)
            self.scan_button.setText('Scan Network')
            return

        self.scanning = True
        self.scan_button.setText('Stop Scan')
        self.statusBar.showMessage('Scanning network...')
        self.device_table.setRowCount(0)
        self.progress_bar.setMaximum(0)
        self.progress_bar.show()

        self.scan_threads = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for interface in self.get_interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        network = ip.rsplit('.', 1)[0] + '.0/24'
                        future = executor.submit(self._perform_scan, network, interface)
                        self.scan_threads.append(future)
                except Exception as e:
                    self.statusBar.showMessage(f'Error scanning interface {interface}: {str(e)}')

    def _perform_scan(self, network, interface):
        try:
            answered, unanswered = arping(network, timeout=1, verbose=False, iface=interface)
            
            for sent, received in answered:
                if not self.scanning:
                    return
                    
                ip = received.psrc
                mac = received.hwsrc
                hostname = self.get_hostname_advanced(ip)
                
                if ip not in self.connected_devices:
                    self.connected_devices[ip] = True
                    self.device_found.emit(ip, mac, hostname)

            common_ports = [80, 443, 22, 445, 3389]
            for ip in [r.psrc for r, _ in answered]:
                if not self.scanning:
                    return
                    
                for port in common_ports:
                    try:
                        syn_scan = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
                        if syn_scan and syn_scan.haslayer(TCP):
                            self.update_device_status(ip, port)
                    except:
                        continue

        except Exception as e:
            self.statusBar.showMessage(f'Scan error: {str(e)}')
        finally:
            if all(thread.done() for thread in self.scan_threads):
                self.scan_complete.emit()

    def update_device_status(self, ip, open_port):
        port_services = {
            80: "Web Server",
            443: "HTTPS Server",
            22: "SSH Server",
            445: "SMB Server",
            3389: "Remote Desktop"
        }
        
        for row in range(self.device_table.rowCount()):
            if self.device_table.item(row, 0).text() == ip:
                current_type = self.device_table.item(row, 3).text()
                service = port_services.get(open_port, "Unknown Service")
                if "Unknown" in current_type:
                    new_type = service
                else:
                    new_type = f"{current_type}, {service}"
                self.device_table.setItem(row, 3, QTableWidgetItem(new_type))
                break

    def add_device_to_table(self, ip, mac, hostname):
        row_position = self.device_table.rowCount()
        self.device_table.insertRow(row_position)
        
        device_type = self.get_device_type(mac)
        
        items = [
            QTableWidgetItem(ip),
            QTableWidgetItem(mac),
            QTableWidgetItem(hostname),
            QTableWidgetItem(device_type),
            QTableWidgetItem('Connected'),
            QTableWidgetItem('No limit')
        ]
        
        for col, item in enumerate(items):
            self.device_table.setItem(row_position, col, item)

    def get_device_type(self, mac):
        mac_prefix = mac[:8].upper()
        known_vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            'DC:A6:32': 'Raspberry Pi',
            '00:0C:29': 'VMware',
            'B8:27:EB': 'Raspberry Pi',
            '00:16:3E': 'Xen Virtual Machine',
            '52:54:00': 'QEMU Virtual NIC'
        }
        return known_vendors.get(mac_prefix, 'Unknown Device')

    def block_ip(self, ip):
        try:
            self.unblock_ip(ip)
            
            block_commands = [
                f'netsh advfirewall firewall add rule name="BLOCK_IN_{ip}" dir=in action=block protocol=any remoteip={ip}',
                f'netsh advfirewall firewall add rule name="BLOCK_OUT_{ip}" dir=out action=block protocol=any remoteip={ip}',
                f'route add {ip} mask 255.255.255.255 0.0.0.0 metric 1'
            ]
            
            for cmd in block_commands:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
            self.verify_blocking(ip)
            self.statusBar.showMessage(f'Successfully blocked {ip}')
            
        except subprocess.CalledProcessError as e:
            self.statusBar.showMessage(f'Error blocking IP: {e.output.decode()}')
            
    def verify_blocking(self, ip):
        try:
            check_cmd = f'netsh advfirewall firewall show rule name="BLOCK_IN_{ip}"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise Exception("Firewall rule verification failed")
                
            ping = subprocess.run(f'ping -n 1 -w 1000 {ip}', shell=True, capture_output=True)
            if ping.returncode == 0:
                raise Exception("IP still accessible after blocking")
                
        except Exception as e:
            self.statusBar.showMessage(f'Block verification failed: {str(e)}')
            
    def unblock_ip(self, ip):
        try:
            unblock_commands = [
                f'netsh advfirewall firewall delete rule name="BLOCK_IN_{ip}"',
                f'netsh advfirewall firewall delete rule name="BLOCK_OUT_{ip}"',
                f'route delete {ip}'
            ]
            
            for cmd in unblock_commands:
                subprocess.run(cmd, shell=True, capture_output=True)
                
            self.statusBar.showMessage(f'Successfully unblocked {ip}')
            
        except subprocess.CalledProcessError as e:
            self.statusBar.showMessage(f'Error unblocking IP: {e.output.decode()}')
            
    def set_bandwidth_limit(self):
        selected_rows = self.device_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, 'Selection Required', 'Please select a device first.')
            return
            
        limit, ok = QInputDialog.getInt(self, 'Set Bandwidth Limit', 
            'Enter bandwidth limit (KB/s):', 1000, 0, 100000, 1)
            
        if ok:
            row = self.device_table.currentRow()
            ip = self.device_table.item(row, 0).text()
            self.device_table.setItem(row, 5, QTableWidgetItem(f'{limit} KB/s'))
            self.apply_bandwidth_limit(ip, limit)

def apply_bandwidth_limit(self, ip, limit_kbps):
    try:
        # Convert to bits per second
        limit_bps = limit_kbps * 8 * 1024
        
        # First ensure running as admin
        if not self.check_admin_privileges():
            self.statusBar.showMessage("Administrator privileges required")
            return False
            
        # Remove any existing rules
        cleanup_commands = [
            f'netsh advfirewall firewall delete rule name="LIMIT_{ip}"',
            f'netsh int ipv4 delete policy name=LIMIT_{ip}',
            f'netsh int ipv4 delete filter name=LIMIT_{ip}'
        ]
        
        # Create new traffic control rules
        tc_commands = [
            # Create QoS policy
            f'netsh int ipv4 set policy name=LIMIT_{ip} new rate={limit_bps} interface=any prio=3',
            
            # Add bidirectional filters
            f'netsh int ipv4 add filter name=LIMIT_{ip}_IN protocol=any srcaddr={ip} qospolicy=LIMIT_{ip}',
            f'netsh int ipv4 add filter name=LIMIT_{ip}_OUT protocol=any dstaddr={ip} qospolicy=LIMIT_{ip}',
            
            # Add supporting firewall rules
            f'netsh advfirewall firewall add rule name="LIMIT_{ip}" dir=in action=allow remoteip={ip} qospolicy=LIMIT_{ip}',
            f'netsh advfirewall firewall add rule name="LIMIT_{ip}" dir=out action=allow remoteip={ip} qospolicy=LIMIT_{ip}'
        ]
        
        # Execute commands
        for cmd in cleanup_commands + tc_commands:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
        # Verify the limit was applied
        if self.verify_bandwidth_limit(ip):
            self.statusBar.showMessage(f'Successfully applied {limit_kbps} KB/s limit to {ip}')
            return True
            
    except subprocess.CalledProcessError as e:
        self.statusBar.showMessage(f'Error setting bandwidth limit: {e.output.decode()}')
        return False

def check_admin_privileges(self):
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

    def verify_bandwidth_limit(self, ip):
        try:
            check_cmd = f'netsh int ipv4 show policy name=LIMIT_{ip}'
            result = subprocess.run(check_cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise Exception("QoS policy verification failed")
                
        except Exception as e:
            self.statusBar.showMessage(f'Bandwidth limit verification failed: {str(e)}')

    def block_device(self):
        selected_rows = self.device_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, 'Selection Required', 'Please select a device first.')
            return
            
        row = self.device_table.currentRow()
        ip = self.device_table.item(row, 0).text()
        current_status = self.device_table.item(row, 4).text()
        
        if current_status == 'Connected':
            self.device_table.setItem(row, 4, QTableWidgetItem('Blocked'))
            self.block_ip(ip)
        else:
            self.device_table.setItem(row, 4, QTableWidgetItem('Connected'))
            self.unblock_ip(ip)

    def export_devices(self):
        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Export Devices", "", 
                "CSV Files (*.csv);;All Files (*)")
            if filename:
                with open(filename, 'w') as f:
                    headers = ['IP Address', 'MAC Address', 'Hostname', 
                             'Device Type', 'Status', 'Bandwidth Limit']
                    f.write(','.join(headers) + '\n')
                    
                    for row in range(self.device_table.rowCount()):
                        row_data = []
                        for col in range(self.device_table.columnCount()):
                            item = self.device_table.item(row, col)
                            row_data.append(item.text() if item else '')
                        f.write(','.join(row_data) + '\n')
                        
                self.statusBar.showMessage(f'Devices exported to {filename}')
        except Exception as e:
            self.statusBar.showMessage(f'Error exporting devices: {str(e)}')

    def on_scan_complete(self):
        self.statusBar.showMessage('Scan completed')
        self.progress_bar.hide()
        self.scan_button.setText('Scan Network')
        self.scanning = False

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    ex = NetworkManager()
    ex.show()
    sys.exit(app.exec_())
