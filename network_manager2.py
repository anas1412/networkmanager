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
                
                hostname = "Unknown"
                if ip not in self.connected_devices:
                    self.connected_devices[ip] = True
                    self.device_found.emit(ip, mac, hostname)
        except Exception as e:
            self.statusBar.showMessage(f'Scan error: {str(e)}')
        finally:
            if all(thread.done() for thread in self.scan_threads):
                self.scan_complete.emit()

    def add_device_to_table(self, ip, mac, hostname):
        row_position = self.device_table.rowCount()
        self.device_table.insertRow(row_position)
        
        items = [
            QTableWidgetItem(ip),
            QTableWidgetItem(mac),
            QTableWidgetItem(hostname),
            QTableWidgetItem("Unknown Device"),
            QTableWidgetItem('Connected'),
            QTableWidgetItem('No limit')
        ]
        
        for col, item in enumerate(items):
            self.device_table.setItem(row_position, col, item)
    
    def set_bandwidth_limit(self):
        selected_rows = self.device_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, 'Selection Required', 'Please select a device first.')
            return

        row = self.device_table.currentRow()
        ip = self.device_table.item(row, 0).text()
        
        limit, ok = QInputDialog.getInt(self, 'Set Bandwidth Limit', 
                                        f'Set bandwidth limit for {ip} (in kbps):', min=1)
        if ok:
            self.device_table.setItem(row, 5, QTableWidgetItem(f'{limit} kbps'))
            self.statusBar.showMessage(f'Bandwidth limit set for {ip} to {limit} kbps')
            # Add your logic to apply the bandwidth limit, such as interacting with QoS settings.

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

    def block_ip(self, ip):
        try:
            unblock_commands = [
                f'netsh advfirewall firewall add rule name="BLOCK_IN_{ip}" dir=in action=block protocol=any remoteip={ip}',
                f'netsh advfirewall firewall add rule name="BLOCK_OUT_{ip}" dir=out action=block protocol=any remoteip={ip}',
            ]
            for cmd in unblock_commands:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            self.statusBar.showMessage(f'Error blocking IP: {e.output.decode()}')

    def unblock_ip(self, ip):
        try:
            unblock_commands = [
                f'netsh advfirewall firewall delete rule name="BLOCK_IN_{ip}"',
                f'netsh advfirewall firewall delete rule name="BLOCK_OUT_{ip}"',
            ]
            for cmd in unblock_commands:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            self.statusBar.showMessage(f'Error unblocking IP: {e.output.decode()}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    ex = NetworkManager()
    ex.show()
    sys.exit(app.exec_())
