import sys
import socket
import psutil
import netifaces
import threading
import subprocess
import wmi
import nmap
from scapy.all import arping
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QTableWidget, QAbstractItemView, QHeaderView, QTableWidgetItem, 
    QProgressBar, QStatusBar, QMessageBox, QInputDialog, QFileDialog, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

class NetworkManager(QMainWindow):
    scan_complete = pyqtSignal()  # Emits when the scan is complete
    device_found = pyqtSignal(str, str, str)  # Emits (IP, MAC, Hostname)
    update_status_signal = pyqtSignal(str, int)  # Emits status message and duration for statusBar update

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Network Manager Pro')
        self.setGeometry(100, 100, 1000, 600)

        # Data members
        self.connected_devices = {}
        self.scanning = False
        self.max_workers = 10
        self.nm = nmap.PortScanner()

        # Signal connections
        self.device_found.connect(self.add_device_to_table)
        self.scan_complete.connect(self.on_scan_complete)
        self.update_status_signal.connect(self.update_status_bar)  # Connect the new signal for updating the status bar

        # Initialize UI
        self.initUI()

    def initUI(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()

        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel('Network Interface:')
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        refresh_button = QPushButton('Refresh Interfaces')
        refresh_button.clicked.connect(self.refresh_interfaces)

        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addWidget(refresh_button)
        layout.addLayout(interface_layout)

        # Device table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            'IP Address', 'MAC Address', 'Hostname', 'Device Type', 'Status', 'Bandwidth Limit'
        ])
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
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
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFont(QFont('Arial', 10))
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Set the status bar (Corrected)
        self.setStatusBar(QStatusBar(self))

        main_widget.setLayout(layout)

    def refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        self.interface_combo.clear()
        interfaces = self.get_interfaces()
        if not interfaces:
            self.update_status_signal.emit('No active network interfaces found.', 3000)
        else:
            # Display interface name and corresponding IP address
            self.interface_combo.addItems([f"{iface[0]} ({iface[1]})" for iface in interfaces])
            self.statusBar().showMessage('Interfaces refreshed', 3000)

    def get_interfaces(self):
        """Retrieve all available network interfaces."""
        interfaces = []
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    interfaces.append((iface, ip))  # Store tuple of interface name and IP address
        except Exception as e:
            self.statusBar().showMessage(f'Error getting interfaces: {str(e)}', 3000)
        return interfaces

    def scan_network(self):
        """Scan the selected network for devices."""
        if self.scanning:
            self.scanning = False
            self.scan_button.setText('Scan Network')
            self.progress_bar.hide()
            return

        self.scanning = True
        self.scan_button.setText('Stop Scan')
        self.update_status_signal.emit('Scanning network...', 0)  # Emit signal to update status bar
        self.device_table.setRowCount(0)
        self.progress_bar.setMaximum(0)
        self.progress_bar.show()

        # Extract the selected interface (format is now 'interface_name (ip_address)')
        selected_interface = self.interface_combo.currentText()
        interface_name = selected_interface.split(' (')[0]  # Get the interface name
        try:
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                network = ip.rsplit('.', 1)[0] + '.0/24'

                # Run scan in a separate thread
                threading.Thread(target=self._perform_scan, args=(network, interface_name)).start()
            else:
                self.update_status_signal.emit('No IPv4 address found for the selected interface.', 3000)
        except Exception as e:
            self.update_status_signal.emit(f'Error starting scan: {str(e)}', 3000)

    def _perform_scan(self, network, interface):
        """Perform the actual network scan."""
        try:
            answered, _ = arping(network, timeout=1, verbose=False, iface=interface)
            for _, received in answered:
                if not self.scanning:
                    return
                ip, mac = received.psrc, received.hwsrc
                if ip not in self.connected_devices:
                    self.connected_devices[ip] = True
                    self.device_found.emit(ip, mac, "Unknown")
        except Exception as e:
            self.update_status_signal.emit(f'Scan error: {str(e)}', 3000)
        finally:
            self.scan_complete.emit()

    def add_device_to_table(self, ip, mac, hostname):
        """Add a device to the table."""
        row_position = self.device_table.rowCount()
        self.device_table.insertRow(row_position)
        items = [
            QTableWidgetItem(ip),
            QTableWidgetItem(mac),
            QTableWidgetItem(hostname),
            QTableWidgetItem("Unknown Device"),
            QTableWidgetItem('Connected'),
            QTableWidgetItem('No limit'),
        ]
        for col, item in enumerate(items):
            self.device_table.setItem(row_position, col, item)

    def set_bandwidth_limit(self):
        """Set bandwidth limit for a selected device."""
        # Implementation...

    def block_device(self):
        """Block or unblock a selected device."""
        # Implementation...

    def export_devices(self):
        """Export the list of devices to a CSV file."""
        # Implementation...

    def on_scan_complete(self):
        """Handle actions when the scan is complete."""
        self.scanning = False
        self.progress_bar.hide()
        self.scan_button.setText('Scan Network')
        self.update_status_signal.emit('Scan completed.', 3000)  # Emit signal for scan completion

    def update_status_bar(self, message, duration):
        """Safely update the status bar from a background thread."""
        self.statusBar().showMessage(message, duration)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    ex = NetworkManager()
    ex.show()
    sys.exit(app.exec_())
