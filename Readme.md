Network Manager Pro
Overview

Network Manager Pro is a Python-based GUI application for managing and monitoring network devices. It provides powerful features such as network scanning, device blocking, bandwidth limiting, and exporting device data. The tool is built with PyQt5 and utilizes various libraries for network operations.
Features

    Network Scanning: Identify devices connected to your network with detailed information, including IP addresses, MAC addresses, hostnames, and device types.
    Bandwidth Limiting: Set bandwidth limits for selected devices to control network usage.
    Device Blocking: Block devices from accessing the network using firewall rules.
    Interface Management: View and refresh available network interfaces.
    Device Exporting: Export device details to a CSV file for documentation or further analysis.

Prerequisites

Before using Network Manager Pro, ensure you have the following installed:

    Python 3.8 or later
    Required Python libraries:
        PyQt5
        scapy
        nmap
        psutil
        netifaces
        wmi

To install the libraries, run:

pip install PyQt5 scapy python-nmap psutil netifaces wmi

Installation

    Clone the repository:

    git clone https://github.com/yourusername/network-manager-pro.git
    cd network-manager-pro

    Install the dependencies as listed in the prerequisites.

Usage

    Run the application:

    python network_manager_pro.py

    The GUI will launch. You can:
        Select a network interface from the dropdown menu.
        Click Scan Network to detect connected devices.
        Use buttons to block/unblock devices or set bandwidth limits.
        Export the scanned device list as a CSV file.

Key Components

    Network Scanning: Utilizes ARP and Nmap to identify devices on the network.
    Hostname Retrieval: Uses various methods (DNS, NetBIOS, mDNS, WMI) for enhanced accuracy.
    Device Blocking: Implements Windows Firewall rules to block devices.
    Bandwidth Limiting: Applies QoS policies to manage bandwidth usage.

Screenshots

Add screenshots here if available.
Contributing

Contributions are welcome! Follow these steps to contribute:

    Fork the repository.
    Create a new branch:

git checkout -b feature-name

Make your changes and commit:

git commit -m "Add feature-name"

Push the changes to your fork:

    git push origin feature-name

    Create a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.