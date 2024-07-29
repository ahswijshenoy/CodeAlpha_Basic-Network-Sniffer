## Python Network Sniffer
This Python project provides a basic network sniffer that captures and analyzes network traffic using the Scapy library. The application features a graphical user interface (GUI) built with Tkinter, allowing users to start and stop the sniffing process and view the traffic details in real-time.

# Features
1.**Real-time Traffic Monitoring:** Capture live network traffic and display packet details.

2.**Support for Common Protocols:** Recognizes TCP, UDP, and other protocols.

3.**GUI Control:** Start and stop the packet capture through an intuitive GUI interface.

4.**Detailed Packet Information:** Displays timestamp, source IP, destination IP, protocol type, and payload summary.

# How It Works

The network sniffer uses Scapy, a powerful Python library, to capture packets flowing through the network interface. It then analyzes the packets, extracts essential information, and displays it in the GUI. The tool can be useful for network debugging and educational purposes to understand how data flows in a network.

# Prerequisites
Before running the network sniffer, ensure you have the following installed:
- Python 3.x
- Scapy
- Tkinter (usually included with Python)

# Installation
**Clone the repository:**
git clone https://github.com/ahswijshenoy/python-network-sniffer.git
**Navigate to the directory:**
cd python-network-sniffer

# Usage
To run the sniffer, execute the following command in the terminal:
python network_sniffer.py
The GUI will open with two buttons: "Start Sniffer" and "Stop Sniffer." Click "Start Sniffer" to begin capturing network traffic and "Stop Sniffer" to halt the capture. Captured packet details will be displayed in the scrolling text area.

# GUI Overview
- **Start/Stop Buttons:** Control the packet capturing process.
- **Text Area:** Displays detailed information about each packet in real-time.

# Contributing
Contributions to this project are welcome. If you have suggestions or improvements, please fork the repository and submit a pull request.

# License
This project is licensed under the MIT License - see the LICENSE.md file for details.
