███▄    █ ▓█████▄▄▄█████▓ █     █░ ▄▄▄     ▄▄▄█████▓ ▄████▄   ██░ ██ 
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓█░ █ ░█░▒████▄   ▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒█░ █ ░█ ▒██  ▀█▄ ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░█░ █ ░█ ░██▄▄▄▄██░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██ 
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░░██▒██▓  ▓█   ▓██▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓

# NetWatch

NetWatch is a lightweight, terminal-based local network discovery and reconnaissance tool written in Python. It scans your local subnet using ARP requests, resolves hostnames, identifies device manufacturers via MAC address OUI lookups, and features a clean interactive text UI (TUI) built with curses.

---

## Features

* **Subnet Auto-Discovery:** Automatically detects your local IP and scans the /24 network.
* **ARP Network Scanning:** Fast and reliable device discovery using scapy.
* **Hostname Resolution:** Attempts reverse DNS lookups for discovered IP addresses.
* **Vendor Identification:** Identifies hardware manufacturers using local MAC OUI lookup databases.
* **Interactive Terminal UI (TUI):** Built with curses, featuring real-time status updates and animated spinners.
* **Data Export:** Export your scan results instantly to JSON or CSV formats with automated timestamps.

---

## Prerequisites

Because NetWatch crafts low-level ARP packets via scapy, **root/administrator privileges** are required to run the script.

* Python 3.8+
* Scapy (requires raw socket permissions)

---

## Installation

1. Clone or download the repository:
   ```bash
   git clone [https://github.com/your-username/netwatch.git](https://github.com/your-username/netwatch.git)
   cd netwatch
   ```

2. Install the required dependencies:
   ```bash
   pip install scapy mac-vendor-lookup
   ```

---

## Usage

Run the script with administrator privileges (using sudo on Linux/macOS or an elevated prompt on Windows):

```bash
sudo python3 netwatch.py
```

### Exporting Results
Once the network scan completes and displays the discovered devices, NetWatch will prompt you directly inside the terminal:
* Press **j** to export results to a timestamped `network_scan_YYYYMMDD_HHMMSS.json` file.
* Press **c** to export results to a timestamped `network_scan_YYYYMMDD_HHMMSS.csv` file.
* Press any other key to skip exporting.

---

## Project Structure

```text
netwatch/
│
├── netwatch.py          # Main application script
└── README.md            # Project documentation
```

---

## Built With

* [Python](https://www.python.org/) - Core programming language
* [Scapy](https://scapy.net/) - Packet manipulation and ARP scanning
* [Mac Vendor Lookup](https://github.com/bachand/mac-vendor-lookup) - MAC address manufacturer mapping
* [Curses](https://docs.python.org/3/library/curses.html) - Terminal handling for TUI interfaces