```
███▄    █ ▓█████▄▄▄█████▓ █     █░ ▄▄▄     ▄▄▄█████▓ ▄████▄   ██░ ██ 
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓█░ █ ░█░▒████▄   ▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒█░ █ ░█ ▒██  ▀█▄ ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░█░ █ ░█ ░██▄▄▄▄██░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██ 
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░░██▒██▓  ▓█   ▓██▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓
```
# NetWatch

Netwatch is a simple, local network discovery tool built with python. 

## Features

* **Subnet Auto-Discovery:** Automatically detects local IP and scans the /24 network.
* **ARP Network Scanning:** Uses Address Resolution Protocol requests to map active IP addresses to their physical MAC addresses on a local subnet
* **Hostname Resolution:** Attempts reverse DNS lookups for discovered IP addresses.
* **Vendor Identification:** Identifies hardware manufacturers using local MAC OUI lookup databases.
* **Full Screen TUI:** Built with curses.
* **Data Export:** Export scan results instantly to JSON or CSV formats with automated timestamps.

## Dependencies

* Python 3.8+
* Scapy

Install:

Fedora:

```
sudo dnf install python3 python3-scapy
```

Windows (Powershell):
```
winget install -e --id Python.Python.3.12
```

Open a new terminal session and then run:

```
pip install scapy
```

Arch:
```
sudo pacman -S python python-scapy
```

---

## Installation

1. Clone the repository:
   ```
   git clone [https://github.com/your-username/netwatch.git](https://github.com/your-username/netwatch.git)
   cd netwatch
   ```

2. Install the required dependencies:
   ```
   pip install mac-vendor-lookup
   ```

---

## Usage

Run the script:

```bash
sudo python3 netwatch.py
```

## Built With

* [Python](https://www.python.org/) - Core programming language
* [Scapy](https://scapy.net/) - Packet manipulation and ARP scanning
* [Mac Vendor Lookup](https://github.com/bachand/mac-vendor-lookup) - MAC address manufacturer mapping
* [Curses](https://docs.python.org/3/library/curses.html) - Terminal handling for TUI interfaces