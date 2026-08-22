import os
import socket
import ipaddress

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup, BaseMacLookup
from dataclasses import dataclass



@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str

    def __str__(self):
        return (
            f"{self.ip} | {self.mac} | {self.hostname} | {self.vendor}"
        )

mac_lookup = MacLookup()


def initialize_vendor_db():
    try:
        if not os.path.exists(BaseMacLookup.cache_path):
            print("[*] Downloading MAC vendor database (first-time setup)...")
            mac_lookup.update_vendors()
        else:
            mac_lookup.load_vendors()

    except Exception as error:
        print(f"[!] Could not update MAC vendor database: {error}")

        try:
            mac_lookup.load_vendors()
        except Exception:
            print("[!] MAC vendor database unavailable.")


def get_hostname(ip):
    """Try to find the hostname associated with an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"


def get_vendor(mac):
    """Try to identify the manufacturer from a MAC address."""
    try:
        return mac_lookup.lookup(mac)
    except KeyError:
        return "Unknown"


def scan_network(network):
    """Discover devices on the local network using ARP."""
    arp_request = ARP(pdst=str(network))

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    answered = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    devices = []

    for sent, received in answered:
        hostname = get_hostname(received.psrc)
        vendor = get_vendor(received.hwsrc)

        devices.append(
            Device(
                ip=received.psrc,
                mac=received.hwsrc,
                hostname=hostname,
                vendor=vendor,
            )
)

    return devices


def main():
    initialize_vendor_db()

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    network = ipaddress.ip_network(
        f"{local_ip}/24",
        strict=False
    )

    print()
    print("""
 ███▄    █ ▓█████▄▄▄█████▓ █     █░ ▄▄▄     ▄▄▄█████▓ ▄████▄   ██░ ██ 
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓█░ █ ░█░▒████▄   ▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒█░ █ ░█ ▒██  ▀█▄ ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░█░ █ ░█ ░██▄▄▄▄██░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██ 
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░░██▒██▓  ▓█   ▓██▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓
░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░   ░ ▓░▒ ▒   ▒▒   ▓▒█░ ▒ ░░   ░ ░▒ ▒  ░ ▒ ░░▒░▒
░ ░░   ░ ▒░ ░ ░  ░   ░      ▒ ░ ░    ▒   ▒▒ ░   ░      ░  ▒    ▒ ░▒░ ░
   ░   ░ ░    ░    ░        ░   ░    ░   ▒    ░      ░         ░  ░░ ░
         ░    ░  ░            ░          ░  ░        ░ ░       ░  ░  ░
                                                     ░                
                                                     """)
    print()
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    print(f"Network: {network}")
    print()

    print(f"Scanning {network}...")
    print()

    devices = scan_network(network)

    for device in devices:
        print(f"[+] {device}")

    print()
    print(f"{len(devices)} devices found.")


if __name__ == "__main__":
    main()