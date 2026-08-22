import os
import socket
import ipaddress
import datetime
import json
import csv

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup, BaseMacLookup
from dataclasses import asdict, dataclass



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
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"


def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except KeyError:
        return "Unknown"


def scan_network(network):
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


def export_results(devices):
    if not devices:
        print("[!] No devices to export.")
        return

    print()
    choice = (
        input("Would you like to export the results? (json/csv/none): ")
        .strip()
        .lower()
    )

    if choice not in ["json", "csv"]:
        print("[*] Skipping export.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_{timestamp}.{choice}"

    try:
        if choice == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump([asdict(device) for device in devices], f, indent=4)
            print(f"[*] Results successfully exported to {filename}")
        elif choice == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor"])
                for d in devices:
                    writer.writerow([d.ip, d.mac, d.hostname, d.vendor])
            print(f"[+] Successfully exported results to {filename}")
    except Exception as e:
        print(f"[!] Error occurred while exporting results: {e}")


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

    export_results(devices)


if __name__ == "__main__":
  main()