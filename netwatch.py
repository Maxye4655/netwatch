import os
import socket
import ipaddress
import datetime
import json
import csv
import threading
import time

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup, BaseMacLookup
from dataclasses import asdict, dataclass

import curses

@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str

    def __str__(self):
        return f"{self.ip} | {self.mac} | {self.hostname} | {self.vendor}"


mac_lookup = MacLookup()


def initialize_vendor_db(stdscr):
    try:
        if not os.path.exists(BaseMacLookup.cache_path):
            stdscr.addstr("[*] Downloading MAC vendor database (first-time setup)...\n", curses.color_pair(1))
            stdscr.refresh()
            mac_lookup.update_vendors()
        else:
            mac_lookup.load_vendors()
    except Exception as error:
        stdscr.addstr(f"[!] Could not update MAC vendor database: {error}\n", curses.color_pair(1) | curses.A_BOLD)
        stdscr.refresh()
        try:
            mac_lookup.load_vendors()
        except Exception:
            stdscr.addstr("[!] MAC vendor database unavailable.\n", curses.color_pair(1) | curses.A_BOLD)
            stdscr.refresh()


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

    # Access index 0 explicitly to capture the collection wrapper
    answered = srp(packet, timeout=2, verbose=False)[0]
    devices = []

    for item in answered:
        sent = item.query
        received = item.answer
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


def export_results_curses(stdscr, devices):
    if not devices:
        stdscr.addstr("\n[!] No devices to export.\n", curses.color_pair(1))
        stdscr.refresh()
        return

    stdscr.addstr("\nWould you like to export the results? (", curses.color_pair(1))
    stdscr.addstr("j", curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
    stdscr.addstr(" = JSON, ", curses.color_pair(1))
    stdscr.addstr("c", curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
    stdscr.addstr(" = CSV, any other key = Skip): ", curses.color_pair(1))
    stdscr.refresh()
    
    char = stdscr.getch()
    choice = chr(char).lower() if 0 <= char <= 255 else ""

    if choice not in ["j", "c"]:
        stdscr.addstr("\n[*] Skipping export.\n", curses.color_pair(1))
        stdscr.refresh()
        return

    ext = "json" if choice == "j" else "csv"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_{timestamp}.{ext}"

    try:
        if ext == "json":
            with open(filename, "w", encoding="utf-8") as f:       
                json.dump([asdict(device) for device in devices], f, indent=4)
        elif ext == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor"])
                for d in devices:
                    writer.writerow([d.ip, d.mac, d.hostname, d.vendor])
        
        stdscr.addstr(f"\n[+] Successfully exported results to ", curses.color_pair(1))
        stdscr.addstr(filename, curses.color_pair(1) | curses.A_UNDERLINE | curses.A_BOLD)
        stdscr.addstr("\n", curses.color_pair(1))
    except Exception as e:
        stdscr.addstr(f"\n[!] Error occurred while exporting results: {e}\n", curses.color_pair(1) | curses.A_BOLD)
    
    stdscr.refresh()


def run_scanner(stdscr):
    stdscr.scrollok(True)
    
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)

    initialize_vendor_db(stdscr)

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    ascii_logo = """
 ███▄    █ ▓█████▄▄▄█████▓ █     █░ ▄▄▄     ▄▄▄█████▓ ▄████▄   ██░ ██ 
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓█░ █ ░█░▒████▄   ▓  ██▒ ▓▒▒██▀ ▀█  ▓██░ ██▒
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒█░ █ ░█ ▒██  ▀█▄ ▒ ▓██░ ▒░▒▓█    ▄ ▒██▀▀██░
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░█░ █ ░█ ░██▄▄▄▄██░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█ ░██ 
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░░██▒██▓  ▓█   ▓██▒ ▒██▒ ░ ▒ ▓███▀ ░░▓█▒░██▓
"""
    stdscr.addstr(ascii_logo, curses.color_pair(1) | curses.A_BOLD)
    
    stdscr.addstr("Hostname: ", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(f"{hostname}\n", curses.color_pair(1))
    
    stdscr.addstr("Local IP: ", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(f"{local_ip}\n", curses.color_pair(1))
    
    stdscr.addstr("Network:  ", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(f"{network}\n\n", curses.color_pair(1))
    stdscr.refresh()

    scan_results = []
    scan_done = threading.Event()

    def worker():
        nonlocal scan_results
        scan_results = scan_network(network)
        scan_done.set()

    scan_thread = threading.Thread(target=worker)
    scan_thread.start()

    spinner_frames = ["|", "/", "-", "\\"]
    frame_idx = 0

    y, x = stdscr.getyx()

    while not scan_done.is_set():
        stdscr.move(y, 0)
        stdscr.clrtoeol()
        
        stdscr.addstr("[", curses.color_pair(1))
        stdscr.addstr(spinner_frames[frame_idx], curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr("] Scanning network... Please wait...", curses.color_pair(1))
        
        stdscr.refresh()
        frame_idx = (frame_idx + 1) % len(spinner_frames)
        time.sleep(0.1)

    stdscr.move(y, 0)
    stdscr.clrtoeol()
    stdscr.addstr("[+] Network scan complete!\n\n", curses.color_pair(1) | curses.A_BOLD)

    stdscr.addstr("Scan Results:\n", curses.color_pair(1) | curses.A_UNDERLINE | curses.A_BOLD)
    for device in scan_results:
        stdscr.addstr("[+] ", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(f"{device}\n", curses.color_pair(1))

    stdscr.addstr(f"\n{len(scan_results)} devices found.\n", curses.color_pair(1) | curses.A_BOLD)
    stdscr.refresh()

    export_results_curses(stdscr, scan_results)
    
    stdscr.addstr("\nPress any key to exit full terminal mode...", curses.color_pair(1))
    stdscr.refresh()
    stdscr.getch()


def main():
    curses.wrapper(run_scanner)


if __name__ == "__main__":
    main()



