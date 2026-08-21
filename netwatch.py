import ipaddress
import socket
from scapy.all import ARP, Ether, srp


def get_hostname(ip):
  try:
    hostname = socket.gethostbyaddr(ip)[0]
    return hostname
  except socket.herror:
    return "Unknown"


# scan the network for active devices
def scan_network(network):
  arp_request = ARP(pdst=str(network))
  broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
  packet = broadcast / arp_request

  answered = srp(packet, timeout=2, verbose=False)[0]

  devices = []

  for sent, received in answered:
    hostname = get_hostname(received.psrc)

    devices.append(
        {"ip": received.psrc, "mac": received.hwsrc, "hostname": hostname}
    )

  return devices


def main():
  hostname = socket.gethostname()
  local_ip = socket.gethostbyname(hostname)
  network = ipaddress.ip_network(local_ip + "/24", strict=False)

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
  print("-----------------------------------------------------------------")
  print(f"Hostname: {hostname}")
  print(f"Local IP: {local_ip}")
  print(f"Network: {network}")
  print()
  print(f"Scanning network {network} for active devices...")

  devices = scan_network(network)

  for device in devices:
    print(f"[+] {device['ip']} - {device['mac']} - {device['hostname']}")

  print()
  print(f"{len(devices)} devices found.")


if __name__ == "__main__":
  main()