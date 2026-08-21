import socket
import ipaddress


def main():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network = ipaddress.ip_network(local_ip + '/24', strict=False)

    print("NetWatch")
    print("========")
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    print(f"Network: {network}")


if __name__ == "__main__":
    main()
