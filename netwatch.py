import socket

def main():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print("NetWatch")
    print("========")
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")

if __name__ == "__main__":
    main()
