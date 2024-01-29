import socket
import threading
import nmap
import getmac
import requests
import scapy.all as scapy

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3389: "RDP"
}

def syn_scan(target_ip, port):
    try:
        # Crafting the SYN packet
        syn_packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S")
        
        # Sending the SYN packet and waiting for a response
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)
        
        # Analyzing the response
        if response:
            if response.haslayer(scapy.TCP):
                # Check if the TCP flags indicate a SYN-ACK (port open)
                if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                    print(f"Port {port} open on {target_ip}")
                # Check if the TCP flags indicate a RST (port closed)
                elif response[scapy.TCP].flags == 0x14:  # RST
                    print(f"Port {port} closed on {target_ip}")
            else:
                print(f"Unable to determine status of port {port} on {target_ip}")
        else:
            print(f"No response from port {port} on {target_ip}")

    except Exception as e:
        print(f"Error scanning port {port}: {e}")


def version_detection(target_ip, port):
    nm = nmap.PortScanner()
    nm.scan(target_ip, str(port), arguments='-sV')

    if nm[target_ip]['tcp'][port]['state'] == 'open':
        service = nm[target_ip]['tcp'][port]['name']
        version = nm[target_ip]['tcp'][port]['product'] + ' ' + nm[target_ip]['tcp'][port]['version']
        print(f"Port {port} open on {target_ip}: {service} - {version}")

def send_arp_request(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        # Extract MAC address from the response
        return answered_list[0][1].hwsrc
    else:
        return None

def mac_address_retrieval(target_ip):
    try:
        # Send ARP request
        mac = send_arp_request(target_ip)

        if mac:
            print(f"MAC address for {target_ip}: {mac}")
        else:
            print(f"Unable to retrieve MAC address for {target_ip}")
    except Exception as e:
        print(f"Error retrieving MAC address: {e}")

def public_ip_information(target_ip):
    try:
        response = requests.get(f"https://ipinfo.io/{target_ip}/json")
        data = response.json()

        print(f"Public IP Information for {target_ip}:")
        print(f"IP Address: {data['ip']}")
        print(f"Location: {data['city']}, {data['region']}, {data['country']}")
        print(f"ISP: {data.get('org', 'N/A')}")
        print(f"AS (Autonomous System): {data.get('asn', 'N/A')}")
        print(f"Hostname: {data.get('hostname', 'N/A')}")
        print(f"Latitude/Longitude: {data.get('loc', 'N/A')}")
    except Exception as e:
        print(f"Error retrieving public IP information: {e}")

def scan_port(target_ip, port, service_version_detection=False, mac_address_retrieval=False):
    banner = ""  # Initialize banner to an empty string

    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(1)
        # Attempt to connect to the target IP and port
        sock.connect((target_ip, port))

        try:
            # Perform banner grabbing to get service version information
            data = sock.recv(1024)
            banner = data.decode('utf-8').strip()
            print(f"Port {port} open on {target_ip}: {COMMON_PORTS.get(port, 'Unknown')} - {banner}")

        except UnicodeDecodeError:
            # If decoding as UTF-8 fails, print raw bytes
            print(f"Port {port} open on {target_ip}: {COMMON_PORTS.get(port, 'Unknown')} - Raw Bytes: {data}")

        # Additional Functionality 1: Check for vulnerable services or known exploits
        check_for_exploits(port, banner)

        # Additional Functionality 2: Version Detection
        if service_version_detection:
            version_detection(target_ip, port)

        # Additional Functionality 3: MAC Address Retrieval
        if mac_address_retrieval:
            mac_address_retrieval(target_ip)

    except socket.error:
        # If the connection attempt fails, the port is likely closed
        print(f"Port {port} closed on {target_ip}")
    finally:
        # Close the socket
        sock.close()

# Assuming COMMON_PORTS is a dictionary mapping port numbers to service names
COMMON_PORTS = {20: 'FTP', 21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS'}

def check_for_exploits(port, banner):
    try:
        if isinstance(banner, bytes):
            # Attempt to decode raw bytes as UTF-8
            banner_str = banner.decode('utf-8')
        else:
            banner_str = banner

        # Check for potential vulnerabilities based on the decoded string
        if port == 21 and "vsftpd" in banner_str.lower():
            print(f"Potential vulnerability in FTP service on port {port}: vsftpd 2.3.4")
        else:
            print(f"No known vulnerabilities detected for port {port}")
    except UnicodeDecodeError:
        # If decoding fails, print a message
        print(f"Unable to decode raw bytes for port {port}")


def ping_sweep(target_subnet):
    # Placeholder function for ping sweep
    print(f"Pinging hosts in subnet {target_subnet}...")
    live_hosts = []
    for host in range(1, 255):
        ip_address = f"{target_subnet}.{host}"
        if is_host_alive(ip_address):
            live_hosts.append(ip_address)
    print(f"Live hosts: {', '.join(live_hosts)}")

def is_host_alive(ip_address, port=80):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip_address, port))
        sock.close()
        return True
    except (socket.error, socket.timeout):
        return False

def main_menu():
    print("==== Network Scanner ====")
    print("1. Regular Scan")
    print("2. Stealth (SYN) Scan")
    print("3. Ping Sweep")
    print("4. Service Version Detection")
    print("5. MAC Address Retrieval")
    print("6. IP Geolocation")
    print("7. Exit")

def main_menu():
    print("==== Network Scanner ====")
    print("1. Regular Scan")
    print("2. Stealth (SYN) Scan")
    print("3. Ping Sweep")
    print("4. Service Version Detection")
    print("5. MAC Address Retrieval")
    print("6. Public IP")
    print("7. Is Host Alive")
    print("8. Exit")

def main():
    while True:
        main_menu()
        choice = input("Enter your choice (1-8): ")

        if choice == '1':
            target_ip = input("Enter the target IP address: ")
            start_port = int(input("Enter the start port: "))
            end_port = int(input("Enter the end port: "))
            print(f"\nScanning ports {start_port} to {end_port} on {target_ip}...")
            for port in range(start_port, end_port + 1):
                scan_port(target_ip, port)

        elif choice == '2':
            target_ip = input("Enter the target IP address: ")
            start_port = int(input("Enter the start port: "))
            end_port = int(input("Enter the end port: "))
            print(f"\nScanning ports {start_port} to {end_port} (SYN scan) on {target_ip}...")
            for port in range(start_port, end_port + 1):
                syn_scan(target_ip, port)

        elif choice == '3':
            target_subnet = input("Enter the target subnet (e.g., 192.168.1): ")
            ping_sweep(target_subnet)

        elif choice == '4':
            target_ip = input("Enter the target IP address: ")
            start_port = int(input("Enter the start port: "))
            end_port = int(input("Enter the end port: "))
            print(f"\nScanning ports {start_port} to {end_port} for service version on {target_ip}...")
            for port in range(start_port, end_port + 1):
                version_detection(target_ip, port)

        elif choice == '5':
            target_ip = input("Enter the target IP address: ")
            mac_address_retrieval(target_ip)
            
        elif choice == '6':
            target_ip = input("Enter the target Public IP address: ")
            print(f"\nGetting Public IP information for {target_ip}...")
            public_ip_information(target_ip)

        elif choice == '7':
            target_ip = input("Enter the target IP address: ")
            print(f"\nChecking if host {target_ip} is alive...")
            if is_host_alive(target_ip):
                print(f"Host {target_ip} is alive.")
            else:
                print(f"Host {target_ip} is not reachable.")

        elif choice == '8':
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 8.")

if __name__ == "__main__":
    main()
