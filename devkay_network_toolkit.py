import socket
import subprocess
import os
import re
import requests
import whois
import dns.resolver
import ssl
import threading
import time
import sys
import hashlib
import ipaddress
import webbrowser

# === Loader Spinner ===
loader_running = False

def loader_spin(text="Initializing..."):
    global loader_running
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while loader_running:
        sys.stdout.write(f"\r{text}... {spinner[idx % len(spinner)]}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 40 + "\r")  # Clear the line

# === Get Local Device IP ===
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# === External IP Tracker ===
def get_ip_info(ip):
    url = (
        f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    try:
        res = requests.get(url, timeout=5).json()
        if res.get("status") != "success":
            return None
        return res
    except:
        return None

# === WHOIS Lookup ===
def whois_lookup(ip_or_domain):
    global loader_running
    print("\n[+] WHOIS lookup initiated. Gathering critical information...")
    loader_running = True
    loader_thread = threading.Thread(target=loader_spin, args=("WHOIS Lookup",))
    loader_thread.start()

    try:
        w = whois.whois(ip_or_domain)
        loader_running = False
        loader_thread.join()
        print("\n[INFO] WHOIS Data:")
        for k, v in w.items():
            if v:
                print(f"{k}: {v}")
    except:
        loader_running = False
        loader_thread.join()
        print("[-] WHOIS lookup failed. Target not reachable.")

# === DNS Lookup ===
def dns_lookup(domain):
    global loader_running
    print("\n[+] Performing DNS Lookup...")
    loader_running = True
    loader_thread = threading.Thread(target=loader_spin, args=("DNS Lookup",))
    loader_thread.start()

    try:
        print("\n[INFO] DNS Records Found:")
        for record_type in ["A", "AAAA", "MX", "TXT", "NS"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    print(f"{record_type}: {rdata}")
            except:
                continue
        loader_running = False
        loader_thread.join()
    except:
        loader_running = False
        loader_thread.join()
        print("[-] DNS lookup failed. Target system unreachable.")

# === SSL Certificate Info ===
def get_ssl_info(domain):
    global loader_running
    print("\n[+] Retrieving SSL Certificate data...")
    loader_running = True
    loader_thread = threading.Thread(target=loader_spin, args=("SSL Info",))
    loader_thread.start()

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                loader_running = False
                loader_thread.join()
                print("\n[INFO] SSL Certificate Data:")
                print(f"Issuer: {cert['issuer']}")
                print(f"Valid From: {cert['notBefore']}")
                print(f"Valid Until: {cert['notAfter']}")
    except:
        loader_running = False
        loader_thread.join()
        print("[-] SSL certificate retrieval failed. Connection not secured.")

# === IP Port Scanner ===
def port_scan(ip):
    global loader_running
    print("\n[+] Scanning for open ports on target...")
    loader_running = True
    loader_thread = threading.Thread(target=loader_spin, args=("Port Scan",))
    loader_thread.start()

    open_ports = []
    for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    loader_running = False
    loader_thread.join()
    print(f"\n[INFO] Open Ports on {ip}: {open_ports if open_ports else 'None found'}")

# === External IP Tracking ===
def track_external_ip(ip):
    global loader_running
    print(f"\n[+] Target IP: {ip} located. Commencing tracking...\n")
    try:
        socket.inet_pton(socket.AF_INET, ip)  # IPv4 validation
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)  # IPv6 validation
        except socket.error:
            print("[-] Invalid IP format.")
            return

    loader_running = True
    loader_thread = threading.Thread(target=loader_spin)
    loader_thread.start()

    try:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Hostname not available"

        loader_running = False
        loader_thread.join()

        print(f"[INFO] Hostname: {hostname}")
        port_scan(ip)

        info = get_ip_info(ip)
        if info:
            print("\n[INFO] Location and Network Information:")
            print(f"Continent: {info.get('continent')}")
            print(f"Country: {info.get('country')}")
            print(f"Region: {info.get('region')}")
            print(f"City: {info.get('city')}")
            print(f"Latitude: {info.get('lat')}")
            print(f"Longitude: {info.get('lon')}")
            print(f"Timezone: {info.get('timezone')}")
            print(f"ISP: {info.get('isp')}")
            print(f"Organization: {info.get('org')}")
            print(f"ASN: {info.get('as')}")
        else:
            print("[-] Location information not available.")

        whois_lookup(ip)
    except Exception as e:
        loader_running = False
        loader_thread.join()
        print(f"[-] Error while tracking IP: {e}")

# === MAC Vendor Lookup ===
def get_mac_vendor(mac):
    url = f"https://api.macvendors.com/{mac}"
    try:
        r = requests.get(url, timeout=3)
        return r.text if r.status_code == 200 else "Unknown Vendor"
    except:
        return "Unknown Vendor"

# === Ping Device ===
def ping_device(ip):
    return os.system(f"ping -n 1 {ip} >nul 2>&1") == 0

# === Reverse DNS ===
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown Device"

# === Local Network Scanner ===
def scan_local_network():
    global loader_running
    print("\n[+] Scanning local network for connected devices...\n")
    loader_running = True
    loader_thread = threading.Thread(target=loader_spin, args=("Scanning",))
    loader_thread.start()

    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_output.splitlines():
            match = re.match(r"^\s*([\d\.]+)\s+([a-fA-F0-9\-]+)\s+\w+", line)
            if match:
                ip, mac = match.group(1), match.group(2)
                print(f"\n[INFO] Device IP: {ip}")
                print(f"MAC Address: {mac}")
                print(f"Vendor: {get_mac_vendor(mac)}")
                print(f"Device Name: {get_device_name(ip)}")
                print(f"Status: {'Online' if ping_device(ip) else 'Offline'}")
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
    except Exception as e:
        print(f"[-] Local scan failed: {e}")
    finally:
        loader_running = False
        loader_thread.join()

# === Domain to IP Resolver ===
def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        print("[-] Domain resolution failed.")
        return None

# === Nmap Scan ===
def nmap_scan(target):
    print(f"\n[+] Launching Nmap scan on {target}...")
    try:
        result = subprocess.check_output(["nmap", "-A", "-T4", target], text=True)
        print("[INFO] Nmap Scan Results:\n")
        print(result)
    except FileNotFoundError:
        print("[-] Nmap is not installed or not in system PATH.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap scan failed:\n{e.output}")

# === Live Network Monitor ===
def hash_devices(devices):
    return hashlib.md5("".join(sorted(devices)).encode()).hexdigest()

def live_network_monitor(interval=15):
    print("\n[+] Starting live network monitor (Ctrl+C to stop)...\n")
    previous_hash = None
    try:
        while True:
            arp_output = subprocess.check_output("arp -a", shell=True, text=True)
            current_devices = []
            for line in arp_output.splitlines():
                match = re.match(r"^\s*([\d\.]+)\s+([a-fA-F0-9\-]+)\s+\w+", line)
                if match:
                    ip = match.group(1)
                    current_devices.append(ip)
            
            current_hash = hash_devices(current_devices)
            if current_hash != previous_hash:
                print(f"\n[!] Network change detected at {time.strftime('%H:%M:%S')}")
                for ip in current_devices:
                    print(f" - {ip} ({'Online' if ping_device(ip) else 'Offline'})")
                previous_hash = current_hash

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Live monitor stopped by user.")

# === Traceroute ===
def traceroute(target):
    print(f"\n[+] Performing Traceroute to {target}...\n")
    try:
        result = subprocess.check_output(["tracert", target], text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"[-] Traceroute failed: {e}")

# === Subnet Scanner ===
def scan_subnet(subnet):
    print(f"\n[+] Scanning subnet {subnet}...\n")
    try:
        network = ipaddress.IPv4Network(subnet)
        for ip in network.hosts():
            if ping_device(str(ip)):
                print(f"[INFO] Active IP: {ip}")
            else:
                print(f"[INFO] Inactive IP: {ip}")
    except ValueError:
        print("[-] Invalid subnet.")

# === HTTP Header Inspection ===
def get_http_headers(domain):
    print(f"\n[+] Fetching HTTP headers for {domain}...\n")
    try:
        response = requests.head(f"http://{domain}", timeout=5)
        print("[INFO] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except requests.RequestException as e:
        print(f"[-] Error fetching HTTP headers: {e}")

# === Main Menu ===
def main():
    print("DevKay Network-Toolkit")
    print("1. Scan Local Network")
    print("2. Track External IP or Domain")
    print("3. Display Local Device IP")
    print("4. Run Nmap Scan")
    print("5. Live Local Network Monitor")
    print("6. Traceroute to Target")
    print("7. Scan Subnet")
    print("8. Fetch HTTP Headers")
    print("9. Exit")

    while True:
        choice = input("\nSelect option (1-9): ").strip()
        if choice == '1':
            scan_local_network()
        elif choice == '2':
            target = input("Enter target IP or Domain: ").strip()
            ip = resolve_domain_to_ip(target) if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) else target
            if ip:
                track_external_ip(ip)
                if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
                    dns_lookup(target)
                    get_ssl_info(target)
            else:
                print("[-] Invalid input. Operation aborted.")
        elif choice == '3':
            local_ip = get_local_ip()
            print(f"[INFO] This Device's Local IP: {local_ip}")
        elif choice == '4':
            target = input("Enter target IP or Domain: ").strip()
            nmap_scan(target)
        elif choice == '5':
            live_network_monitor()
        elif choice == '6':
            target = input("Enter target IP or Domain: ").strip()
            traceroute(target)
        elif choice == '7':
            subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24): ").strip()
            scan_subnet(subnet)
        elif choice == '8':
            domain = input("Enter domain to fetch HTTP headers: ").strip()
            get_http_headers(domain)
        elif choice == '9':
            print("Operation terminated.")
            break
        else:
            print("[-] Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
