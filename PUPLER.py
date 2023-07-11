import os
import sys
import requests
import argparse
import socket
import readline
import dns.resolver
import whois
import ipaddress
import json
import urllib.request
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

# Check if script is running with administrative privileges
if os.geteuid() != 0:
    print(f"{Fore.RED}This script requires administrative privileges to run.")
    print(f"Please run the script with 'sudo' or as a superuser.")
    sys.exit(1)

def get_ip_info(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    data = response.json()
    return data

def scan_ip(ip):
    ip_info = get_ip_info(ip)
    print(f"{Fore.GREEN}IP: {ip}")
    print(f"Country: {ip_info['country']}")
    print(f"City: {ip_info['city']}")
    print(f"ISP: {ip_info['isp']}")
    print(f"Latitude: {ip_info['lat']}")
    print(f"Longitude: {ip_info['lon']}")


COMMON_PORTS = [80, 443, 22, 21, 23, 25, 110, 143, 3306, 5432]

def port_scan(ip, scan_type):
    open_ports = []
    if scan_type == "simple":
        for port in tqdm(COMMON_PORTS, desc="Scanning common ports"):
            if is_port_open(ip, port):
                open_ports.append(port)
    elif scan_type == "comprehensive":
        for port in tqdm(range(1, 65536), desc="Scanning all ports"):
            if is_port_open(ip, port):
                open_ports.append(port)
    elif scan_type == "medium":
        for port in tqdm(range(1, 1024), desc="Scanning medium ports"):
            if is_port_open(ip, port):
                open_ports.append(port)
    else:
        print(f"{Fore.RED}Invalid scan type. Please choose 'simple', 'comprehensive', or 'medium'.")

    return open_ports

def is_port_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def dns_lookup(domain):
    try:
        answers = dns.resolver.resolve(domain)
        print(f"{Fore.GREEN}DNS Lookup Results for {domain}:")
        for answer in answers:
            print(answer)
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}Domain not found.")
    except dns.resolver.NoAnswer:
        print(f"{Fore.RED}No DNS records found.")
    except dns.resolver.Timeout:
        print(f"{Fore.RED}DNS lookup timed out.")
    except dns.resolver.NoNameservers:
        print(f"{Fore.RED}No DNS nameservers found.")

def traceroute(ip):
    try:
        dest_ip = socket.gethostbyname(ip)
        ttl = 1
        max_hops = 30
        print(f"{Fore.GREEN}Traceroute Results for {ip}:")
        while True:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.settimeout(1)
            recv_socket.bind(("", 0))
            recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            send_socket.sendto(b"", (ip, 33434))
            try:
                _, curr_addr = recv_socket.recvfrom(512)
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error:
                pass
            finally:
                send_socket.close()
                recv_socket.close()

            if curr_addr is not None:
                print(f"{ttl}: {curr_name} ({curr_addr})")
            else:
                print(f"{ttl}: *")

            ttl += 1
            if curr_addr == dest_ip or ttl > max_hops:
                break
    except socket.gaierror:
        print(f"{Fore.RED}Invalid IP address or domain name.")

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"{Fore.GREEN}Whois Lookup Results for {domain}:")
        print(w)
    except whois.parser.PywhoisError:
        print(f"{Fore.RED}Domain not found.")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

def reverse_dns_lookup(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        print(f"{Fore.GREEN}Reverse DNS Lookup Results for {ip}:")
        print(f"Domain: {domain}")
    except socket.herror:
        print(f"{Fore.RED}Reverse DNS lookup failed.")
    except socket.gaierror:
        print(f"{Fore.RED}Invalid IP address.")

def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        data = response.json()
        print(f"{Fore.GREEN}GeoIP Lookup Results for {ip}:")
        print(f"Country: {data['country']}")
        print(f"City: {data['city']}")
        print(f"ISP: {data['isp']}")
        print(f"Latitude: {data['lat']}")
        print(f"Longitude: {data['lon']}")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Failed to perform GeoIP lookup.")

def subnet_calculator(ip, subnet_mask):
    try:
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        print(f"{Fore.GREEN}Subnet Calculator Results for {ip}/{subnet_mask}:")
        print(f"Network Address: {network.network_address}")
        print(f"Broadcast Address: {network.broadcast_address}")
        print(f"Netmask: {network.netmask}")
        print(f"Number of Hosts: {network.num_addresses - 2}")
    except ValueError:
        print(f"{Fore.RED}Invalid IP address or subnet mask.")

def ip_reputation_check(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": "YOUR_API_KEY"}  # Replace with your AbuseIPDB API key
        response = requests.get(url, headers=headers)
        data = response.json()
        if data["data"]["isWhitelisted"]:
            print(f"{Fore.GREEN}IP Reputation Check Results for {ip}:")
            print("IP is whitelisted.")
        else:
            print(f"{Fore.RED}IP Reputation Check Results for {ip}:")
            print(f"IP is blacklisted.")
            print(f"Category: {data['data']['category']}")
            print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Failed to perform IP reputation check.")

def ip_geolocation(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = urllib.request.urlopen(url)
        data = json.load(response)
        print(f"{Fore.GREEN}IP Geolocation Results for {ip}:")
        print(f"Country: {data['country']}")
        print(f"Region: {data['region']}")
        print(f"City: {data['city']}")
        print(f"Postal Code: {data['postal']}")
        print(f"Timezone: {data['timezone']}")
    except urllib.error.URLError:
        print(f"{Fore.RED}Failed to perform IP geolocation.")

def ip_range_calculator(ip_range):
    try:
        start_ip, end_ip = ip_range.split("-")
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
        ip_network = ipaddress.summarize_address_range(start, end)
        print(f"{Fore.GREEN}IP Range Calculator Results for {ip_range}:")
        if ip_network:
            for network in ip_network:
                print(network)
        else:
            print(f"No IP networks found within the given range.")
    except ValueError:
        print(f"{Fore.RED}Invalid IP range format.")

def ip_to_mac_address(ip):
    try:
        mac_address = ""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((ip, 0))
            mac_address = s.getsockname()[4]
        if mac_address:
            mac_address = ":".join("{:02x}".format(byte) for byte in mac_address)
            print(f"{Fore.GREEN}IP to MAC Address Lookup Results for {ip}:")
            print(f"MAC Address: {mac_address}")
        else:
            print(f"{Fore.RED}Failed to retrieve MAC address.")
    except socket.error:
        print(f"{Fore.RED}Failed to retrieve MAC address.")

def ip_to_asn(ip):
    try:
        url = f"https://api.iptoasn.com/v1/as/ip/{ip}"
        response = requests.get(url)
        data = response.json()
        print(f"{Fore.GREEN}IP to ASN Lookup Results for {ip}:")
        print(f"ASN: {data['as_number']}")
        print(f"Organization: {data['as_description']}")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Failed to perform IP to ASN lookup.")

def ip_to_service_mapping(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key=YOUR_API_KEY"  # Replace with your Shodan API key
        response = requests.get(url)
        data = response.json()
        print(f"{Fore.GREEN}IP to Service Mapping Results for {ip}:")
        if "ports" in data:
            ports = data["ports"]
            if ports:
                for port in ports:
                    print(f"Port: {port}")
                    if str(port) in data["data"]:
                        print(f"Service: {data['data'][str(port)]['_shodan']['module']}")
                        print(f"Product: {data['data'][str(port)]['product']}")
                        print(f"Version: {data['data'][str(port)]['version']}")
                    print()
            else:
                print(f"{Fore.RED}No open ports found.")
        else:
            print(f"{Fore.RED}No port information available.")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Failed to perform IP to service mapping.")

def ip_blacklist_check(ip):
    try:
        url = f"https://www.abuseipdb.com/check/{ip}/json?key=YOUR_API_KEY"  # Replace with your AbuseIPDB API key
        response = requests.get(url)
        data = response.json()
        if "data" in data:
            print(f"{Fore.GREEN}IP Blacklist Check Results for {ip}:")
            print(f"Is Blacklisted: {data['data']['is_blacklisted']}")
            print(f"Total Reports: {data['data']['total_reports']}")
            print(f"Abuse Confidence Score: {data['data']['abuse_confidence_score']}")
        else:
            print(f"{Fore.RED}No information available for the IP.")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Failed to perform IP blacklist check.")

def ip_traffic_analysis(ip):
    try:
        print(f"{Fore.GREEN}IP Traffic Analysis for {ip}:")
        # Add your custom traffic analysis logic here
    except Exception as e:
        print(f"{Fore.RED}An error occurred during IP traffic analysis: {e}")

def show_menu():
    print(f"{Fore.CYAN}IP Toolkit Menu:")
    print("1. Scan IP")
    print("2. Port Scan")
    print("3. DNS Lookup")
    print("4. Traceroute")
    print("5. Whois Lookup")
    print("6. Reverse DNS Lookup")
    print("7. GeoIP Lookup")
    print("8. Subnet Calculator")
    print("9. IP Reputation Check")
    print("10. IP Geolocation")
    print("11. IP Range Calculator")
    print("12. IP to MAC Address Lookup")
    print("13. IP to ASN Lookup")
    print("14. IP to Service Mapping")
    print("15. IP Blacklist Check")
    print("16. IP Traffic Analysis")
    print("17. Exit")

def main():

    print(f"""{Fore.RED}
____  _   _ ____  _     _____ ____  
|  _ \| | | |  _ \| |   | ____|  _ \ 
| |_) | | | | |_) | |   |  _| | |_) |
|  __/| |_| |  __/| |___| |___|  _ < 
|_|    \___/|_|   |_____|_____|_| \_\
    """)

    parser = argparse.ArgumentParser(description="Python3 IP Toolkit")
    parser.add_argument("ip", nargs="?", help="IP address or domain name to analyze")
    args = parser.parse_args()

    if args.ip:
        scan_ip(args.ip)
    else:
        while True:
            print(Style.RESET_ALL)
            show_menu()
            choice = input(f"{Fore.YELLOW}Select an option: ")

            if choice == "1":
                ip = input("Enter the IP address to scan: ")
                print(f"{Fore.CYAN}==============================")
                scan_ip(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "2":
                ip = input("Enter the IP address to scan: ")
                print(f"{Fore.CYAN}Port Scan Options:")
                print("1. Simple")
                print("2. Comprehensive")
                print("3. Medium")
                scan_choice = input(f"{Fore.YELLOW}Select a scan type: ")
                if scan_choice == "1":
                    open_ports = port_scan(ip, "simple")
                    print(f"{Fore.GREEN}Open Ports: {Fore.YELLOW}{open_ports}")
                elif scan_choice == "2":
                    open_ports = port_scan(ip, "comprehensive")
                    print(f"{Fore.GREEN}Open Ports: {Fore.YELLOW}{open_ports}")
                elif scan_choice == "3":
                    open_ports = port_scan(ip, "medium")
                    print(f"{Fore.GREEN}Open Ports: {Fore.YELLOW}{open_ports}")
                else:
                    print(f"{Fore.RED}Invalid scan type. Please try again.")
            elif choice == "3":
                domain = input("Enter the domain name to perform DNS lookup: ")
                print(f"{Fore.CYAN}==============================")
                dns_lookup(domain)
                print(f"{Fore.CYAN}==============================")
            elif choice == "4":
                ip = input("Enter the IP address or domain name to perform traceroute: ")
                print(f"{Fore.CYAN}==============================")
                traceroute(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "5":
                domain = input("Enter the domain name to perform Whois lookup: ")
                print(f"{Fore.CYAN}==============================")
                whois_lookup(domain)
                print(f"{Fore.CYAN}==============================")
            elif choice == "6":
                ip = input("Enter the IP address to perform reverse DNS lookup: ")
                print(f"{Fore.CYAN}==============================")
                reverse_dns_lookup(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "7":
                ip = input("Enter the IP address to perform GeoIP lookup: ")
                print(f"{Fore.CYAN}=============================")
                geoip_lookup(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "8":
                ip = input("Enter the IP address: ")
                subnet_mask = input("Enter the subnet mask: ")
                print(f"{Fore.CYAN}==============================")
                subnet_calculator(ip, subnet_mask)
                print(f"{Fore.CYAN}==============================")
            elif choice == "9":
                ip = input("Enter the IP address to check reputation: ")
                print(f"{Fore.CYAN}==============================")
                ip_reputation_check(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "10":
                ip = input("Enter the IP address to perform geolocation: ")
                print(f"{Fore.CYAN}==============================")
                ip_geolocation(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "11":
                ip_range = input("Enter the IP range (start-end): ")
                print(f"{Fore.CYAN}==============================")
                ip_range_calculator(ip_range)
                print(f"{Fore.CYAN}==============================")
            elif choice == "12":
                ip = input("Enter the IP address to perform MAC address lookup: ")
                print(f"{Fore.CYAN}==============================")
                ip_to_mac_address(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "13":
                ip = input("Enter the IP address to perform ASN lookup: ")
                print(f"{Fore.CYAN}==============================")
                ip_to_asn(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "14":
                ip = input("Enter the IP address to perform service mapping: ")
                print(f"{Fore.CYAN}==============================")
                ip_to_service_mapping(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "15":
                ip = input("Enter the IP address to perform blacklist check: ")
                print(f"{Fore.CYAN}==============================")
                ip_blacklist_check(ip)
                print(f"{Fore.CYAN}==============================")
            elif choice == "16":
                ip = input("Enter the IP address to perform traffic analysis: ")
                print(f"{Fore.CYAN}==============================")
                ip_traffic_analysis(ip)
                print(f"{Fore.CYAN}==============================")

            elif choice == "17":
                print(f"{Fore.RED}Exiting IP Toolkit...")
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
    os.system("clear")
