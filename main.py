# Tool to use only for professional and educational purposes.
# Tool using 2 different API that can be seen below.

# Possibility to also use : ipdata.co
import os
import requests
import socket
import whois
from art import *
from urllib.parse import urlparse

def cls():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def fetch(url):
    """Fetch the content of a URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def banner():
    print("Use for professional purposes/educational content only")
    print ("                                                ")
    print ("                   -    -                       ")
    print ("                    ____                        ")
    print("------------------------------------------------")
    print("       INFORMATION GATHERING TOOLS")
    print("------------------------------------------------")
    tprint("yoInfo", font="random")

def menu():
    """Display the main menu."""
    print("[+] 1. Whois Lookup")
    print("[+] 2. DNS Lookup + Cloudflare Detector")
    print("[+] 3. Geo-IP Lookup")
    print("[+] 4. HTTP Header Info")
    print("[+] 5. Link Grabber")
    print("[+] 6. Reverse IP Lookup")
    print("[+] 7. IP Tracker")
    print("[+] 0. Exit")

def whois_lookup(domain):
    """Perform a Whois lookup."""
    try:
        domain_info = whois.whois(domain)
        print(domain_info)
    except Exception as e:
        print(f"Error fetching Whois data: {e}")

def dns_lookup(domain):
    """Perform DNS lookup and check for Cloudflare protection."""
    ns = f"http://api.hackertarget.com/dnslookup/?q={domain}"
    response = fetch(ns)
    if response:
        print(response)
        if 'cloudflare' in response.lower():
            print("Cloudflare Detected!")
        else:
            print("Not Protected by Cloudflare")

def geo_ip_lookup(ip):
    """Fetch geographic information about the IP."""
    geo = f"http://ip-api.com/json/{ip}"
    response = fetch(geo)
    if response:
        print(response)

def http_header_info(domain):
    """Fetch HTTP headers for a given domain."""
    header = f"http://api.hackertarget.com/httpheaders/?q={domain}"
    response = fetch(header)
    if response:
        print(response)

def link_grabber(url):
    """Fetch and print links from a given URL."""
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    crawl = f"https://api.hackertarget.com/pagelinks/?q={url}"
    response = fetch(crawl)
    if response:
        print(response)

def reverse_ip_lookup(ip):
    """Perform a reverse IP lookup."""
    lookup = f"http://api.hackertarget.com/reverseiplookup/?q={ip}"
    response = fetch(lookup)
    if response:
        print(response)

def ip_tracker():
    """Track an IP address and display information."""
    ip = input("Enter an IP address to track: ")
    if validate_ip(ip):
        info = get_ip_info(ip)
        if info:
            print_ip_info(info)
    else:
        print("Invalid IP format.")

def validate_ip(ip):
    """Validate the IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            return False
    return True

def get_ip_info(ip):
    """Fetch IP information from ip-api.com."""
    url = f"http://ip-api.com/json/{ip}"
    response = fetch(url)
    if response:
        return response.json()
    return None

def print_ip_info(info):
    """Print the IP information in a formatted way."""
    if info['status'] == 'success':
        print(f"\nInformation for IP: {info['query']}")
        print(f"IP: {info['query']}")
        print(f"Type: {info['type']}")
        print(f"Continent: {info['continent']}")
        print(f"Country: {info['country']}")
        print(f"Region: {info['regionName']}")
        print(f"City: {info['city']}")
        print(f"Zip: {info['zip']}")
        print(f"ISP: {info['isp']}")
        print(f"Latitude: {info['lat']:.4f}, Longitude: {info['lon']:.4f}")
    else:
        print(f"Error: {info['message']}")

def main():
    cls()
    banner()
    while True:
        menu()
        choice = input('Enter your choice: ')
        if choice == '1':
            domain = input('Enter Domain or IP Address: ')
            whois_lookup(domain)
        elif choice == '2':
            domain = input('Enter Domain: ')
            dns_lookup(domain)
        elif choice == '3':
            ip = input('Enter IP Address: ')
            geo_ip_lookup(ip)
        elif choice == '4':
            domain = input('Enter Domain or IP Address: ')
            http_header_info(domain)
        elif choice == '5':
            url = input('Enter URL: ')
            link_grabber(url)
        elif choice == '6':
            ip = input('Enter IP Address: ')
            reverse_ip_lookup(ip)
        elif choice == '7':
            ip_tracker()
        elif choice == '0':
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid option! Please try again.")

if __name__ == "__main__":
    main()
