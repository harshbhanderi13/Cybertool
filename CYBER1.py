import re
import subprocess
import sys
import time
import random
import requests
import os
import sqlite3
from socket import gethostbyname, gethostbyaddr, gaierror
from datetime import datetime
from colorama import Fore, Style, init
import ipaddress

DB_FILE = "recon.db"
init(autoreset=True)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        target_type TEXT,
        subdomain TEXT,
        ip TEXT,
        scan_type TEXT,
        result TEXT,
        timestamp DATETIME
    )
    """)
    conn.commit()
    conn.close()

# Save scan result to database
def save_scan(target, target_type, subdomain, ip, scan_type, result):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    INSERT INTO scans (target, target_type, subdomain, ip, scan_type, result, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (target, target_type, subdomain, ip, scan_type, result, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Validate domain format
def validate_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain)

# Validate IP address format
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Extract domain from URL
def extract_domain_from_url(url):
    # Remove protocol if present
    if url.startswith(('http://', 'https://')):
        url = url.split('://', 1)[1]
    
    # Remove path, query parameters, etc.
    url = url.split('/')[0].split('?')[0].split('#')[0]
    
    # Remove port if present
    url = url.split(':')[0]
    
    return url

# Determine input type and process accordingly
def process_input(user_input):
    user_input = user_input.strip()
    
    # Check if it's an IP address
    if validate_ip(user_input):
        print(f"{Fore.GREEN}[+] Detected IP address: {user_input}")
        return user_input, "ip"
    
    # Check if it's a URL or domain
    domain = extract_domain_from_url(user_input)
    
    if validate_domain(domain):
        print(f"{Fore.GREEN}[+] Detected domain: {domain}")
        return domain, "domain"
    
    return None, None

# Get IP from domain or return IP if already IP
def get_target_ip(target, target_type):
    if target_type == "ip":
        return target
    else:
        try:
            return gethostbyname(target)
        except gaierror:
            return None

# Display a loading animation
def loading_animation():
    loading_text = f"{Fore.CYAN}Wait for the tool to be ready in sec..."
    print(f"{loading_text}\n")
    time.sleep(1)
    for i in range(4):
        print(f"{loading_text} {'.' * (i+1)}", end="\r")
        time.sleep(0.5)

# Show banner
def show_banner():
    banner = f"""{Fore.LIGHTCYAN_EX}
░▒█▀▀▄░█░░█░█▀▀▄░█▀▀░█▀▀▄░▀█▀░▄▀▀▄░▄▀▀▄░█░
░▒█░░░░█▄▄█░█▀▀▄░█▀▀░█▄▄▀░░█░░█░░█░█░░█░█░
░▒█▄▄▀░▄▄▄▀░▀▀▀▀░▀▀▀░▀░▀▀░░▀░░░▀▀░░░▀▀░░▀▀
{Style.RESET_ALL}
{Fore.GREEN}
-------------------------------
Project: Internship
Author : harsh bhanderi
Version: 2.0 (Enhanced)
-------------------------------{Style.RESET_ALL}"""
    print(banner)
    loading_animation()

# Display menu
def show_menu():
    menu = f"""{Fore.CYAN}Choose scan type:
    {Fore.GREEN}1. Beginner Scan
    {Fore.YELLOW}2. Intermediate Scan
    {Fore.RED}3. Hard Scam/Phishing Analysis
    {Fore.BLUE}4. Subdomain Enumeration (Domain only)
    """
    choice = input(f"{menu}{Fore.CYAN}Enter your choice (1-4): ")
    return choice

# Beginner scan (works with both domain and IP)
def beginner_scan(target, target_type):
    target_ip = get_target_ip(target, target_type)
    
    if target_type == "domain":
        print(f"\n{Fore.GREEN}[+] Running WHOIS Scan...")
        try:
            result = subprocess.run(["whois", target], capture_output=True, text=True)
            print(result.stdout)
            save_scan(target, target_type, None, target_ip, "WHOIS", result.stdout)
        except Exception as e:
            print(f"{Fore.RED}[!] WHOIS failed: {e}")

        print(f"\n{Fore.GREEN}[+] Running DNS Lookup...")
        try:
            response = requests.get(f"https://dns.google/resolve?name={target}")
            print(response.json())
            save_scan(target, target_type, None, target_ip, "DNS Lookup", str(response.json()))
        except Exception as e:
            print(f"{Fore.RED}[!] DNS Lookup failed: {e}")
    
    else:  # IP address
        print(f"\n{Fore.GREEN}[+] Running WHOIS Scan on IP...")
        try:
            result = subprocess.run(["whois", target], capture_output=True, text=True)
            print(result.stdout)
            save_scan(target, target_type, None, target, "WHOIS", result.stdout)
        except Exception as e:
            print(f"{Fore.RED}[!] WHOIS failed: {e}")

        print(f"\n{Fore.GREEN}[+] Running Reverse DNS Lookup...")
        try:
            reverse = gethostbyaddr(target)
            print(f"{Fore.MAGENTA}Reverse DNS: {reverse}")
            save_scan(target, target_type, None, target, "Reverse DNS", str(reverse))
        except Exception as e:
            print(f"{Fore.RED}[!] Reverse DNS Lookup failed: {e}")

    print(f"\n{Fore.GREEN}[+] Running Ping Test...")
    try:
        result = subprocess.run(["ping", "-c", "3", target], capture_output=True, text=True)
        print(result.stdout)
        save_scan(target, target_type, None, target_ip, "Ping Test", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Ping Test failed: {e}")

# Intermediate scan (works with both domain and IP)
def intermediate_scan(target, target_type):
    target_ip = get_target_ip(target, target_type)
    
    print(f"\n{Fore.YELLOW}[+] Running Full Port Scan with Nmap...")
    try:
        result = subprocess.run(["nmap", "-p-", target], capture_output=True, text=True)
        print(result.stdout)
        save_scan(target, target_type, None, target_ip, "Nmap Full Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nmap Full Scan failed: {e}")

    if target_type == "domain":
        print(f"\n{Fore.YELLOW}[+] Running Reverse IP Lookup...")
        try:
            ip = gethostbyname(target)
            reverse = gethostbyaddr(ip)
            print(f"{Fore.MAGENTA}Reverse IP Info: {reverse}")
            save_scan(target, target_type, None, ip, "Reverse IP", str(reverse))
        except Exception as e:
            print(f"{Fore.RED}[!] Reverse IP Lookup failed: {e}")
    else:  # IP address
        print(f"\n{Fore.YELLOW}[+] Running Reverse DNS Lookup...")
        try:
            reverse = gethostbyaddr(target)
            print(f"{Fore.MAGENTA}Reverse DNS Info: {reverse}")
            save_scan(target, target_type, None, target, "Reverse DNS", str(reverse))
        except Exception as e:
            print(f"{Fore.RED}[!] Reverse DNS Lookup failed: {e}")

# Hard scan (works with both domain and IP)
def hard_scan(target, target_type):
    target_ip = get_target_ip(target, target_type)
    
    print(f"\n{Fore.RED}[+] Running Aggressive Nmap Scan...")
    try:
        result = subprocess.run(["nmap", "-A", target], capture_output=True, text=True)
        print(result.stdout)
        save_scan(target, target_type, None, target_ip, "Nmap Aggressive Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nmap Aggressive Scan failed: {e}")

    print(f"\n{Fore.RED}[+] Running Nikto Vulnerability Scan...")
    try:
        result = subprocess.run(["nikto", "-h", target], capture_output=True, text=True)
        print(result.stdout)
        save_scan(target, target_type, None, target_ip, "Nikto Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nikto Scan failed: {e}")

# Subdomain enumeration (only works with domains)
def subdomain_enumeration(target, target_type):
    if target_type == "ip":
        print(f"{Fore.RED}[!] Subdomain enumeration only works with domains, not IP addresses!")
        return
    
    print(f"\n{Fore.BLUE}[+] Starting Subdomain Enumeration...")

    print(f"\n{Fore.CYAN}[+] Using Amass...")
    try:
        result = subprocess.run(["amass", "enum", "-d", target], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.strip().endswith(target):
                subdomain = line.strip()
                try:
                    ip = gethostbyname(subdomain)
                    print(f"{Fore.GREEN}[✔️] Found: {subdomain} -> {ip}")
                    save_scan(target, target_type, subdomain, ip, "amass", "resolved")
                except:
                    save_scan(target, target_type, subdomain, "", "amass", "unresolved")
    except Exception as e:
        print(f"{Fore.RED}[❌] Amass failed: {e}")

    print(f"\n{Fore.CYAN}[+] Using theHarvester...")
    try:
        result = subprocess.run(["theHarvester", "-d", target, "-b", "all"], capture_output=True, text=True)
        print(result.stdout)
        save_scan(target, target_type, None, None, "theHarvester", "harvested")
    except Exception as e:
        print(f"{Fore.RED}[❌] theHarvester failed: {e}")

    print(f"\n{Fore.CYAN}[+] Optional: Brute-forcing subdomains...")
    wordlist_path = "/usr/share/wordlists/amass/subdomains-top1mil-110000.txt"
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            for sub in f:
                subdomain = f"{sub.strip()}.{target}"
                try:
                    ip = gethostbyname(subdomain)
                    print(f"{Fore.GREEN}[✔️] Found: {subdomain} -> {ip}")
                    save_scan(target, target_type, subdomain, ip, "brute", "resolved")
                except:
                    continue
    else:
        print(f"{Fore.YELLOW}[!] Wordlist '{wordlist_path}' not found.")

# Main function
def main():
    init_db()
    show_banner()
    
    user_input = input(f"{Fore.CYAN}Enter domain/URL or IP address (examples: example.com, https://example.com, 8.8.8.8): ").strip()
    
    target, target_type = process_input(user_input)
    
    if not target or not target_type:
        print(f"{Fore.RED}Invalid input! Please enter a valid domain, URL, or IP address.")
        print(f"{Fore.YELLOW}Examples: example.com, https://example.com, 192.168.1.1")
        sys.exit(1)
    
    choice = show_menu()
    print(f"{Fore.CYAN}Wait for result...")

    if choice == '1':
        beginner_scan(target, target_type)
    elif choice == '2':
        intermediate_scan(target, target_type)
    elif choice == '3':
        hard_scan(target, target_type)
    elif choice == '4':
        subdomain_enumeration(target, target_type)
    else:
        print(f"{Fore.RED}Invalid choice! Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()