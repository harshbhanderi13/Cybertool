import re
import subprocess
import sys
import time
import random
import requests
import os
import sqlite3
from socket import gethostbyname, gethostbyaddr
from datetime import datetime
from colorama import Fore, Style, init

DB_FILE = "recon.db"
init(autoreset=True)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
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
def save_scan(domain, subdomain, ip, scan_type, result):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    INSERT INTO scans (domain, subdomain, ip, scan_type, result, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (domain, subdomain, ip, scan_type, result, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Validate domain format
def validate_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain)

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
Version: 1.0
-------------------------------{Style.RESET_ALL}"""
    print(banner)
    loading_animation()

# Display menu
def show_menu():
    menu = f"""{Fore.CYAN}Choose scan type:
    {Fore.GREEN}1. Beginner Scan
    {Fore.YELLOW}2. Intermediate Scan
    {Fore.RED}3. Hard Scam/Phishing Analysis
    {Fore.BLUE}4. Subdomain Enumeration (Amass + theHarvester)
    """
    choice = input(f"{menu}{Fore.CYAN}Enter your choice (1-4): ")
    return choice

# Beginner scan
def beginner_scan(domain):
    print(f"\n{Fore.GREEN}[+] Running WHOIS Scan...")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "WHOIS", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] WHOIS failed: {e}")

    print(f"\n{Fore.GREEN}[+] Running DNS Lookup...")
    try:
        response = requests.get(f"https://dns.google/resolve?name={domain}")
        print(response.json())
        save_scan(domain, None, None, "DNS Lookup", str(response.json()))
    except Exception as e:
        print(f"{Fore.RED}[!] DNS Lookup failed: {e}")

    print(f"\n{Fore.GREEN}[+] Running Ping Test...")
    try:
        result = subprocess.run(["ping", "-c", "3", domain], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "Ping Test", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Ping Test failed: {e}")

# Intermediate scan
def intermediate_scan(domain):
    print(f"\n{Fore.YELLOW}[+] Running Full Port Scan with Nmap...")
    try:
        result = subprocess.run(["nmap", "-p-", domain], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "Nmap Full Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nmap Full Scan failed: {e}")

    print(f"\n{Fore.YELLOW}[+] Running Reverse IP Lookup...")
    try:
        ip = gethostbyname(domain)
        reverse = gethostbyaddr(ip)
        print(f"{Fore.MAGENTA}Reverse IP Info: {reverse}")
        save_scan(domain, None, ip, "Reverse IP", str(reverse))
    except Exception as e:
        print(f"{Fore.RED}[!] Reverse IP Lookup failed: {e}")

# Hard scan
def hard_scan(domain):
    print(f"\n{Fore.RED}[+] Running Aggressive Nmap Scan...")
    try:
        result = subprocess.run(["nmap", "-A", domain], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "Nmap Aggressive Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nmap Aggressive Scan failed: {e}")

    print(f"\n{Fore.RED}[+] Running Nikto Vulnerability Scan...")
    try:
        result = subprocess.run(["nikto", "-h", domain], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "Nikto Scan", result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Nikto Scan failed: {e}")

# Subdomain enumeration
def subdomain_enumeration(domain):
    print(f"\n{Fore.BLUE}[+] Starting Subdomain Enumeration...")

    print(f"\n{Fore.CYAN}[+] Using Amass...")
    try:
        result = subprocess.run(["amass", "enum", "-d", domain], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.strip().endswith(domain):
                subdomain = line.strip()
                try:
                    ip = gethostbyname(subdomain)
                    print(f"{Fore.GREEN}[✔️] Found: {subdomain} -> {ip}")
                    save_scan(domain, subdomain, ip, "amass", "resolved")
                except:
                    save_scan(domain, subdomain, "", "amass", "unresolved")
    except Exception as e:
        print(f"{Fore.RED}[❌] Amass failed: {e}")

    print(f"\n{Fore.CYAN}[+] Using theHarvester...")
    try:
        result = subprocess.run(["theHarvester", "-d", domain, "-b", "all"], capture_output=True, text=True)
        print(result.stdout)
        save_scan(domain, None, None, "theHarvester", "harvested")
    except Exception as e:
        print(f"{Fore.RED}[❌] theHarvester failed: {e}")

    print(f"\n{Fore.CYAN}[+] Optional: Brute-forcing subdomains...")
    wordlist_path = "/usr/share/wordlists/amass/subdomains-top1mil-110000.txt"
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            for sub in f:
                subdomain = f"{sub.strip()}.{domain}"
                try:
                    ip = gethostbyname(subdomain)
                    print(f"{Fore.GREEN}[✔️] Found: {subdomain} -> {ip}")
                    save_scan(domain, subdomain, ip, "brute", "resolved")
                except:
                    continue
    else:
        print(f"{Fore.YELLOW}[!] Wordlist '{wordlist_path}' not found.")

# Main function
def main():
    init_db()
    show_banner()
    domain = input(f"{Fore.CYAN}Enter domain (example: example.com): ").strip()

    if not validate_domain(domain):
        print(f"{Fore.RED}Invalid domain format! Example: example.com")
        sys.exit(1)

    choice = show_menu()
    print(f"{Fore.CYAN}Wait for result...")

    if choice == '1':
        beginner_scan(domain)
    elif choice == '2':
        intermediate_scan(domain)
    elif choice == '3':
        hard_scan(domain)
    elif choice == '4':
        subdomain_enumeration(domain)
    else:
        print(f"{Fore.RED}Invalid choice! Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
