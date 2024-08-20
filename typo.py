import os
import argparse
import subprocess
import requests
import json
import configparser
from colorama import Fore, Style
import whois
from datetime import datetime

def get_api_key():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config['abuseipdb']['api']

def dnstwist_use(target, output_file='dnstwist_output.json'):
    print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} Starting dnstwist for {target}...")

    # check if file exists, if not, remove it
    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        subprocess.run(['dnstwist', '-r', '--format', 'json', '-o', output_file, target], check=True)

        # JSON-Datei einlesen
        with open(output_file, 'r') as f:
            data = json.load(f)
        return data
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} dnstwist execution failed: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} JSON parsing failed: {e}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} An error occurred: {e}")
        return []

def api_abuseipdb(target_ip, verbose=True, max_age_in_days=90):
    api_key = get_api_key()
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        "ipAddress": target_ip,
        "maxAgeInDays": max_age_in_days,
        "verbose": str(verbose).lower()
    }

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} WHOIS lookup failed for {domain}: {e}")
        return None

def process_domain(target):
    data = dnstwist_use(target)
    for entry in data:
        domain = entry.get('domain')
        ip = entry.get('dns_a', [])
        if not domain or not ip:
            continue

        # Check each IP address found
        for ip_address in ip:
            abuse_info = api_abuseipdb(ip_address)
            creation_date = get_whois_info(domain)

            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Domain: {domain}")
            print(f"    IP: {ip_address}")
            print(f"    Creation Date: {creation_date}")

            abuse_data = abuse_info.get('data', {})
            print(f"    AbuseIPDB Info:")
            print(f"        IP Address: {abuse_data.get('ipAddress')}")
            print(f"        Is Public: {abuse_data.get('isPublic')}")
            print(f"        Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore')}")
            print(f"        Country: {abuse_data.get('countryName')}")
            print(f"        ISP: {abuse_data.get('isp')}")
            print(f"        Total Reports: {abuse_data.get('totalReports')}")

            reports = abuse_data.get('reports', [])
            if reports:
                print(f"        Reports:")
                for report in reports:
                    print(f"            Reported At: {report.get('reportedAt')}")
                    print(f"            Comment: {report.get('comment')}")
            else:
                print(f"        Reports: None")

def main():
    print(r"""
        ______ _     _     _     _   _             _            
        | ___ \ |   (_)   | |   | | | |           | |           
        | |_/ / |__  _ ___| |__ | |_| |_   _ _ __ | |_ ___ _ __ 
        |  __/| '_ \| / __| '_ \|  _  | | | | '_ \| __/ _ \ '__|
        | |   | | | | \__ \ | | | | | | |_| | | | | ||  __/ |   
        \_|   |_| |_|_|___/_| |_\_| |_/\__,_|_| |_|\__\___|_|   

        Author: G0urmetD
        Version: 0.1
    """)
    
    parser = argparse.ArgumentParser(description="Find possible phishing campaign domains")
    parser.add_argument("-target", help="Defines the target domain")
    parser.add_argument("-t-file", help="Defines target domains in a txt file")

    args = parser.parse_args()

    if args.target:
        process_domain(args.target)
    elif args.t_file:
        with open(args.t_file, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                if domain:
                    process_domain(domain)
    else:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} No target specified. Use -target or -t-file.")

if __name__ == "__main__":
    main()
