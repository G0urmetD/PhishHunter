import os
import time
import argparse
import subprocess
import requests
import json
import configparser
from colorama import Fore, Style
import whois
from datetime import datetime
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor

def get_api_key():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config['abuseipdb']['api']

def retry_request(func, retries=3, delay=5):
    for attempt in range(retries):
        try:
            return func()
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Error: {e}. Retrying {attempt + 1}/{retries} in {delay} seconds...")
            time.sleep(delay)
    raise Exception(f"{Fore.RED}[!]{Style.RESET_ALL} Failed after multiple retries.")

def dnstwist_use(targets, output_file='dnstwist_output.json'):
    print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} Starting dnstwist for {targets}...")

    # check if file exists, if not, remove it
    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        subprocess.run(['dnstwist', '-r', '--format', 'json', '-o', output_file, targets], check=True)

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

    #response = requests.get(url, headers=headers, params=params)
    response = retry_request(lambda: requests.get(url, headers=headers, params=params)) # calls the retry function, if api requests fails, it will try again
    response.raise_for_status()
    return response.json()

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date
    except whois.parser.PywhoisError as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} WHOIS lookup failed for {domain}: Domain not found or privacy protection.")
        return "Unknown"
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} WHOIS lookup failed for {domain}: {e}")
        return "Unknown"

def process_domain(targets):
    data = dnstwist_use(targets)
    domain_ip_table = []

    # Table for domain and IP information
    for entry in data:
        domain = entry.get('domain')
        ip = entry.get('dns_a', [])
        if not domain or not ip:
            continue

        # Add domain and IPs to the table
        for ip_address in ip:
            domain_ip_table.append([domain, ip_address])

    # Print the domain and IP table
    if domain_ip_table:
        print(f"\n{Fore.YELLOW}[i]{Style.RESET_ALL} Domains and IP addresses found:")
        print(tabulate(domain_ip_table, headers=["Domain", "IP-address"], tablefmt="pretty"))
    
    # Proceed with AbuseIPDB check
    for domain, ip_address in domain_ip_table:
        abuse_info = api_abuseipdb(ip_address)
        creation_date = get_whois_info(domain)

        # Prepare AbuseIPDB data for table
        abuse_data = abuse_info.get('data', {})
        abuse_table = [
            ["IP Address", abuse_data.get('ipAddress')],
            ["Is Public", abuse_data.get('isPublic')],
            ["Abuse Confidence Score", abuse_data.get('abuseConfidenceScore')],
            ["Country", abuse_data.get('countryName')],
            ["ISP", abuse_data.get('isp')],
            ["Total Reports", abuse_data.get('totalReports')],
            ["Creation Date", creation_date]
        ]

        # Print AbuseIPDB table
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Domain: {domain} - IP: {ip_address}")
        print(tabulate(abuse_table, tablefmt="pretty"))

        # Print Reports if available
        reports = abuse_data.get('reports', [])
        if reports:
            print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} Reports for IP {ip_address}:")
            report_table = []
            for report in reports:
                report_table.append([report.get('reportedAt'), report.get('comment')])
            print(tabulate(report_table, headers=["Reported At", "Comment"], tablefmt="pretty"))
        else:
            print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} No reports found for IP {ip_address}.")

def cleanup_temp_files(output_file):
    try:
        with open(output_file, 'r') as file:
        #if os.path.exists(output_file):
            os.remove(output_file)
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to remove file {output_file}: {e}")

# adding multithreading for multiple domains
def process_domain_concurrent(domains):
    # max_workers defines the count of parallel threads
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(process_domain, domains)

def main():
    print(r"""
        ______ _     _     _     _   _             _            
        | ___ \ |   (_)   | |   | | | |           | |           
        | |_/ / |__  _ ___| |__ | |_| |_   _ _ __ | |_ ___ _ __ 
        |  __/| '_ \| / __| '_ \|  _  | | | | '_ \| __/ _ \ '__|
        | |   | | | | \__ \ | | | | | | |_| | | | | ||  __/ |   
        \_|   |_| |_|_|___/_| |_\_| |_/\__,_|_| |_|\__\___|_|   

        Author: G0urmetD
        Version: 0.6
    """)
    
    parser = argparse.ArgumentParser(description="Find possible phishing campaign domains.")
    parser.add_argument('-targets', nargs='+', help="Defines one or multiple target domains.")
    parser.add_argument("-t-file", help="Defines target domains in a txt file.")
    parser.add_argument("-max-age", help="Max age of AbuseIPDB data in days.", type=int, default=90)
    parser.add_argument("-clean", action='store_true', help="Removes the temporary file.")

    args = parser.parse_args()

    output_file = "dnstwist_output.json"
    # Check if clean switch is enabled
    if args.clean:
        cleanup_temp_files(output_file)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} dnstwist_output.json was removed.")
        return # Exit the program after cleaning, no further checks needed

    if args.targets:
        process_domain_concurrent(args.targets) # iterate throught the list, because dnstwist wants single strings
    elif args.t_file:
        with open(args.t_file, 'r') as file:
            domains = [domain.strip() for domain in file.readlines() if domain.strip()]
            if domains:
                # Parallel processing of multiple domains
                process_domain_concurrent(domains)
            else:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} No valid domains found in the file.")
    else:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} No targets specified. Use -targets or -t-file.")

if __name__ == "__main__":
    main()
