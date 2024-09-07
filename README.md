# PhishHunter
PhishHunter is a security tool designed to identify and analyse potential phishing domains and IP addresses. The tool utilises dnstwist's domain name permutation engine to scan variant domains that could be mistaken for a target domain. These domains are checked for their registration status and IP addresses.

Additionally, the IP addresses are matched against the AbuseIPDB database to check for potentially malicious activity such as abuse reports and the Abuse Confidence Score. The tool also provides WHOIS queries to determine the creation date of the domains found.

The output is clearly structured and provides only the most relevant information, such as the IP address, abuse level, ISP, country of origin and comments from reported incidents. PhishHunter is a valuable tool for security researchers and IT security departments to recognise and prevent phishing campaigns at an early stage.

# Preparation
Install all requirements:
```bash
pip3 install -r requirements.txt
```

Configure the 'config.ini' file with your AbuseIPDB API key:
```ini
[abuseipdb]
api=<API-KEY>
```

# Usage
```bash
        ______ _     _     _     _   _             _
        | ___ \ |   (_)   | |   | | | |           | |
        | |_/ / |__  _ ___| |__ | |_| |_   _ _ __ | |_ ___ _ __
        |  __/| '_ \| / __| '_ \|  _  | | | | '_ \| __/ _ \ '__|
        | |   | | | | \__ \ | | | | | | |_| | | | | ||  __/ |
        \_|   |_| |_|_|___/_| |_\_| |_/\__,_|_| |_|\__\___|_|

        Author: G0urmetD
        Version: 0.6

usage: typo.py [-h] [-targets TARGETS [TARGETS ...]] [-t-file T_FILE] [-clean]

Find possible phishing campaign domains.

options:
  -h, --help            show this help message and exit
  -targets TARGETS [TARGETS ...]
                        Defines one or multiple target domains.
  -t-file T_FILE        Defines target domains in a txt file.
  -clean                Removes the temporary file.
```

# Example
## Single Domain
```bash
python3 typo.py -targets <domain>
```

## Multiple Domains
```bash
python3 typo.py -targets <domain1> <domain2> <domain3>
```
OR

Craft a new txt file with some domains to check:
```bash
domain1
domain2
domain3
```

Then execute the tool with -t-file parameter and txt as input:
```bash
python3 typo.py -t-file target-domains.txt
```
