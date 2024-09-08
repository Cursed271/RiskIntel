# ----- License ------------------------------------------- #

# RiskIntel Copyright (C) 2024 Steven Pereira
# This program comes with ABSOLUTELY NO WARRANTY.
# This is free software, and you are welcome to redistribute it under certain conditions.

# ----- Libraries ----------------------------------------- #

import os
import requests
import socket
import time
import subprocess
import ipinfo
import threading
import json
import warnings
import re
from rich.console import Console
from Wappalyzer import Wappalyzer, WebPage

# ----- Global Declaration -------------------------------- #

console = Console()
ip_info_access_token = "" # Add your IpInfo API Key here
abuse_ip_access_token = "" # Add your AbuseDB API Key here
email_api_key = "" # Add your Prospeo API Key here
ssl_versions = {"TLS 1.0": "--tlsv1","TLS 1.1": "--tlsv1_1","TLS 1.2": "--tlsv1_2","TLS 1.3": "--tlsv1_3","SSL 2.0": "--ssl2","SSL 3.0": "--ssl3"}
report_folder_name = 'Reports'
domain_file_name = 'Domains.txt'
alive_domains_file_name = 'Alive_Domains.txt'
generate_ip_file_name = 'IP_Address.txt'
generate_ip_list_file_name = 'IP_List.txt'
ip_info_file_name = 'IP_Info.txt'
abuse_ip_file_name = 'Abuse_IP_Score.txt'
ssl_version_file_name = 'SSL_Versions.txt'
typo_file_name = 'TypoSquatting_Domains.txt'
email_file_name = 'Email_Addresses.txt'
check_records_file_name = 'DNS_Health.txt'
technologies_file_name = 'Technologies.txt'
web_title_file_name = 'Web_Title.txt'
http_headers_file_name = 'HTTP_Headers.txt'
script_dir = os.path.dirname(os.path.abspath(__file__))
report_folder_path = os.path.join(script_dir, report_folder_name)
os.makedirs(report_folder_path, exist_ok=True)
domain_file_path = os.path.join(report_folder_path, domain_file_name)
alive_domains_file_path = os.path.join(report_folder_path, alive_domains_file_name)
generate_ip_file_path = os.path.join(report_folder_path, generate_ip_file_name)
generate_ip_list_file_path = os.path.join(report_folder_path, generate_ip_list_file_name)
ip_info_file_path = os.path.join(report_folder_path, ip_info_file_name)
abuse_ip_file_path = os.path.join(report_folder_path, abuse_ip_file_name)
ssl_version_file_path = os.path.join(report_folder_path, ssl_version_file_name)
typo_file_path = os.path.join(report_folder_path, typo_file_name)
email_file_path = os.path.join(report_folder_path, email_file_name)
check_records_file_path = os.path.join(report_folder_path, check_records_file_name)
technologies_file_path = os.path.join(report_folder_path, technologies_file_name)
web_title_file_path = os.path.join(report_folder_path, web_title_file_name)
http_headers_file_path = os.path.join(report_folder_path, http_headers_file_name)

# ----- Banner -------------------------------------------- #

def banner():
    console.print(rf"""[bold yellow]
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │                                                                                      
│    8888888b.  d8b          888      8888888          888            888    │           
│    888   Y88b Y8P          888        888            888            888    │           
│    888    888              888        888            888            888    │           
│    888   d88P 888 .d8888b  888  888   888   88888b.  888888 .d88b.  888    │           
│    8888888P"  888 88K      888 .88P   888   888 "88b 888   d8P  Y8b 888    │           
│    888 T88b   888 "Y8888b. 888888K    888   888  888 888   88888888 888    │           
│    888  T88b  888      X88 888 "88b   888   888  888 Y88b. Y8b.     888    │           
│    888   T88b 888  88888P' 888  888 8888888 888  888  "Y888 "Y8888  888    │ 
│                                                                            │  
│                                   +-+-+                                    │    
│                             [#c61a09]Made by Cursed271[bold yellow]                              │
│                                   +-+-+                                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘        
    """)
	
# ----- Fetch Domains ------------------------------------- #

def fetch_domains(domain):
	find_td = f"curl -s -k 'https://crt.sh/?q={domain}' | grep '<TD>'"
	grep_domain = f"{find_td} | grep '.{domain}'"
	remove_td = f"{grep_domain} | tr -d '</TD>'"
	remove_spaces = f"{remove_td} | sed 's/^[[:space:]]*//'"
	change_br = f"{remove_spaces} | tr 'BR' '\n'"
	sort_output = f"{change_br} | sort | uniq"
	remove_null = f"{sort_output} | awk 'NF'"
	save_to_file = f"{remove_null} > {domain_file_path}"
	cert_output = os.system(save_to_file)

# ----- Append HTTPS -------------------------------------- #

def add_https(domain):
	if os.path.exists(domain_file_path):
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		with open(domain_file_path, 'w') as file:
			for content in contents:
				file.write(f"https://{content.strip()}\n")
	else:
		fetch_domains(domain)
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		with open(domain_file_path, 'w') as file:
			for content in contents:
				file.write(f"https://{content.strip()}\n")

# ----- Check Alive Domains ------------------------------- #

def alive_domains():
	if os.path.exists(alive_domains_file_path):
		remove_file = os.system(f"rm -r {alive_domains_file_path}")
		with open(domain_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(alive_domains_file_path, 'w') as outfile:
			for content in contents:
				link = content.strip()
				if link:
					try:
						response = requests.get(link, timeout=2)
						status_code = response.status_code
						if status_code == 200:
							outfile.write(f"[+] {link} is active\n")
						else:
							outfile.write("")
					except requests.RequestException as e:
						outfile.write("")
	else:
		with open(domain_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(alive_domains_file_path, 'w') as outfile:
			for content in contents:
				link = content.strip()
				if link:
					try:
						response = requests.get(link, timeout=2)
						status_code = response.status_code
						if status_code == 200:
							outfile.write(f"[+] {link} is active\n")
						else:
							outfile.write("")
					except requests.RequestException as e:
						outfile.write("")

# ----- Generate IP Address ------------------------------- #

def generate_ip():
	if os.path.exists(generate_ip_file_path):
		remove_file = os.system(f"rm -r {generate_ip_file_path}")
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		for content in contents:
			remove_https = content.replace("https://", "")
			remove_backslash = remove_https.replace("\n", "")
			remove_special = remove_backslash.replace("*.", "")
			make_lower = remove_special.lower()
			with open(generate_ip_file_path, 'a') as outfile:
				try:
					ip_address = socket.gethostbyname(make_lower)
					outfile.write(f"The IP Address of {make_lower} is {ip_address}\n")
				except:
					continue
	else:
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		for content in contents:
			remove_https = content.replace("https://", "")
			remove_backslash = remove_https.replace("\n", "")
			remove_special = remove_backslash.replace("*.", "")
			make_lower = remove_special.lower()
			with open(generate_ip_file_path, 'a') as outfile:
				try:
					ip_address = socket.gethostbyname(make_lower)
					outfile.write(f"The IP Address of {make_lower} is {ip_address}\n")
				except:
					continue

# ----- Get IP Address List ------------------------------- #

def generate_ip_list():
	if os.path.exists(generate_ip_list_file_path):
		remove_file = os.system(f"rm -r {generate_ip_list_file_path}")
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		for content in contents:
			remove_https = content.replace("https://", "")
			remove_backslash = remove_https.replace("\n", "")
			remove_special = remove_backslash.replace("*.", "")
			make_lower = remove_special.lower()
			with open(generate_ip_list_file_path, 'a') as outfile:
				try:
					ip_address = socket.gethostbyname(make_lower)
					outfile.write(f"{ip_address}\n")
				except:
					continue
	else:
		with open(domain_file_path, 'r') as file:
			contents = file.readlines()
		for content in contents:
			remove_https = content.replace("https://", "")
			remove_backslash = remove_https.replace("\n", "")
			remove_special = remove_backslash.replace("*.", "")
			make_lower = remove_special.lower()
			with open(generate_ip_list_file_path, 'a') as outfile:
				try:
					ip_address = socket.gethostbyname(make_lower)
					outfile.write(f"{ip_address}\n")
				except:
					continue

# ----- IP Address Information ---------------------------- #

def ip_info():
	if os.path.exists(ip_info_file_path):
		remove_file = os.system(f"rm -r {ip_info_file_path}")
		with open(generate_ip_list_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(ip_info_file_path, 'w') as outfile:
			for content in contents:
				content = content.replace('\n', '')
				ip_info_handler = ipinfo.getHandler(ip_info_access_token)
				details = ip_info_handler.getDetails(content)
				asn = details.org
				asn_split = asn.split()
				outfile.write(f"[+] The ASN for {content} is {asn_split[0]}\n")
	else:
		with open(generate_ip_list_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(ip_info_file_path, 'w') as outfile:
			for content in contents:
				content = content.replace('\n', '')
				ip_info_handler = ipinfo.getHandler(ip_info_access_token)
				details = ip_info_handler.getDetails(content)
				asn = details.org
				asn_split = asn.split()
				outfile.write(f"[+] The ASN for {content} is {asn_split[0]}\n")

# ----- IP Reputation ------------------------------------- #	

def ip_reputation():
	if os.path.exists(abuse_ip_file_path):
		remove_file = os.system(f"rm -r {abuse_ip_file_path}")
		with open(generate_ip_list_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(abuse_ip_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace('\n', '')
				abuse_ip_check = subprocess.run(['curl', '-s', '-G', 'https://api.abuseipdb.com/api/v2/check', '--data-urlencode', f'ipAddress={content}', '-H', f'Key: {abuse_ip_access_token}', '-H', 'Accept: application/json'], capture_output=True, text=True)
				abuse_output = abuse_ip_check.stdout
				response_json = json.loads(abuse_output)
				abuse_score = response_json['data']['abuseConfidenceScore']
				outfile.write(f"[+] Abuse Confidence Score for {content} is {abuse_score}\n")
	else:
		with open(generate_ip_list_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(abuse_ip_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace('\n', '')
				abuse_ip_check = subprocess.run(['curl', '-s', '-G', 'https://api.abuseipdb.com/api/v2/check', '--data-urlencode', f'ipAddress={content}', '-H', f'Key: {abuse_ip_access_token}', '-H', 'Accept: application/json'], capture_output=True, text=True)
				abuse_output = abuse_ip_check.stdout
				response_json = json.loads(abuse_output)
				abuse_score = response_json['data']['abuseConfidenceScore']
				outfile.write(f"[+] Abuse Confidence Score for {content} is {abuse_score}\n")

# ----- TypoSquatting Domains ----------------------------- #

def typosquatting(domain, outfile):
	with open(typo_file_path, 'a') as outfile:
		results = subprocess.run(['dnstwist', '-r', f'{domain}'], capture_output=True, text=True)
		results = results.stdout.splitlines()
		for result in results:
			result = result.split()
			outfile.write(f"[+] Found {result[1]} domain - {result[2]}\n")

def typosquatting_threading(domain):
	if os.path.exists(typo_file_path):
		remove_file = os.system(f"rm -r {typo_file_path}")
		threads = []
		with open(typo_file_path, 'a') as outfile:
			thread = threading.Thread(target=typosquatting, args = (domain, outfile))
			threads.append(thread)
			thread.start()
			for thread in threads:
				thread.join()
	else:
		threads = []
		with open(typo_file_path, 'a') as outfile:
			thread = threading.Thread(target=typosquatting, args = (domain, outfile))
			threads.append(thread)
			thread.start()
			for thread in threads:
				thread.join()

# ----- DNS Checker --------------------------------------- #

def check_records(domain):
	if os.path.exists(check_records_file_path):
		remove_file = os.system(f"rm -r {check_records_file_path}")
		dmarc_domain = f"_dmarc.{domain}"
		mx_record = f"https://dns.google/resolve?name={domain}&type=MX"
		spf_record = f"https://dns.google/resolve?name={domain}&type=TXT"
		dmarc_record = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
		mx_response = requests.get(mx_record)
		spf_response = requests.get(spf_record)
		dmarc_response = requests.get(dmarc_record)
		mx_data = mx_response.json()
		spf_data = spf_response.json()
		dmarc_data = dmarc_response.json()
		mx_command = [answer['data'] for answer in mx_data['Answer']]
		spf_command = [answer['data'] for answer in spf_data['Answer']]
		dmarc_command = [answer['data'] for answer in dmarc_data['Answer']]
		with open(check_records_file_path, 'a') as outfile:
			if mx_command == "":
				outfile.write(f"No MX Record found for {domain}\n")
			else:
				outfile.write(f"MX Record found for {domain}\n")
			if spf_command == "":
				outfile.write(f"No SPF Record found for {domain}\n")
			else:
				outfile.write(f"SPF Record found for {domain}\n")
			if dmarc_command == "":
				outfile.write(f"No DMARC Record found for {domain}\n")
			else:
				outfile.write(f"DMARC Record found for {domain}\n")
	else:
		dmarc_domain = f"_dmarc.{domain}"
		mx_record = f"https://dns.google/resolve?name={domain}&type=MX"
		spf_record = f"https://dns.google/resolve?name={domain}&type=TXT"
		dmarc_record = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
		mx_response = requests.get(mx_record)
		spf_response = requests.get(spf_record)
		dmarc_response = requests.get(dmarc_record)
		mx_data = mx_response.json()
		spf_data = spf_response.json()
		dmarc_data = dmarc_response.json()
		mx_command = [answer['data'] for answer in mx_data['Answer']]
		spf_command = [answer['data'] for answer in spf_data['Answer']]
		dmarc_command = [answer['data'] for answer in dmarc_data['Answer']]
		with open(check_records_file_path, 'a') as outfile:
			if mx_command == "":
				outfile.write(f"No MX Record found for {domain}\n")
			else:
				outfile.write(f"MX Record found for {domain}\n")
			if spf_command == "":
				outfile.write(f"No SPF Record found for {domain}\n")
			else:
				outfile.write(f"SPF Record found for {domain}\n")
			if dmarc_command == "":
				outfile.write(f"No DMARC Record found for {domain}\n")
			else:
				outfile.write(f"DMARC Record found for {domain}\n")

# ----- Email Addresses ----------------------------------- #

def search_emails(domain):
	if os.path.exists(email_file_path):
		remove_file = os.system(f"rm -r {email_file_path}")
		url = 'https://api.prospeo.io/domain-search'
		required_headers={'Content-Type': 'application/json', 'X-KEY': email_api_key}
		data = {'company': domain, 'limit': 49}
		with open(email_file_path, 'a') as outfile:
			response = requests.post(url, json=data, headers=required_headers)
			response_data = response.json()
			email_list = response_data['response']['email_list']
			email_addresses = [email_info['email'] for email_info in email_list]
			outfile.write(f"[+] Found the following email addresses for {domain}:\n")
			for email in email_addresses:
				outfile.write(f"\t{email}\n")
	else:
		url = 'https://api.prospeo.io/domain-search'
		required_headers={'Content-Type': 'application/json', 'X-KEY': email_api_key}
		data = {'company': domain, 'limit': 49}
		with open(email_file_path, 'a') as outfile:
			response = requests.post(url, json=data, headers=required_headers)
			print(response)
			response_data = response.json()
			email_list = response_data['response']['email_list']
			email_addresses = [email_info['email'] for email_info in email_list]
			outfile.write(f"[+] Found the following email addresses for {domain}:\n")
			for email in email_addresses:
				outfile.write(f"\t{email}\n")

# ----- Web Technologies ---------------------------------- #

def check_technologies():
	if os.path.exists(technologies_file_path):
		remove_file = os.system(f"rm -r {technologies_file_path}")
		warnings.filterwarnings("ignore", message="Caught 'unbalanced parenthesis at position")
		warnings.filterwarnings("ignore", message="Traceback (most recent call last)")
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(technologies_file_path, 'a') as outfile: 
			for content in contents:
				content = content.replace(" is active\n", "")
				content = content.replace("[+] ", "")
				response = requests.get(content)
				try:
					webpage = WebPage.new_from_response(response)
					wappalyzer = Wappalyzer.latest()
					technologies = wappalyzer.analyze(webpage)
					if not technologies:
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"[-] No technologies found for {content}\n")
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"\n")
					else:
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"[+] Technologies used on the {content}: \n")
						outfile.write(f"+--------------------------------------------------+\n")
						for technology in technologies:
							outfile.write(f"{technology}\n")
						outfile.write(f"\n")
				except:
					outfile.write("")
	else:
		warnings.filterwarnings("ignore", message="Caught 'unbalanced parenthesis at position")
		warnings.filterwarnings("ignore", message="Traceback (most recent call last)")
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(technologies_file_path, 'a') as outfile: 
			for content in contents:
				content = content.replace(" is active\n", "")
				content = content.replace("[+] ", "")
				response = requests.get(content)
				try:
					webpage = WebPage.new_from_response(response)
					wappalyzer = Wappalyzer.latest()
					technologies = wappalyzer.analyze(webpage)
					if not technologies:
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"[-] No technologies found for {content}\n")
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"\n")
					else:
						outfile.write(f"+--------------------------------------------------+\n")
						outfile.write(f"[+] Technologies used on the {content}: \n")
						outfile.write(f"+--------------------------------------------------+\n")
						for technology in technologies:
							outfile.write(f"{technology}\n")
						outfile.write(f"\n")
				except:
					outfile.write("")

# ----- Web Title ----------------------------------------- #

def website_title():
	if os.path.exists(web_title_file_path):
		remove_file = os.system(f"rm -r {web_title_file_path}")
		warnings.filterwarnings("ignore", message="Unverified HTTPS request is being")
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(web_title_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace(" is active\n", "")
				content = content.replace("[+] ", "")
				try:
					response = requests.get(content, timeout=10, verify=False)
					response.raise_for_status()
					title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
					if title_match:
						outfile.write(f"[+] Title of {content} - {title_match.group(1).strip()}\n")
					else:
						outfile.write(f"[-] No title found for {content}\n")
				except requests.exceptions.RequestException as e:
					outfile.write(f"[-] No title found for {content}\n")
	else:
		warnings.filterwarnings("ignore", message="Unverified HTTPS request is being")
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(web_title_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace(" is active\n", "")
				content = content.replace("[+] ", "")
				try:
					response = requests.get(content, timeout=10, verify=False)
					response.raise_for_status()
					title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
					if title_match:
						outfile.write(f"[+] Title of {content} - {title_match.group(1).strip()}\n")
					else:
						outfile.write(f"[-] No title found for {content}\n")
				except requests.exceptions.RequestException as e:
					outfile.write(f"[-] No title found for {content}\n")

# ----- HTTP Headers -------------------------------------- #

def http_headers():
	if os.path.exists(http_headers_file_path):
		remove_file = os.system(f"rm -r {http_headers_file_path}")
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(http_headers_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace("[+] ", "")
				content = content.replace(" is active\n", "")
				header_command = subprocess.run(['curl', '-I', '-s', '-k', f'{content}'], capture_output=True, text=True)
				outfile.write(f"[+] HTTP Headers for {content}:\n")
				outfile.write(f"{header_command.stdout}\n")
	else:
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(http_headers_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace("[+] ", "")
				content = content.replace(" is active\n", "")
				header_command = subprocess.run(['curl', '-I', '-s', '-k', f'{content}'], capture_output=True, text=True)
				outfile.write(f"[+] HTTP Headers for {content}:\n")
				outfile.write(f"{header_command.stdout}\n")

# ----- SSL/TLS Versions ---------------------------------- #

def ssl_version(content, outfile):
	outputs = {}
	for version_name, option in ssl_versions.items():
		result = subprocess.run(['sslyze', f'{content}', option], capture_output=True, text=True)
		outputs[version_name] = result.stdout.splitlines()
	for version_name, output_lines in outputs.items():
		if any("The server accepted " in line for line in output_lines):
			outfile.write(f"[+] The server - {content} is using {version_name}\n")
	if not any("The server accepted " in line for output_lines in outputs.values() for line in output_lines):
		outfile.write("No supported TLS/SSL versions found\n")

def ssl_version_threading():
	if os.path.exists(ssl_version_file_path):
		remove_file = os.system(f"rm -r {ssl_version_file_path}")
		threads = []
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(ssl_version_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace('[+] https://', '')
				content = content.replace(' is active\n', '')
				thread = threading.Thread(target=ssl_version, args=(content, outfile))
				threads.append(thread)
				thread.start()
			for thread in threads:
				thread.join()
	else:
		threads = []
		with open(alive_domains_file_path, 'r') as infile:
			contents = infile.readlines()
		with open(ssl_version_file_path, 'a') as outfile:
			for content in contents:
				content = content.replace('[+] https://', '')
				content = content.replace(' is active\n', '')
				thread = threading.Thread(target=ssl_version, args=(content, outfile))
				threads.append(thread)
				thread.start()
			for thread in threads:
				thread.join()

# ----- Menu ---------------------------------------------- #

def menu():
	console.print("[#0000ff]+----------------------------------------------------------------------------+")
	domain = console.input("[bold yellow]+ Enter the Domain name that you want to enumerate: ")
	console.print("[#0000ff]+----------------------------------------------------------------------------+")
	console.print("[#0000ff]+ Enumerating Identities from Crt.sh...")
	fetch_domains(domain)
	add_https(domain)
	time.sleep(2)
	console.print("[#0000ff]+ Checking Identities that are Alive...")
	alive_domains()
	time.sleep(2)
	console.print("[#0000ff]+ Extracting IP Address...")
	generate_ip()
	generate_ip_list()
	time.sleep(2)
	console.print("[#0000ff]+ Extracting IP Netblocks...")
	ip_info()
	time.sleep(2)
	console.print("[#0000ff]+ Checking the IP Abuse Score...")
	ip_reputation()
	time.sleep(2)
	console.print("[#0000ff]+ Extracting Typosquatting Domains...")
	typosquatting_threading(domain)
	time.sleep(2)
	console.print("[#0000ff]+ Extracting Email Addresses...")
	search_emails(domain)
	time.sleep(2)
	console.print("[#0000ff]+ Checking DNS Health...")
	check_records(domain)
	time.sleep(2)
	console.print("[#0000ff]+ Extracting Web Technologies...")
	check_technologies()
	time.sleep(2)
	console.print("[#0000ff]+ Extracting Web Titles...")
	website_title()
	time.sleep(2)
	console.print("[#0000ff]+ Extracting HTTP Headers...")
	http_headers()
	time.sleep(2)
	console.print("[#0000ff]+ Checking SSL/TLS versions...")
	ssl_version_threading()
	time.sleep(2)
	console.print("[#0000ff]+----------------------------------------------------------------------------+")
	console.print(f"[#66ff00]+ Your files are stored in {report_folder_path}")
	console.print("[#0000ff]+----------------------------------------------------------------------------+")

# ----- Main Function ------------------------------------- #

if __name__=="__main__":
	banner()
	menu()

# ----- End ----------------------------------------------- #
