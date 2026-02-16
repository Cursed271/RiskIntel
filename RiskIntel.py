# ----- License -------------------------------------------------- # 

#  RiskIntel - RiskIntel is an open-source recon tool for ethical hacking, domain enumeration, and threat analysis tasks.
#  Copyright (c) 2025 - CursedSec (Operated by Cursed271). All rights reserved.

#  This software is an proprietary intellectual property developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the CURSEDSEC OWNERSHIP EDICT:
#
#  🚫 PROHIBITION WARNING 🚫
#  Redistribution, re-uploading, and unauthorized modification are strictly forbidden 
#  under the COE. Use is granted ONLY under the limited terms defined in the official 
#  LICENSE file (COE), which must be included in all copies.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 LICENSE: CURSEDSEC OWNERSHIP EDICT (COE)
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os
import whois
import socket
import ipinfo
import urllib3
import requests
import subprocess
import dns.resolver
from bs4 import BeautifulSoup
from rich.console import Console

# ----- Global Declaration --------------------------------------- #

console = Console()
ipinfo_token = "ff4f67b485c629"

# ----- Create Folders ------------------------------------------- #

def create_folders(domain):
	folder_structure = [
		f"{domain}/Domain",
		f"{domain}/SubDomain",
		f"{domain}/IP Address",
		f"{domain}/Web Applications",
		f"{domain}/Web Applications/HTTP Headers",
	]
	for folder in folder_structure:
		os.makedirs(folder, exist_ok=True)

# ----- Performing Whois ----------------------------------------- #

def extract_whois(domain):
	try:
		info = whois.whois(domain)
		with open(f"{domain}/Domain/DomainWhois.txt", "w") as file:
			file.write(str(info))
	except Exception as e:
		console.print(f"[bold red][!] WHOIS Enumeration Failed for Domain - {domain} - {e}!")

# ----- Subdomain Enumeration ------------------------------------ #

def extract_subdomain(domain):
	file = f"{domain}/SubDomain/SubDomains.txt"
	try:
		command = ["subfinder", "-d", domain, "-o", file]
		subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except Exception as e:
		console.print(f"[bold red][!] Subdomain Enumeration Failed for Domain - {domain} - {e}!")

# ----- Check Alive Subdomains ----------------------------------- #

def extract_alive_subdomains(domain):
	input_file = f"{domain}/SubDomain/SubDomains.txt"
	output_file = f"{domain}/SubDomain/AliveSubDomains.txt"
	try:
		command = ["dnsx", "-l", input_file, "-o", output_file]
		subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except Exception as e:
		console.print(f"[bold red][!] Alive Subdomain Enumeration Failed for Domain - {domain} - {e}!")	

# ----- Extract IP Addresses ------------------------------------- #

def extract_ipaddress(domain):
	input_file = f"{domain}/SubDomain/AliveSubDomains.txt"
	output_file = f"{domain}/IP Address/IPAddress.txt"
	fancy_file = f"{domain}/IP Address/IPAddressList.txt"
	try:
		with open(input_file, "r") as infile:
			subdomains = infile.read().splitlines()
		with open(output_file, "w") as outfile, open(fancy_file, "w") as fancyfile:
			for sub in subdomains:
				try:
					ip = socket.gethostbyname(sub)
					outfile.write(f"[+] The SubDomain - {sub}, resolves to {ip}\n")
					fancyfile.write(f"{ip}\n")
				except socket.gaierror:
					outfile.write(f"[!] The SubDomain - {sub}, does not resolve to any IP Address\n")
	except Exception as e:
		console.print(f"[bold red][!] IP Address Extraction Failed for Domain - {domain} - {e}!")

# ----- Typosquatting Domains Extraction ------------------------- #

def extract_typosquatting(domain):
	output_file = f"{domain}/Domain/TypoSquatting.txt"
	try:
		if os.path.exists(output_file):
			os.remove(output_file)
		subprocess.run(
			["dnstwist", domain, "--registered", "-o", output_file],
			check=True,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE
		)
	except Exception as e:
		console.print(f"[bold red][!] TypoSquatting Domains Extraction Failed for Domain - {domain} - {e}!")

# ----- Web Application Titles Extraction ------------------------ #

def extract_tiles(domain):
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	input_file = f"{domain}/SubDomain/AliveSubDomains.txt"
	output_file = f"{domain}/Web Applications/WebTitles.txt"
	with open(input_file, "r") as infile, open(output_file, "w") as outfile:
		for line in infile:
			url = f"https://{line.strip()}"
			try:
				response = requests.get(url, timeout=10, verify=False)
				response.raise_for_status()
				soup = BeautifulSoup(response.text, 'html.parser')
				title = soup.title.string.strip() if soup.title else 'No title found'
				outfile.write(f"[+] The Web Title of {url} - {title}\n")
			except Exception as e:
				console.print(f"[bold red][!] Web Title Extraction Failed for Domain - {domain} - {e}!")

# ----- Extract HTTP Headers ------------------------------------- #

def extract_headers(domain):
	input_file = f"{domain}/SubDomain/AliveSubDomains.txt"
	output_path = f"{domain}/Web Applications/HTTP Headers/"
	with open(input_file, "r") as f:
		domains = [line.strip() for line in f if line.strip()]
	for domain in domains:
		filename = domain + ".txt"
		filepath = os.path.join(output_path, filename)
		try:
			with open(filepath, "w") as output_file:
				subprocess.run(
					["curl", "-I", "-k", f"https://{domain}"],
					stdout=output_file,
					stderr=subprocess.DEVNULL,
					timeout=10
				)
		except Exception as e:
			console.print(f"[bold red][!] HTTP Header Extraction Failed for Domain - {domain} - {e}!")

# ----- Extract SSL Versions ------------------------------------- #

def extract_sslversions(domain):
	input_file = f"{domain}/SubDomain/AliveSubDomains.txt"
	output_file = f"{domain}/Web Applications/SSL_Versions.txt"
	ssl_versions = {
		"TLS 1.0": "--tlsv1",
		"TLS 1.1": "--tlsv1_1",
		"TLS 1.2": "--tlsv1_2",
		"TLS 1.3": "--tlsv1_3",
		"SSL 2.0": "--ssl2",
		"SSL 3.0": "--ssl3"
	}
	try:
		with open(input_file, "r") as infile, open(output_file, "w") as outfile:
			for line in infile:
				subdomain = line.strip()
				url = f"{subdomain}"
				supported_versions = []
				for version_name, option in ssl_versions.items():
						result = subprocess.run(
							['sslyze', url, option],
							capture_output=True, text=True
						)
						if "The server accepted" in result.stdout:
							supported_versions.append(version_name)
				if supported_versions:
					outfile.write(f"[+] {url} accepted {', '.join(supported_versions)}\n")
				else:
					outfile.write(f"[+] {url} accepted no supported versions\n")
	except Exception as e:
		console.print(f"[bold red][!] SSL Version Extraction Failed for Domain - {domain} - {e}!")

# ----- IPInfo Extraction ---------------------------------------- #

def extract_ipinfo(domain):
	input_file = f"{domain}/IP Address/IPAddressList.txt"
	output_file = f"{domain}/IP Address/IPInfo.txt"
	handler = ipinfo.getHandler(ipinfo_token)
	try:
		with open(input_file, "r") as infile, open(output_file, "w") as outfile:
			for line in infile:
				ip = line.strip()
				details = handler.getDetails(ip)
				org_info = details.all.get("org", "Unknown")
				asn, company = org_info.split(" ", 1)
				outfile.write(f"[+] ASN of IP Address - {ip} is {asn} & it belongs to {company}\n")
	except Exception as e:
		console.print(f"[bold red][!] IP Address Info Extraction Failed for Domain - {domain} - {e}!")

# ----- DNS Query Extraction ------------------------------------- #

def extract_dns(domain):
	output_file = f"{domain}/Domain/Email Records.txt"
	dmarc_domain = f"_dmarc.{domain}"
	dmarc_records = dns.resolver.resolve(dmarc_domain, "TXT")
	txt_records = dns.resolver.resolve(domain, "TXT")
	spf_found = False
	mx_records = dns.resolver.resolve(domain, "MX")
	try:
		with open(output_file, "w") as outfile:
			try:
				for r in dmarc_records:
					outfile.write(f"[+] DMARC: {r.to_text()}\n")
			except:
				outfile.write(f"[!] No DMARC record found for {domain}\n")
			try:
				for r in txt_records:
					txt = r.to_text().strip('"')
					if txt.startswith("v=spf1"):
						outfile.write(f"[+] SPF: {txt}\n")
						spf_found = True
				if not spf_found:
					outfile.write(f"[!] No SPF record found for {domain}\n")
			except:
				outfile.write(f"[!] No TXT records (for SPF) found for {domain}\n")
			try:
				outfile.write("[+] MX Records:\n")
				for r in mx_records:
					outfile.write(f"    {r.exchange} - Priority: {r.preference}\n")
			except:
				outfile.write(f"[!] No MX records found for {domain}\n")
	except Exception as e:
		print(f"[!] Email DNS record extraction failed for {domain}: {e}")

# ----- Menu ----------------------------------------------------- #

def menu(domain):
	create_folders(domain)
	console.print(f"[bold green][+] Performing Whois Extraction.....")
	extract_whois(domain)
	console.print(f"[bold green][+] Performing SubDomain Extraction.....")
	extract_subdomain(domain)
	console.print(f"[bold green][+] Checking for Alive Subdomains.....")
	extract_alive_subdomains(domain)
	console.print(f"[bold green][+] Performing IP Address Extraction.....")
	extract_ipaddress(domain)
	console.print(f"[bold green][+] Performing TypoSquatting Domains Extraction.....")
	extract_typosquatting(domain)
	console.print(f"[bold green][+] Performing Web Title Extraction.....")
	extract_tiles(domain)
	console.print(f"[bold green][+] Performing Web Headers Extraction.....")
	extract_headers(domain)
	console.print(f"[bold green][+] Performing SSL Extraction.....")
	extract_sslversions(domain)
	console.print(f"[bold green][+] Performing IP Address Info Extraction.....")
	extract_ipinfo(domain)
	console.print(f"[bold green][+] Performing DNS Extraction.....")
	extract_dns(domain)
	if os.path.exists(f"{domain}/IP Address/IPAddressList.txt"):
			os.remove(f"{domain}/IP Address/IPAddressList.txt")

# ----- Banner --------------------------------------------------- #

def ascii():
	console.print(rf"""[#C6ECE3]
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                         │
│    ooooooooo.    o8o           oooo        ooooo                 .             oooo     │ 
│    `888   `Y88.  `"'           `888        `888'               .o8             `888     │ 
│     888   .d88' oooo   .oooo.o  888  oooo   888  ooo. .oo.   .o888oo  .ooooo.   888     │ 
│     888ooo88P'  `888  d88(  "8  888 .8P'    888  `888P"Y88b    888   d88' `88b  888     │ 
│     888`88b.     888  `"Y88b.   888888.     888   888   888    888   888ooo888  888     │ 
│     888  `88b.   888  o.  )88b  888 `88b.   888   888   888    888 . 888    .o  888     │ 
│    o888o  o888o o888o 8""888P' o888o o888o o888o o888o o888o   "888" `Y8bod8P' o888o    │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
	""")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")
	console.print(rf"[#C6ECE3]  RiskIntel - Know Your Targets. Own the Recon.")
	console.print(rf"[#C6ECE3]  Created by [bold black]Cursed271")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
	os.system("cls" if os.name == "nt" else "clear")
	ascii()
	domain = console.input(f"[#C6ECE3][?] Enter the Domain Name that you want to perform Reconnaissance on: ")
	menu(domain)
	console.print("[#C6ECE3]+--------------------------------------------------------------+")

# ----- End ------------------------------------------------------ #
