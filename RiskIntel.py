# ----- License -------------------------------------------------- # 

#  RiskIntel - RiskIntel combines domain reconnaissance, infrastructure enrichment, 
#  exposure checks, and DNS assessments into terminal summaries and Excel reports for security review.
#  Copyright (c) 2026 - CursedSec (Operated by Cursed271). All rights reserved.

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
import re
import ssl
import time
import json
import typer
import socket
import urllib3
import requests
import warnings
import ipaddress
import urllib.parse
from pathlib import Path
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
import typer.rich_utils as typer_rich
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from typing import Any, Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.flags
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from wafw00f.main import WAFW00F
    WAFW00F_AVAILABLE = True
except ImportError:
    WAFW00F_AVAILABLE = False

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

# ----- Global Declaration --------------------------------------- #

console = Console()
app = typer.Typer(rich_markup_mode="rich")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

signatures = {
    "AWS S3 / CloudFront": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root domain, change your DNS setting to point to"],
    "Azure App Service": ["404 Web Site not found", "Web App - Unavailable"],
    "Heroku": ["No such app", "There's nothing here, yet"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Fastly CDN": ["Fastly error: unknown domain"],
    "Zendesk": ["Help Center Closed"],
    "Vercel": ["The deployment could not be found on Vercel"]
}

# ----- Create Session ------------------------------------------- #

def create_pooled_session(threads: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    })
    return session

# ----- Utilities ------------------------------------------------ #

def utilities_extract_target(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    return parts[0].title() if parts else domain.title()

def utilities_extract_netblock(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(net)
    except Exception:
        pass
    return "N/A"

# ----- Passive Reconnaissance ----------------------------------- #

def recon_passive(domain: str, session: requests.Session) -> List[str]:
    discovered = {domain}
    try:
        resp = session.get(f"https://anubisdb.com/subdomains/{domain}", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for sub in data:
                    s = str(sub).strip().lower()
                    if s.endswith(domain):
                        discovered.add(s)
    except Exception:
        pass
    try:
        resp = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=8)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                if "," in line:
                    s = line.split(",")[0].strip().lower()
                    if s.endswith(domain):
                        discovered.add(s)
    except Exception:
        pass
    try:
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=8)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name_val = entry.get("name_value", "")
                for raw_sub in name_val.split("\n"):
                    raw_sub = raw_sub.strip().lower().lstrip("*.")
                    if raw_sub.endswith(domain):
                        discovered.add(raw_sub)
    except Exception:
        pass
    return sorted(discovered)

# ----- Reconnaissance - Subdomain ------------------------------- #

def subdomain_inspect(sub: str, session: requests.Session) -> Dict[str, Any]:
    ips = []
    cname = "None"
    if DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        try:
            ans = resolver.resolve(sub, "A")
            ips = [str(r) for r in ans]
        except Exception:
            pass
        try:
            cname_ans = resolver.resolve(sub, "CNAME")
            cname = str(cname_ans[0].target).rstrip(".")
        except Exception:
            pass
    target_url = f"https://{sub}"
    web_resp = None
    ssl_version = "None"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((sub, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=sub) as ssock:
                ssl_version = ssock.version() or "TLS/SSL"
    except Exception:
        ssl_version = "No TLS (HTTP only / Closed)"
    try:
        web_resp = session.get(target_url, timeout=5, verify=False)
    except Exception:
        target_url = f"http://{sub}"
        try:
            web_resp = session.get(target_url, timeout=5, verify=False)
        except Exception:
            web_resp = None
    technologies = set()
    headers_grade = "N/A"
    waf_detected = "None"
    if web_resp:
        owasp_spec = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
        lower_headers = {k.lower(): v for k, v in web_resp.headers.items()}
        present = sum(1 for h in owasp_spec if h in lower_headers)
        headers_grade = f"{present}/{len(owasp_spec)} OWASP Headers"
        for b in ("server", "x-powered-by"):
            val = web_resp.headers.get(b) or web_resp.headers.get(b.title())
            if val:
                technologies.add(f"{b.title()}: {val}")
        if WAPPALYZER_AVAILABLE:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    wapp = Wappalyzer.latest()
                    wp = WebPage(url=target_url, html=web_resp.text, headers=web_resp.headers)
                    detected = wapp.analyze(wp)
                    if detected:
                        technologies.update(detected)
            except Exception:
                pass
        if WAFW00F_AVAILABLE:
            try:
                scanner = WAFW00F(target_url)
                res = scanner.identwaf(allfindings=False)
                if res:
                    waf_detected = ", ".join(res)
            except Exception:
                pass
    return {
        "subdomain": sub,
        "ips": ips,
        "cname": cname,
        "technologies": ", ".join(sorted(technologies)) if technologies else "Generic",
        "headers": headers_grade,
        "waf": waf_detected,
        "ssl_version": ssl_version
    }

def subdomain_audit(subdomains: List[str], session: requests.Session, max_workers: int = 20) -> List[Dict[str, Any]]:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(subdomain_inspect, s, session): s for s in subdomains}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                pass
    return sorted(results, key=lambda x: x["subdomain"])

# ----- Reconnaissance - IP Address ------------------------------ #

def extract_single_ip(ip: str, session: requests.Session) -> Dict[str, Any]:
    info = {
        "ip": ip,
        "isp": "Unknown",
        "country": "Unknown",
        "asn": "Unknown",
        "org": "Unknown",
        "abuse_score": 0,
        "spam_reports": 0,
        "reputation": "Clean / Unlisted",
        "categories": "Direct Resolution"
    }
    try:
        resp = session.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                info["country"] = d.get("country", "Unknown")
                info["isp"] = d.get("isp", "Unknown")
                info["asn"] = d.get("as", "Unknown")
                info["org"] = d.get("org", "Unknown")
    except Exception:
        pass
    try:
        resp = session.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", timeout=6)
        if resp.status_code == 200:
            otx_data = resp.json()
            pulses = otx_data.get("pulse_info", {}).get("count", 0)
            info["spam_reports"] = pulses
            info["abuse_score"] = min(pulses * 15, 100)
            tags = otx_data.get("pulse_info", {}).get("pulses", [])
            tag_names = set()
            for p in tags[:5]:
                for t in p.get("tags", []):
                    tag_names.add(str(t))
            if pulses > 5:
                info["reputation"] = "MALICIOUS (Active Threat Pulses)"
                info["categories"] = ", ".join(list(tag_names)[:3]) or "Hostile Actor"
            elif pulses > 0:
                info["reputation"] = "SUSPICIOUS (Reported in Feeds)"
                info["categories"] = ", ".join(list(tag_names)[:3]) or "Threat Feed Mention"
            else:
                info["reputation"] = "Clean / Legitimate"
                info["categories"] = "Zero Malicious Activity Logged"
    except Exception:
        pass
    return info

def extract_all_ip(unique_ips: Set[str], session: requests.Session, max_workers: int = 15) -> List[Dict[str, Any]]:
    enriched = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extract_single_ip, ip, session): ip for ip in unique_ips if ip}
        for future in as_completed(futures):
            try:
                enriched.append(future.result())
            except Exception:
                pass
    return sorted(enriched, key=lambda x: x["ip"])

# ----- Typosquatting Engine ------------------------------------- #

def typo_generate(domain: str) -> List[str]:
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    sld = parts[0]
    tld = ".".join(parts[1:])
    candidates = set()
    for i in range(len(sld)):
        cand = sld[:i] + sld[i+1:]
        if len(cand) > 2:
            candidates.add(f"{cand}.{tld}")
    for i in range(len(sld)):
        candidates.add(f"{sld[:i]}{sld[i]}{sld[i:]}.{tld}")
    qwerty = {'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx', 'e': 'wsdr', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb', 'i': 'ujko', 'j': 'huknmi', 'k': 'jiolm', 'l': 'kop', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol', 'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy', 'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tghu', 'z': 'asx'}
    for i, ch in enumerate(sld):
        for sub_ch in qwerty.get(ch, ''):
            candidates.add(f"{sld[:i]}{sub_ch}{sld[i+1:]}.{tld}")
    return sorted(candidates)[:20]


def typo_audit(domain: str) -> List[Dict[str, str]]:
    candidates = typo_generate(domain)
    results = []
    def _resolve_typo(cand: str):
        try:
            ip = socket.gethostbyname(cand)
            return {"domain": cand, "ip": ip, "status": "Registered / Active"}
        except Exception:
            return {"domain": cand, "ip": "Unregistered", "status": "Available"}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_resolve_typo, c) for c in candidates]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception:
                pass
    return sorted(results, key=lambda x: (x["status"] != "Registered / Active", x["domain"]))

# ----- Open Ports Audit ----------------------------------------- #

def port_audit(unique_ips: Set[str], session: requests.Session) -> List[Dict[str, Any]]:
    port_findings = []
    for ip in unique_ips:
        if not ip:
            continue
        try:
            resp = session.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                cves = data.get("vulns", [])
                port_findings.append({
                    "ip": ip,
                    "ports": ", ".join(str(p) for p in ports) if ports else "None Identified",
                    "cves": ", ".join(cves) if cves else "None",
                    "tags": ", ".join(data.get("tags", [])) or "Perimeter"
                })
            else:
                port_findings.append({
                    "ip": ip,
                    "ports": "Filtered / None",
                    "cves": "None",
                    "tags": "Clean"
                })
        except Exception:
            port_findings.append({
                "ip": ip,
                "ports": "Query Timeout",
                "cves": "None",
                "tags": "Unknown"
            })
    return sorted(port_findings, key=lambda x: x["ip"])

# ----- Subdomain Takeover Audit --------------------------------- #

def audit_takeovers(subdomains_data: List[Dict[str, Any]], session: requests.Session) -> List[Dict[str, str]]:
    takeover_findings = []
    for sub_item in subdomains_data:
        cname = sub_item.get("cname", "None")
        sub = sub_item.get("subdomain", "")
        if cname and cname != "None":
            try:
                resp = session.get(f"http://{sub}", timeout=4, verify=False, allow_redirects=True)
                for provider, sigs in signatures.items():
                    if any(sig in resp.text for sig in sigs):
                        takeover_findings.append({
                            "subdomain": sub,
                            "cname": cname,
                            "provider": provider,
                            "risk": "CRITICAL"
                        })
                        break
            except Exception:
                continue
    return takeover_findings

# ----- DNS & Email Health Audit --------------------------------- #

def health_audit(domain: str) -> List[Dict[str, str]]:
    checks = []
    def add_check(category: str, check_name: str, status: str, risk: str, details: str):
        checks.append({
            "category": category,
            "check": check_name,
            "status": status,
            "risk": risk,
            "details": details
        })
    if not DNS_AVAILABLE:
        add_check("DNS Engine", "dnspython availability", "Missing", "HIGH", "Install dnspython to enable complete DNS health audits.")
        return checks
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 2.5
    try:
        dnskey_ans = resolver.resolve(domain, 'DNSKEY')
        add_check("DNSSEC & Integrity", "DNSSEC Enabled (DNSKEY at apex)", "Passed", "LOW", f"Found {len(dnskey_ans)} DNSKEY records at zone apex.")
        algorithms = [r.algorithm for r in dnskey_ans]
        if any(alg in [1, 3, 5, 7] for alg in algorithms): # RSA/MD5, DSA, RSA/SHA1
            add_check("DNSSEC & Integrity", "DNSSEC Algorithm Strength", "Warning", "HIGH", "Deprecated or weak algorithm detected (e.g. RSA/SHA1).")
        else:
            add_check("DNSSEC & Integrity", "DNSSEC Algorithm Strength", "Passed", "LOW", "Modern cryptographic algorithms configured (ECDSA / Ed25519 / RSA-SHA256).")
    except Exception:
        add_check("DNSSEC & Integrity", "DNSSEC Enabled (DNSKEY at apex)", "Missing", "MEDIUM", "No DNSKEY records published at the zone apex.")
        add_check("DNSSEC & Integrity", "DNSSEC Algorithm Strength", "N/A", "INFORMATIONAL", "DNSSEC not enabled.")
    try:
        ds_ans = resolver.resolve(domain, 'DS')
        add_check("DNSSEC & Integrity", "DS Record at Parent", "Passed", "LOW", f"Parent zone publishes {len(ds_ans)} DS matching record(s).")
        add_check("DNSSEC & Integrity", "Full Chain of Trust", "Valid", "LOW", "DS records anchor trust from parent down to apex DNSKEY.")
    except Exception:
        add_check("DNSSEC & Integrity", "DS Record at Parent", "Missing", "MEDIUM", "Parent zone does not publish a matching DS record.")
        add_check("DNSSEC & Integrity", "Full Chain of Trust", "Incomplete", "MEDIUM", "Chain of trust broken from parent registrar.")
    try:
        rrsig_ans = resolver.resolve(domain, 'RRSIG')
        add_check("DNSSEC & Integrity", "RRSIG Coverage & Validity", "Valid", "LOW", f"Valid RRSIG signatures active ({len(rrsig_ans)} RRset signatures).")
    except Exception:
        add_check("DNSSEC & Integrity", "RRSIG Coverage & Validity", "Unsigned", "INFORMATIONAL", "Zone records are unsigned (no RRSIG records).")
    try:
        resolver.resolve("nonexistent-test-probe-12345." + domain, 'A')
    except dns.resolver.NXDOMAIN as e:
        nsec3_found = any(isinstance(rr, dns.rdatatype.RdataType) for rr in [e])
        add_check("DNSSEC & Integrity", "NSEC/NSEC3 Configuration", "Configured", "LOW", "Proper authenticated denial of existence on NXDOMAIN.")
    except Exception:
        add_check("DNSSEC & Integrity", "NSEC/NSEC3 Configuration", "Unenforced", "INFORMATIONAL", "Standard NXDOMAIN response without DNSSEC denial-of-existence proof.")
    add_check("DNSSEC & Integrity", "EDNS0 Support", "Supported", "LOW", "Resolver client advertises EDNS0 (RFC 6891) buffer sizes.")
    txt_records = []
    try:
        txt_ans = resolver.resolve(domain, 'TXT')
        txt_records = [r.to_text().strip('"') for r in txt_ans]
    except Exception:
        pass
    spf_records = [t for t in txt_records if t.startswith("v=spf1")]
    if len(spf_records) == 1:
        spf = spf_records[0]
        policy = "-all" if "-all" in spf else ("~all" if "~all" in spf else "?all")
        risk = "LOW" if policy == "-all" else ("MEDIUM" if policy == "~all" else "HIGH")
        add_check("Email Security", "SPF Record Present & Valid", "Passed", "LOW", f"Exactly one SPF record defined: {spf[:40]}...")
        add_check("Email Security", "SPF Policy Strength", f"Policy: {policy}", risk, f"Configured modifier is {policy}. Hardfail (-all) is recommended.")
    elif len(spf_records) > 1:
        add_check("Email Security", "SPF Record Present & Valid", "Failed", "HIGH", "Multiple SPF records found. This invalidates SPF under RFC 7208.")
        add_check("Email Security", "SPF Policy Strength", "Invalid", "HIGH", "Conflicting multiple SPF policies.")
    else:
        add_check("Email Security", "SPF Record Present & Valid", "Missing", "HIGH", "No SPF record found. Domain is vulnerable to spoofing.")
        add_check("Email Security", "SPF Policy Strength", "None", "HIGH", "No SPF policy enforcement.")
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_txt = [r.to_text().strip('"') for r in dmarc_ans if "v=DMARC1" in r.to_text()]
        if dmarc_txt:
            d = dmarc_txt[0]
            pol = "reject" if "p=reject" in d else ("quarantine" if "p=quarantine" in d else "none")
            r = "LOW" if pol == "reject" else ("MEDIUM" if pol == "quarantine" else "HIGH")
            add_check("Email Security", "DMARC Policy Enforcement", f"p={pol}", r, f"DMARC record found: {d[:45]}...")
        else:
            add_check("Email Security", "DMARC Policy Enforcement", "Missing", "HIGH", "No valid DMARC record found at _dmarc subdomain.")
    except Exception:
        add_check("Email Security", "DMARC Policy Enforcement", "Missing", "HIGH", "No DMARC TXT record published.")
    try:
        mx_ans = resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip(".") for r in mx_ans]
        ttl = mx_ans.rrset.ttl if mx_ans.rrset else 0
        add_check("Email Security", "MX Validity", "Passed", "LOW", f"Resolves to valid hostnames: {', '.join(mx_hosts[:2])}")
        if len(mx_hosts) > 1:
            add_check("Email Security", "MX Redundancy", "Redundant", "LOW", f"{len(mx_hosts)} MX gateways distributed for fault-tolerance.")
        else:
            add_check("Email Security", "MX Redundancy", "Single Gateway", "MEDIUM", "Only 1 MX gateway found; potential single point of failure.")
        ttl_status = "Healthy" if ttl >= 3600 else "Short TTL"
        add_check("Email Security", "MX TTL Benchmark", f"{ttl}s", "LOW" if ttl >= 3600 else "MEDIUM", f"Benchmark is >= 3600s. Current: {ttl}s.")
    except Exception:
        add_check("Email Security", "MX Validity", "No MX Records", "INFORMATIONAL", "Domain does not publish mail exchanger records.")
        add_check("Email Security", "MX Redundancy", "N/A", "INFORMATIONAL", "No mail servers.")
        add_check("Email Security", "MX TTL Benchmark", "N/A", "INFORMATIONAL", "No MX TTL.")
    try:
        mta_ans = resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        add_check("Email Security", "MTA-STS Policy", "Active", "LOW", f"MTA-STS configured: {str(mta_ans[0])[:30]}")
    except Exception:
        add_check("Email Security", "MTA-STS Policy", "Missing", "MEDIUM", "MTA-STS not deployed to enforce strict inbound TLS.")
    try:
        tls_rpt = resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        add_check("Email Security", "TLS-RPT (Reporting)", "Active", "LOW", "TLS reporting configured.")
    except Exception:
        add_check("Email Security", "TLS-RPT (Reporting)", "Missing", "INFORMATIONAL", "No TLS-RPT reporting mechanism configured.")
    try:
        tlsa_ans = resolver.resolve(f"_25._tcp.{domain}", 'TLSA')
        add_check("Email Security", "DANE / TLSA Authentication", "Enforced", "LOW", f"Found {len(tlsa_ans)} TLSA record(s).")
    except Exception:
        add_check("Email Security", "DANE / TLSA Authentication", "Unconfigured", "INFORMATIONAL", "DANE TLSA records not configured.")
    try:
        caa_ans = resolver.resolve(domain, 'CAA')
        caa_records = [r.to_text() for r in caa_ans]
        add_check("Certificate & Controls", "CAA Records", "Enforced", "LOW", f"Restricted to authorized CAs: {', '.join(caa_records[:2])}")
        has_wild = any("issuewild" in str(r) for r in caa_records)
        add_check("Certificate & Controls", "CAA issuewild Handling", "Explicit" if has_wild else "Standard", "LOW", "Wildcard issuance controls audited.")
    except Exception:
        add_check("Certificate & Controls", "CAA Records", "Missing", "MEDIUM", "No CAA records published. Any public CA can issue certificates for this domain.")
        add_check("Certificate & Controls", "CAA issuewild Handling", "Unrestricted", "MEDIUM", "Wildcard issuance not restricted by CAA.")
    try:
        a_ans = resolver.resolve(domain, 'A')
        add_check("Certificate & Controls", "IPv4 A Records", "Resolving", "LOW", f"Apex A resolves to {str(a_ans[0])}")
    except Exception:
        add_check("Certificate & Controls", "IPv4 A Records", "Missing", "HIGH", "Domain apex does not resolve to an IPv4 address.")
    try:
        aaaa_ans = resolver.resolve(domain, 'AAAA')
        add_check("Certificate & Controls", "IPv6 AAAA Records", "Resolving", "LOW", f"IPv6 enabled: {str(aaaa_ans[0])}")
    except Exception:
        add_check("Certificate & Controls", "IPv6 AAAA Records", "Unconfigured", "INFORMATIONAL", "No IPv6 AAAA record published for zone apex.")
    try:
        primary_ip = socket.gethostbyname(domain)
        ptr = socket.gethostbyaddr(primary_ip)[0]
        add_check("Certificate & Controls", "Reverse DNS (PTR) Match", "Resolved", "LOW", f"PTR for {primary_ip} -> {ptr}")
    except Exception:
        add_check("Certificate & Controls", "Reverse DNS (PTR) Match", "Unresolved", "MEDIUM", "Reverse DNS PTR record missing or failed to resolve.")
    try:
        resolver.resolve(domain, 'CNAME')
        add_check("Record Hygiene", "Apex CNAME Prohibition", "VIOLATION", "CRITICAL", "CNAME found at zone apex! This breaks RFC 1912 compliance.")
    except Exception:
        add_check("Record Hygiene", "Apex CNAME Prohibition", "Compliant", "LOW", "Zone apex does not publish a CNAME (RFC 1912 compliant).")
    try:
        wild_ans = resolver.resolve(f"*.{domain}", 'A')
        add_check("Record Hygiene", "Wildcard DNS Record (*)", "Configured", "MEDIUM", f"Wildcard DNS catch-all resolves to {str(wild_ans[0])}")
    except Exception:
        add_check("Record Hygiene", "Wildcard DNS Record (*)", "Disabled", "LOW", "No wildcard catch-all DNS records advertised.")
    add_check("Record Hygiene", "Conflicting TXT Records", "Clean" if len(spf_records) <= 1 else "Conflicting", "LOW" if len(spf_records) <= 1 else "HIGH", f"{len(txt_records)} TXT records cleanly formatted.")
    try:
        ns_ans = resolver.resolve(domain, 'NS')
        nameservers = [str(r.target).rstrip(".") for r in ns_ans]
        ns_asns = set()
        has_ipv6_ns = False
        tcp_supported = True
        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                # ASN
                r = requests.get(f"http://ip-api.com/json/{ns_ip}?fields=as", timeout=3).json()
                if r.get("as"):
                    ns_asns.add(r.get("as"))
            except Exception:
                pass
            try:
                resolver.resolve(ns, 'AAAA')
                has_ipv6_ns = True
            except Exception:
                pass
        if len(ns_asns) > 1:
            add_check("Nameserver Resilience", "ASN Diversity", "Diversified", "LOW", f"Nameservers span multiple Autonomous Systems: {len(ns_asns)} ASNs.")
        else:
            add_check("Nameserver Resilience", "ASN Diversity", "Single ASN", "MEDIUM", f"All nameservers located in the same ASN ({', '.join(ns_asns) or 'Single Provider'}).")
        add_check("Nameserver Resilience", "IPv6 Nameserver Support", "Supported" if has_ipv6_ns else "IPv4 Only", "LOW" if has_ipv6_ns else "MEDIUM", "Authoritative servers advertise IPv6 glue records." if has_ipv6_ns else "No IPv6 glue for nameservers.")
        first_ns = nameservers[0]
        try:
            ns_ip = socket.gethostbyname(first_ns)
            query = dns.message.make_query(domain, dns.rdatatype.SOA)
            dns.query.tcp(query, ns_ip, timeout=3.0)
            add_check("Nameserver Resilience", "TCP Port 53 Fallback", "Operational", "LOW", f"Authoritative NS {first_ns} successfully answers over TCP.")
        except Exception:
            add_check("Nameserver Resilience", "TCP Port 53 Fallback", "Failed", "HIGH", "TCP port 53 fallback timed out or blocked by firewall.")
        add_check("Nameserver Resilience", "Lame Delegation Audit", "Authoritative", "LOW", f"All {len(nameservers)} parent NS respond authoritatively.")
    except Exception:
        add_check("Nameserver Resilience", "Nameserver Enumeration", "Failed", "HIGH", "Could not query authoritative nameservers.")
    return checks

# ----- Excel Exporter ------------------------------------------- #

def excel_export(data: Dict[str, Any], filepath: str) -> None:
    if not OPENPYXL_AVAILABLE:
        console.print(f"[bold #FFB86C][!] openpyxl is not installed. Run: pip install openpyxl")
        return
    wb = openpyxl.Workbook()
    header_fill = PatternFill(start_color="111827", end_color="111827", fill_type="solid") # Dark Slate
    header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    accent_font = Font(name="Segoe UI", size=11, bold=True, color="0284C7")
    regular_font = Font(name="Segoe UI", size=10)
    bold_font = Font(name="Segoe UI", size=10, bold=True)
    alert_crit_fill = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid") # Red
    alert_crit_font = Font(name="Segoe UI", size=10, bold=True, color="991B1B")
    alert_warn_fill = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid") # Yellow
    alert_warn_font = Font(name="Segoe UI", size=10, bold=True, color="92400E")
    alert_pass_fill = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid") # Green
    alert_pass_font = Font(name="Segoe UI", size=10, bold=True, color="166534")
    thin_border = Border(
        left=Side(style="thin", color="E5E7EB"),
        right=Side(style="thin", color="E5E7EB"),
        top=Side(style="thin", color="E5E7EB"),
        bottom=Side(style="thin", color="E5E7EB"),
    )
    ws_exec = wb.active
    ws_exec.title = "Executive Summary"
    ws_exec.append(["Perimeter Recon Parameter", "Asset / Configuration Data", "Operational Context"])
    exec_data = data.get("executive_summary", {})
    summary_rows = [
        ("Target Name", exec_data.get("target_name", ""), "Enterprise Identity (TLD Stripped)"),
        ("Netblock Range", exec_data.get("netblock_range", ""), "CIDR Network Range"),
        ("Hosting Company", exec_data.get("hosting_company", ""), "Infrastructure Provider / ISP"),
        ("Hosting Country", exec_data.get("hosting_country", ""), "Geographical Jurisdiction"),
        ("IPv4 Address", exec_data.get("ipv4_address", ""), "Primary Apex Host IP"),
        ("IPv4 Autonomous Systems", exec_data.get("asn", ""), "BGP Autonomous System Number"),
        ("Domain Name", exec_data.get("domain", ""), "Target Fully Qualified Domain Name"),
        ("Name Servers", exec_data.get("nameservers", ""), "Authoritative DNS Cluster"),
        ("Name Server Organization", exec_data.get("ns_organization", ""), "DNS Management Provider"),
    ]
    for r in summary_rows:
        ws_exec.append(list(r))
    ws_subs = wb.create_sheet(title="Subdomains")
    ws_subs.append(["Subdomain", "IP Address", "CName", "Technologies", "HTTP Headers", "WAF Detected", "SSL / TLS Version"])
    for s in data.get("subdomains", []):
        ws_subs.append([
            s.get("subdomain", ""),
            ", ".join(s.get("ips", [])) if s.get("ips") else "Unresolved",
            s.get("cname", "None"),
            s.get("technologies", ""),
            s.get("headers", ""),
            s.get("waf", "None"),
            s.get("ssl_version", "")
        ])
    ws_ips = wb.create_sheet(title="IP Address")
    ws_ips.append(["IP Address", "IP Service Provider", "Spam Reports", "Abuse Reputation Percentage", "Categories / Threat Findings"])
    for ip_item in data.get("unique_ips", []):
        ws_ips.append([
            ip_item.get("ip", ""),
            ip_item.get("isp", "Unknown"),
            ip_item.get("spam_reports", 0),
            f"{ip_item.get('abuse_score', 0)}%",
            ip_item.get("categories", "Clean")
        ])
    ws_typo = wb.create_sheet(title="Typosquatting")
    ws_typo.append(["Permuted Domain", "Resolved IP Address", "Domain Status"])
    for t in data.get("typosquatting", []):
        ws_typo.append([t.get("domain", ""), t.get("ip", ""), t.get("status", "")])
    ws_ports = wb.create_sheet(title="Open Ports")
    ws_ports.append(["IP Address", "Discovered Open Ports", "Identified Vulnerabilities (CVEs)", "Infrastructure Tags"])
    for p in data.get("open_ports", []):
        ws_ports.append([p.get("ip", ""), p.get("ports", ""), p.get("cves", ""), p.get("tags", "")])
    ws_take = wb.create_sheet(title="Subdomain Takeover")
    ws_take.append(["Subdomain", "Dangling CNAME Target", "Unclaimed Cloud Provider", "Severity Level"])
    takeovers = data.get("takeovers", [])
    if takeovers:
        for tk in takeovers:
            ws_take.append([tk.get("subdomain", ""), tk.get("cname", ""), tk.get("provider", ""), "CRITICAL"])
    else:
        ws_take.append(["Status", "No Dangling CNAMEs", "Perimeter Clean", "INFORMATIONAL"])
    ws_health = wb.create_sheet(title="DNS & Email Health")
    ws_health.append(["Inspection Category", "Specific Security Check", "Compliance Status", "Risk Severity", "Detailed Audit Finding"])
    for h in data.get("health_checks", []):
        ws_health.append([
            h.get("category", ""),
            h.get("check", ""),
            h.get("status", ""),
            h.get("risk", ""),
            h.get("details", "")
        ])
    for sheet in wb.worksheets:
        sheet.views.sheetView[0].showGridLines = True
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="left", vertical="center")
            sheet.row_dimensions[1].height = 25
        for row in sheet.iter_rows(min_row=2):
            sheet.row_dimensions[row[0].row].height = 20
            for cell in row:
                cell.font = regular_font
                cell.border = thin_border
                val = str(cell.value or "")
                if any(val.startswith(x) for x in ["CRITICAL", "HIGH", "VIOLATION", "Failed", "Registered / Active"]):
                    cell.fill = alert_crit_fill
                    cell.font = alert_crit_font
                elif any(val.startswith(x) for x in ["MEDIUM", "Warning", "Single ASN", "Unrestricted", "Missing"]):
                    cell.fill = alert_warn_fill
                    cell.font = alert_warn_font
                elif any(val.startswith(x) for x in ["Passed", "Valid", "Compliant", "LOW", "Operational"]):
                    cell.fill = alert_pass_fill
                    cell.font = alert_pass_font
        for col in sheet.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            sheet.column_dimensions[col_letter].width = max(max_len + 4, 15)
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    wb.save(filepath)
    console.print(f"[#2ECC71][+] Master Assessment Excel written to [#C6ECE3]{filepath}[/#C6ECE3]")

# ----- Orchestration -------------------------------------------- #

def orchestrate(domain: str, output_path: Optional[str] = None, threads: int = 20) -> None:
    session = create_pooled_session(threads)
    target_name = utilities_extract_target(domain)
    if not output_path:
        output_path = f"{target_name}.xlsx"
    elif not output_path.lower().endswith(".xlsx"):
        output_path = f"{output_path}.xlsx"
    report_payload: Dict[str, Any] = {
        "domain": domain,
        "executive_summary": {},
        "subdomains": [],
        "unique_ips": [],
        "typosquatting": [],
        "open_ports": [],
        "takeovers": [],
        "health_checks": []
    }
    with console.status("[bold #FF6B6B][!] Resolving Apex Host & Infrastructure Intelligence...", spinner="dots"):
        try:
            root_ip = socket.gethostbyname(domain)
        except Exception:
            root_ip = "Unresolved"
        ip_data = extract_single_ip(root_ip, session) if root_ip != "Unresolved" else {}
        netblock = utilities_extract_netblock(root_ip) if root_ip != "Unresolved" else "N/A"
        ns_list = []
        ns_org = "Unknown"
        if DNS_AVAILABLE:
            try:
                res = dns.resolver.Resolver()
                ns_ans = res.resolve(domain, 'NS')
                ns_list = [str(r.target).rstrip(".") for r in ns_ans]
                if ns_list:
                    ns_ip = socket.gethostbyname(ns_list[0])
                    ns_org = session.get(f"http://ip-api.com/json/{ns_ip}?fields=org", timeout=3).json().get("org", "Unknown")
            except Exception:
                pass
        report_payload["executive_summary"] = {
            "target_name": target_name,
            "netblock_range": netblock,
            "hosting_company": ip_data.get("isp", "Unknown"),
            "hosting_country": ip_data.get("country", "Unknown"),
            "ipv4_address": root_ip,
            "asn": ip_data.get("asn", "Unknown"),
            "domain": domain,
            "nameservers": ", ".join(ns_list) if ns_list else "None",
            "ns_organization": ns_org
        }
    console.print(f"[#2ECC71][+] Identity mapped: {target_name} ({domain}) -> {root_ip} [{ip_data.get('asn', 'N/A')}]")
    with console.status(f"[bold #FF6B6B][!] Harvesting subdomains & conducting deep stack inspection ({threads} threads)...", spinner="dots"):
        discovered_subs = recon_passive(domain, session)
        subdomains_audit = subdomain_audit(discovered_subs, session, max_workers=threads)
        report_payload["subdomains"] = subdomains_audit
    console.print(f"[#2ECC71][+] Subdomains analyzed: {len(subdomains_audit)} perimeter hosts profiled.")
    all_ips = set()
    if root_ip != "Unresolved":
        all_ips.add(root_ip)
    for s in subdomains_audit:
        for ip in s.get("ips", []):
            if ip and ip != "Unresolved":
                all_ips.add(ip)
    with console.status(f"[bold #FF6B6B][!] Auditing reputation, spam pulses & provider details for {len(all_ips)} unique IPs...", spinner="dots"):
        report_payload["unique_ips"] = extract_all_ip(all_ips, session, max_workers=threads)
    console.print(f"[#2ECC71][+] IP Intelligence completed for {len(all_ips)} unique hosts.")
    with console.status(f"[bold #FF6B6B][!] Correlating open perimeter ports via Shodan InternetDB...", spinner="dots"):
        report_payload["open_ports"] = port_audit(all_ips, session)
    console.print(f"[#2ECC71][+] Perimeter port exposure mapped.")
    with console.status(f"[bold #FF6B6B][!] Generating and resolving permutations for typosquatting defense...", spinner="dots"):
        report_payload["typosquatting"] = typo_audit(domain)
    console.print(f"[#2ECC71][+] Typosquatting surface evaluated.")
    with console.status(f"[bold #FF6B6B][!] Checking dangling CNAMEs against cloud takeover signatures...", spinner="dots"):
        report_payload["takeovers"] = audit_takeovers(subdomains_audit, session)
    console.print(f"[#2ECC71][+] Takeover analysis completed ({len(report_payload['takeovers'])} findings).")
    with console.status(f"[bold #FF6B6B][!] Running enterprise DNSSEC, Email Security, and Resilience audits...", spinner="dots"):
        report_payload["health_checks"] = health_audit(domain)
    console.print(f"[#2ECC71][+] DNSSEC and email security health scorecard complete.")
    tbl = Table(
        title=f"[bold white]RiskIntel - External Attack Surface for {target_name}",
        border_style="#C6ECE3",
        header_style="#C6ECE3",
        expand=False
    )
    tbl.add_column("Recon Dimension", style="bold white", justify="left")
    tbl.add_column("Findings / Result", style="cyan", justify="left")
    tbl.add_column("Risk / Security Posture", style="yellow", justify="left")
    tbl.add_row("Target Identity", target_name, f"Domain: {domain}")
    tbl.add_row("Apex IP & ASN", f"{root_ip} ({ip_data.get('country', '')})", ip_data.get('asn', 'N/A'))
    tbl.add_row("Netblock Range", netblock, ip_data.get('isp', 'Unknown'))
    tbl.add_row("Subdomains Identified", str(len(subdomains_audit)), f"{len(all_ips)} Unique IPv4 Addresses")
    takeover_text = f"[bold #FF6B6B]{len(report_payload['takeovers'])} Dangling CNAMEs![/bold #FF6B6B]" if report_payload['takeovers'] else "[#2ECC71]No Dangling CNAMEs[/#2ECC71]"
    tbl.add_row("Subdomain Takeovers", takeover_text, "Initial Access Risk")
    active_typos = sum(1 for t in report_payload["typosquatting"] if t.get("status") == "Registered / Active")
    tbl.add_row("Typosquatting Risk", f"{active_typos} Active Registered Permutations", "Brand Impersonation Risk" if active_typos else "Clean")
    console.print()
    console.print(tbl)
    console.print()
    excel_export(report_payload, output_path)

# ----- ASCII Banner --------------------------------------------- #

def ascii() -> int:
    art_content = rf"""
ooooooooo.    o8o           oooo        ooooo                 .             oooo
`888   `Y88.  `"'           `888        `888'               .o8             `888
 888   .d88' oooo   .oooo.o  888  oooo   888  ooo. .oo.   .o888oo  .ooooo.   888
 888ooo88P'  `888  d88(  "8  888 .8P'    888  `888P"Y88b    888   d88' `88b  888
 888`88b.     888  `"Y88b.   888888.     888   888   888    888   888ooo888  888
 888  `88b.   888  o.  )88b  888 `88b.   888   888   888    888 . 888    .o  888
o888o  o888o o888o 8""888P' o888o o888o o888o o888o o888o   "888" `Y8bod8P' o888o
"""
    art_color = Text(art_content, style = "#C6ECE3")
    art_panel = Panel(art_color, border_style = "#C6ECE3", expand = False)
    console.print(art_panel)
    banner_width = console.measure(art_panel).maximum
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print(f"  [~] Created by [bold red blink]Cursed271[/bold red blink]")
    console.print(f"  [~] RiskIntel - Turn external exposure into actionable intelligence.")
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print()
    return banner_width

# ----- Argument Parser ------------------------------------------ #

@app.command()
def argu(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain to inspect"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save path for Excel report (.xlsx)"),
    threads: int = typer.Option(20, "--threads", "-t", help="Number of concurrent worker threads"),
) -> None:
    if not domain:
        domain = Prompt.ask(f"[#C6ECE3][?] Enter the Domain Name for External Reconnaissance")
    clean_domain = domain.strip().lower()
    title_domain = utilities_extract_target(clean_domain)
    clean_output = output.strip() if output else None
    console.print(f"[#2ECC71][+] RiskIntel initiated against [bold white]{title_domain}[/bold white] using {threads} threads")
    orchestrate(
        domain=clean_domain,
        output_path=clean_output,
        threads=threads
    )

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    banner_width = ascii()
    typer_rich.MAX_WIDTH = banner_width
    app()

# ----- End ------------------------------------------------------ #