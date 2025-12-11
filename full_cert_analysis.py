import os
import socket
import json
import subprocess
import re
import pandas as pd
from datetime import datetime

OUTPUT_DIR = os.path.expanduser("~/rpki-analysis/reports")
CACHE_DIR = "/var/lib/rpki-client"

CDN_DOMAINS = {
    "amazonaws.com": ("AWS", "US/Global"),
    "cloudfront.net": ("AWS CloudFront", "US/Global"),
    "cloudflare": ("Cloudflare", "Global"),
    "akamai": ("Akamai", "Global"),
    "fastly": ("Fastly", "US/Global"),
    "azure": ("Azure", "US/Global"),
    "googleapis": ("Google Cloud", "US/Global"),
    "digitalocean": ("DigitalOcean", "US/EU"),
    "linode": ("Linode/Akamai", "US/EU"),
    "vultr": ("Vultr", "Global"),
    "ovh": ("OVH", "EU"),
    "hetzner": ("Hetzner", "EU/Germany"),
}

ip_cache = {}

def resolve_domain(domain):
    if domain in ip_cache:
        return ip_cache[domain]
    try:
        ip = socket.gethostbyname(domain)
        ip_cache[domain] = ip
        return ip
    except:
        ip_cache[domain] = None
        return None

def identify_cdn(domain, ip):
    domain_lower = domain.lower() if domain else ""
    for pattern, (cdn_name, location) in CDN_DOMAINS.items():
        if pattern in domain_lower:
            return True, cdn_name, location
    if ip:
        if ip.startswith(("13.", "52.", "54.", "3.", "18.", "34.", "35.")):
            return True, "AWS (likely)", "US/Global"
        if ip.startswith(("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.65.", "172.66.", "172.67.")):
            return True, "Cloudflare", "Global"
    return False, "", ""

def extract_cert_info(cert_path):
    """Extract IP prefixes from certificate using openssl"""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-inform", "DER", "-noout", "-text"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        
        ipv4_prefixes = []
        
        ip_section = re.search(r'sbgp-ipAddrBlock.*?(?=X509v3|$)', output, re.DOTALL)
        if ip_section:
            section_text = ip_section.group(0)
            ipv4_prefixes = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', section_text)
            ranges = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', section_text)
            for start, end in ranges:
                ipv4_prefixes.append(f"{start}-{end}")
        
        if not ipv4_prefixes:
            ipv4_prefixes = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', output)
        
        if "0.0.0.0" in output and "255.255.255.255" in output:
            return ["0.0.0.0/0 (ALL)"], True
        if "inherit" in output.lower():
            return ["INHERITED"], True
            
        return list(set(ipv4_prefixes)), False
    except Exception as e:
        return [], False

print("Loading RPKI JSON data...")
with open(f"{CACHE_DIR}/json", "r") as f:
    data = json.load(f)

print("Building AS number mapping from ROAs...")
prefix_to_as = {}
for roa in data.get("roas", []):
    asn = roa.get("asn", "")
    prefix = roa.get("prefix", "")
    ta = roa.get("ta", "")
    if prefix and asn:
        prefix_to_as[prefix] = {"asn": asn, "ta": ta}

ta_mapping = {}

for item in data.get("bgpsec_pubkeys", []):
    ta = item.get("ta", "")
    ski = item.get("ski", "")
    if ski and ta:
        ta_mapping[ski] = ta.upper()

for item in data.get("aspas", []):
    ta = item.get("ta", "")
    customer_asid = str(item.get("customer_asid", ""))
    if customer_asid and ta:
        ta_mapping[f"AS{customer_asid}"] = ta.upper()

print("Scanning certificates...")
cert_records = []
cert_count = 0
repo_as_mapping = {}

for root, dirs, files in os.walk(CACHE_DIR):
    for f in files:
        if f.endswith(".cer"):
            cert_count += 1
            cert_path = os.path.join(root, f)
            rel_path = cert_path.replace(CACHE_DIR, "").strip("/")
            
            path_parts = rel_path.split("/")
            repo_domain = ""
            for part in path_parts:
                if "." in part and not part.endswith(".cer") and not part.startswith("ta"):
                    repo_domain = part
                    break
            
            is_ta_cert = "/ta/" in rel_path.lower() or "rpki-ta" in f.lower()
            
            ta = ""
            path_lower = rel_path.lower()
            if "apnic" in path_lower or "apnic" in repo_domain.lower():
                ta = "APNIC"
            elif "arin" in path_lower or "arin" in repo_domain.lower():
                ta = "ARIN"
            elif "ripe" in path_lower or "ripe" in repo_domain.lower():
                ta = "RIPE"
            elif "lacnic" in path_lower or "lacnic" in repo_domain.lower() or "registro.br" in repo_domain.lower():
                ta = "LACNIC"
            elif "afrinic" in path_lower or "afrinic" in repo_domain.lower():
                ta = "AFRINIC"
            elif "cnnic" in repo_domain.lower():
                ta = "APNIC"  
            elif "twnic" in repo_domain.lower():
                ta = "APNIC"  
            elif "idnic" in repo_domain.lower():
                ta = "APNIC"  
            elif "nic.ad.jp" in repo_domain.lower():
                ta = "APNIC"  
            
            ipv4_prefixes, is_delegating_all = extract_cert_info(cert_path)
            
            if is_delegating_all:
                is_ta_cert = True
            
            as_numbers = set()
            for prefix in ipv4_prefixes:
                clean_prefix = prefix.replace(" (ALL)", "").strip()
                if clean_prefix in prefix_to_as:
                    as_numbers.add(prefix_to_as[clean_prefix]["asn"])
                    if not ta:
                        ta = prefix_to_as[clean_prefix].get("ta", "").upper()
            
            ip_address = ""
            is_cdn = False
            cdn_provider = ""
            cdn_location = ""
            
            if repo_domain and repo_domain != "LOCAL":
                ip_address = resolve_domain(repo_domain) or "UNRESOLVED"
                is_cdn, cdn_provider, cdn_location = identify_cdn(repo_domain, ip_address)
            elif "/ta/" in rel_path:
                repo_domain = "LOCAL"
                ip_address = "N/A - LOCAL"
            
            if repo_domain and as_numbers:
                if repo_domain not in repo_as_mapping:
                    repo_as_mapping[repo_domain] = set()
                repo_as_mapping[repo_domain].update(as_numbers)
            
            as_list = sorted(as_numbers)
            
            cert_records.append({
                "Certificate": f,
                "Repository_Domain": repo_domain if repo_domain else "UNKNOWN",
                "Repo_IP_Address": ip_address if ip_address else "UNKNOWN",
                "Trust_Anchor": ta if ta else "UNKNOWN",
                "Is_TA_Cert": is_ta_cert,
                "IPv4_Prefixes": "; ".join(ipv4_prefixes[:20]) + ("..." if len(ipv4_prefixes) > 20 else "") if ipv4_prefixes else "NONE",
                "IPv4_Count": len(ipv4_prefixes),
                "AS_Numbers": "; ".join(str(a) for a in as_list[:10]) + ("..." if len(as_list) > 10 else ""),
                "AS_Count": len(as_list),
                "Is_CDN": is_cdn,
                "CDN_Provider": cdn_provider if cdn_provider else "None",
                "CDN_Location": cdn_location if cdn_location else "N/A",
                "Full_Path": rel_path
            })
            
            if cert_count % 5000 == 0:
                print(f"  Processed {cert_count} certificates...")

print(f"Total certificates found: {cert_count}")

print("Creating repository summary...")
repo_data = {}
for rec in cert_records:
    domain = rec["Repository_Domain"]
    if domain and domain != "UNKNOWN" and domain != "LOCAL":
        if domain not in repo_data:
            repo_data[domain] = {
                "Repository_Domain": domain,
                "IP_Address": rec["Repo_IP_Address"],
                "Is_CDN": rec["Is_CDN"],
                "CDN_Provider": rec["CDN_Provider"],
                "CDN_Location": rec["CDN_Location"],
                "Certificate_Count": 0,
                "Total_IPv4_Prefixes": 0,
                "Trust_Anchors": set(),
                "AS_Numbers": set()
            }
        repo_data[domain]["Certificate_Count"] += 1
        repo_data[domain]["Total_IPv4_Prefixes"] += rec["IPv4_Count"]
        if rec["Trust_Anchor"] and rec["Trust_Anchor"] != "UNKNOWN":
            repo_data[domain]["Trust_Anchors"].add(rec["Trust_Anchor"])
        for asn in rec["AS_Numbers"].replace("...", "").split("; "):
            if asn.strip():
                repo_data[domain]["AS_Numbers"].add(asn.strip())

repo_records = []
for domain, info in repo_data.items():
    tas = sorted(info["Trust_Anchors"])
    repo_records.append({
        "Repository_Domain": info["Repository_Domain"],
        "IP_Address": info["IP_Address"],
        "Is_CDN": info["Is_CDN"],
        "CDN_Provider": info["CDN_Provider"],
        "CDN_Location": info["CDN_Location"],
        "Certificate_Count": info["Certificate_Count"],
        "Total_IPv4_Prefixes": info["Total_IPv4_Prefixes"],
        "AS_Numbers": "; ".join(sorted(info["AS_Numbers"])[:20]),
        "Unique_AS_Count": len(info["AS_Numbers"]),
        "Trust_Anchors": ", ".join(tas) if tas else "MIXED/UNKNOWN"
    })

df_repos = pd.DataFrame(repo_records).sort_values(["Is_CDN", "Certificate_Count"], ascending=[False, False])
df_certs = pd.DataFrame(cert_records)

os.makedirs(OUTPUT_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
excel_file = f"{OUTPUT_DIR}/rpki_complete_analysis_{timestamp}.xlsx"

with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
    df_repos.to_excel(writer, sheet_name="Repositories", index=False)
    df_certs.to_excel(writer, sheet_name="All Certificates", index=False)

print(f"\n✅ Excel saved: {excel_file}")
print(f"   Sheet 1 - Repositories: {len(df_repos)} domains")
print(f"   Sheet 2 - All Certificates: {len(df_certs)} certificates")
print(f"   CDN-hosted repos: {df_repos['Is_CDN'].sum()}")
print(f"   Total ROAs in JSON: {len(data.get('roas', []))}")
print(f"   Prefixes with AS mapping: {len(prefix_to_as)}")
