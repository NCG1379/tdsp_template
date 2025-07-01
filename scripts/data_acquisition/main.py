import os
import json
import ipaddress
import urllib.request
import urllib.parse
from datetime import datetime
from setting import API_KEY, API_URL_IP, API_URL_DOMAIN
from pydantic import BaseModel, Field, field_validator

class VirusTotal(BaseModel):
    ioc: str = Field(description="IP o dominio para buscar información en VirusTotal")
    
    @field_validator("ioc")
    def validate_ioc(cls, value):
        try:
            ipaddress.ip_address(value)
            return value  # It's a valid IP address
        except ValueError:
            # If it's not an IP, assume it's a domain (you can improve validation later)
            if "." in value:
                return value
            raise ValueError("Invalid IOC. Must be a valid IP address or domain.")

class AbuseIPDB(BaseModel):
    ioc: str = Field(description="IP o dominio para buscar información en AbuseIPDB")

class WHOIS_RDAP(BaseModel):
    ioc: str = Field(description="IP o dominio para buscar información en WHOIS_RDAP")

class ShodanIO(BaseModel):
    ioc: str = Field(description="IP o dominio para buscar información en ShodanIO")

def virustotal(ioc):
    """Función para traer información de un ioc de virustotal"""
    try:
        validated_ioc = VirusTotal(ioc=ioc).ioc
    except ValueError as e:
        return {"error": str(e)}

    try:
        # Try parsing as IP
        ipaddress.ip_address(validated_ioc)
        return VirusTotal_APIRequest().display_ip_info(validated_ioc)
    except ValueError:
        # If not an IP, treat it as a domain
        return VirusTotal_APIRequest().display_domain_info(validated_ioc)

def abuseipdb(ioc):
    """Función para traer información de un ioc de abuseipdb"""
    return AbuseIPDB_APIRequest().request(ioc)

def whois_rdap(ioc):
    """Función para traer información de un ioc de whois_rdap"""
    return WHOIS_RDAP_APIRequest().request(ioc)

def shodanio(ioc):
    """Función para traer información de un ioc de shodanio"""
    return ShodanIO_APIRequest().request(ioc)


class VirusTotal_APIRequest():

    def fetch_data(self, url):
        request = urllib.request.Request(url, headers={'x-apikey': API_KEY})
        try:
            with urllib.request.urlopen(request) as response:
                data = json.load(response)
                return data
        except urllib.error.URLError as e:
            print(f"Failed to retrieve data: {e}")
            return None

    def get_associated_domains(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        request = urllib.request.Request(url, headers={'x-apikey': API_KEY})
        associated_domains = []
        try:
            with urllib.request.urlopen(request) as response:
                data = json.load(response)
                associated_domains.extend([res['attributes']['host_name'] for res in data.get('data', [])])
        except urllib.error.URLError as e:
            print(f"Failed to retrieve associated domains for {ip}: {e}")
        return associated_domains

    def display_ip_info(self, ip):
        url = API_URL_IP + urllib.parse.quote(ip)
        data = self.fetch_data(url)
        if not data:
            return

        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        associated_domains = self.get_associated_domains(ip)

        result = [
            f"IP: {ip}",
            f"AS Owner: {attributes.get('as_owner')}",
            f"ASN: {attributes.get('asn')}",
            f"Continent: {attributes.get('continent')}",
            f"Country: {attributes.get('country')}",
            f"JARM: {attributes.get('jarm')}",
            f"Last Analysis Date: {attributes.get('last_analysis_date')}",
            f"Reputation Score: {attributes.get('reputation')}",
            f"Tags: {', '.join(attributes.get('tags', []))}",
            f"Total Votes: Harmless - {attributes.get('total_votes', {}).get('harmless', 0)}, Malicious - {attributes.get('total_votes', {}).get('malicious', 0)}",
            "Last Analysis Stats:",
            f"  Harmless: {last_analysis_stats.get('harmless', 0)}",
            f"  Malicious: {last_analysis_stats.get('malicious', 0)}",
            f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}",
            f"  Timeout: {last_analysis_stats.get('timeout', 0)}",
            f"  Undetected: {last_analysis_stats.get('undetected', 0)}",
            f"Last HTTPS Certificate Date: {attributes.get('last_https_certificate_date')}",
            f"Last Modification Date: {attributes.get('last_modification_date')}",
            f"Network: {attributes.get('network')}",
            f"Regional Internet Registry: {attributes.get('regional_internet_registry')}",
            f"WHOIS: {attributes.get('whois')}",
            f"WHOIS Date: {attributes.get('whois_date')}",
            f"Associated Domains: {', '.join(associated_domains) if associated_domains else 'No associated domains'}",
            "-" * 40
        ]

        # Ensure the output directory exists
        output_dir = "output/single-ip"
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, f"{ip}.txt")
        with open(output_path, 'w') as f:
            f.write("\n".join(result))

        return "\n".join(result)

    def display_domain_info(self, domain):
        url = API_URL_DOMAIN + urllib.parse.quote(domain)
        data = self.fetch_data(url)
        if not data:
            return

        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        result = [
            f"Domain: {domain}",
            f"Categories: {', '.join(attributes.get('categories', {}).values())}",
            f"Creation Date: {attributes.get('creation_date')}",
            f"Last Analysis Date: {attributes.get('last_analysis_date')}",
            f"Last Analysis Stats:",
            f"  Harmless: {last_analysis_stats.get('harmless', 0)}",
            f"  Malicious: {last_analysis_stats.get('malicious', 0)}",
            f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}",
            f"  Timeout: {last_analysis_stats.get('timeout', 0)}",
            f"  Undetected: {last_analysis_stats.get('undetected', 0)}",
            f"Last Modification Date: {attributes.get('last_modification_date')}",
            f"Reputation Score: {attributes.get('reputation')}",
            f"Tags: {', '.join(attributes.get('tags', []))}",
            f"Total Votes: Harmless - {attributes.get('total_votes', {}).get('harmless', 0)}, Malicious - {attributes.get('total_votes', {}).get('malicious', 0)}",
            "-" * 40
        ]

        # Ensure the output directory exists
        output_dir = "output/single-domain"
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, f"{domain}.txt")
        with open(output_path, 'w') as f:
            f.write("\n".join(result))

        print("\n".join(result))

class AbuseIPDB_APIRequest():

    def request(self):

        return 0
    
class WHOIS_RDAP_APIRequest():

    def request(self):

        return 0

class ShodanIO_APIRequest():

    def request(self):

        return 0
    
class TheatMiner_APIRequest():

    def request(self):

        return 0


