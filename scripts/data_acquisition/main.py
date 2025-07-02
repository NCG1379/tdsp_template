import os
import json
import ipaddress
import urllib.request
import urllib.parse
from datetime import datetime
from setting import API_KEY, API_URL_IP, API_URL_DOMAIN
from pydantic import BaseModel, Field, field_validator


def validate_ioc_value(value: str) -> str:
    """
    Validate if the input value is an IP address or a domain.
    Returns a tuple: (value, 'ip') or (value, 'domain').
    Raises ValueError if neither.
    """
    try:
        ipaddress.ip_address(value)
        return (value, 'ip')  # It's a valid IP address
    except ValueError:
        if "." in value:
            return (value, 'domain')  # It's a domain
        raise ValueError("Invalid IOC. Must be a valid IP address or domain.")

class IOCValidatedModel(BaseModel):
    """
    Base Pydantic model for validating and storing an IOC (IP or domain).
    """
    ioc: str = Field(description="IP or Domain to query for information")

    @field_validator("ioc")
    def validate_ioc(cls, value):
        return validate_ioc_value(value)

class VirusTotal(IOCValidatedModel):
    """
    Class for querying VirusTotal API for IP or domain information.
    Inherits IOC validation from IOCValidatedModel.
    """
    def display_info(self):
        """
        Display information for the IOC, dispatching to the correct method
        based on whether the IOC is an IP or a domain.
        """
        ioc_value, ioc_type = self.ioc
        if ioc_type == 'ip':
            return self.display_ip_info()
        elif ioc_type == 'domain':
            return self.display_domain_info()
        else:
            raise ValueError("Unsupported IOC type. Must be either an IP address or a domain.")

    def get_associated_domains(self):
        """
        For an IP address, fetch associated domains from VirusTotal.
        Returns a list of domain names.
        """
        ioc_value, ioc_type = self.ioc
        if ioc_type != 'ip':
            raise ValueError("Associated domains can only be retrieved for IP addresses.")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}/resolutions"
        request = urllib.request.Request(url, headers={'x-apikey': API_KEY})
        try:
            with urllib.request.urlopen(request) as response:
                data = json.load(response)
                return [res['attributes']['host_name'] for res in data.get('data', [])]
        except urllib.error.URLError as e:
            print(f"Failed to retrieve associated domains for {self.ip}: {e}")
            return []

    def display_ip_info(self):
        """
        Fetch and display information about an IP address from VirusTotal.
        Writes results to output/single-ip/{ip}.txt and returns the output string.
        """
        ioc_value, ioc_type = self.ioc
        if ioc_type != 'ip':
            raise ValueError("display_ip_info can only be used with IP addresses.")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        request = urllib.request.Request(url, headers={'x-apikey': API_KEY, 'accept': 'application/json'})
        try:
            with urllib.request.urlopen(request) as response:
                data = json.load(response)
        except urllib.error.URLError as e:
            print(f"Failed to retrieve data: {e}")
            return

        attr = data.get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        domains = self.get_associated_domains()
        lines = [
            f"IP: {ioc_value}",
            f"AS Owner: {attr.get('as_owner')}",
            f"ASN: {attr.get('asn')}",
            f"Continent: {attr.get('continent')}",
            f"Country: {attr.get('country')}",
            f"JARM: {attr.get('jarm')}",
            f"Last Analysis Date: {attr.get('last_analysis_date')}",
            f"Reputation Score: {attr.get('reputation')}",
            f"Tags: {', '.join(attr.get('tags', []))}",
            f"Votes: Harmless {attr.get('total_votes', {}).get('harmless', 0)}, Malicious {attr.get('total_votes', {}).get('malicious', 0)}",
            "Last Analysis Stats:",
            *(f"  {k.capitalize()}: {stats.get(k, 0)}" for k in ['harmless', 'malicious', 'suspicious', 'timeout', 'undetected']),
            f"Last HTTPS Certificate Date: {attr.get('last_https_certificate_date')}",
            f"Last Modification Date: {attr.get('last_modification_date')}",
            f"Network: {attr.get('network')}",
            f"Regional Internet Registry: {attr.get('regional_internet_registry')}",
            f"WHOIS: {attr.get('whois')}",
            f"WHOIS Date: {attr.get('whois_date')}",
            f"Associated Domains: {', '.join(domains) if domains else 'No associated domains'}",
            "-" * 40
        ]
        os.makedirs("output/single-ip", exist_ok=True)
        with open(f"output/single-ip/{ioc_value}.txt", "w") as f:
            f.write("\n".join(lines))
        return "\n".join(lines)

    def display_domain_info(self):
        """
        Fetch and display information about a domain from VirusTotal.
        Writes results to output/single-domain/{domain}.txt and returns the output string.
        """
        ioc_value, ioc_type = self.ioc
        if ioc_type != 'domain':
            raise ValueError("display_domain_info can only be used with domains.")
        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(ioc_value)}"
        request = urllib.request.Request(url, headers={'x-apikey': API_KEY, 'accept': 'application/json'})
        try:
            with urllib.request.urlopen(request) as response:
                data = json.load(response)
        except urllib.error.URLError as e:
            print(f"Failed to retrieve data: {e}")
            return

        attr = data.get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        lines = [
            f"Domain: {ioc_value}",
            f"Categories: {', '.join(attr.get('categories', {}).values())}",
            f"Creation Date: {attr.get('creation_date')}",
            f"Last Analysis Date: {attr.get('last_analysis_date')}",
            "Last Analysis Stats:",
            *(f"  {k.capitalize()}: {stats.get(k, 0)}" for k in ['harmless', 'malicious', 'suspicious', 'timeout', 'undetected']),
            f"Last Modification Date: {attr.get('last_modification_date')}",
            f"Reputation Score: {attr.get('reputation')}",
            f"Tags: {', '.join(attr.get('tags', []))}",
            f"Total Votes: Harmless - {attr.get('total_votes', {}).get('harmless', 0)}, Malicious - {attr.get('total_votes', {}).get('malicious', 0)}",
            "-" * 40
        ]
        os.makedirs("output/single-domain", exist_ok=True)
        with open(f"output/single-domain/{ioc_value}.txt", "w") as f:
            f.write("\n".join(lines))
        return "\n".join(lines)


newConnection = VirusTotal(ioc="google.com")
print(newConnection.display_info())

class AbuseIPDB(IOCValidatedModel):
    pass

class WHOIS_RDAP(IOCValidatedModel):
    pass

class ShodanIO(IOCValidatedModel):
    pass
