from typing import Any
from scripts.utils.mongo_handler import query_db

vt_filter = {"_id": 0, "data.links": 1, "data.attributes.total_votes": 1, "data.attributes.categories": 1,
             "data.attributes.last_analysis_date": 1, "data.attributes.last_analysis_stats": 1}

whois_filter = {"_id": 0, 'startAddress': 1, 'endAddress': 1, 'parentHandle': 1, "status": 1, "name": 1, "type": 1, "country": 1}

abuseipdb_filter = {"_id": 0, "domain": 1, "isWhitelisted": 1, "abuseConfidenceScore": 1, "countryCode": 1,
                "usageType": 1, "isTor": 1, "totalReports": 1, "lastReportedAt": 1}

def vt_summary(ioc: Any) -> dict:
    data = query_db(collection="VirusTotal", query={"ioc": ioc.ioc}, filter=vt_filter, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}

def whois_summary(ioc: Any) -> dict:
    data = query_db(collection="whois", query={"ioc": ioc.ioc}, filter=whois_filter, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}

def abuseipdb_summary(ioc: Any) -> dict:
    data = query_db(collection="AbuseIPDB", query={"ipAddress": ioc.ioc}, filter=abuseipdb_filter, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}
