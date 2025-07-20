from typing import Any
from scripts.utils.mongo_handler import query_db

def vt_summary(ioc: Any) -> dict:
    data = query_db(collection="VirusTotal", query={"ioc": ioc.ioc}, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}

def whois_summary(ioc: Any) -> dict:
    data = query_db(collection="whois", query={"ioc": ioc.ioc}, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}

def abuseipdb_summary(ioc: Any) -> dict:
    data = query_db(collection="AbuseIPDB", query={"ipAddress": ioc.ioc}, one_element=True)
    if len(data) > 0:
        if isinstance(data[0], dict):
            return data[0]
    return {"message": "Unknown"}
