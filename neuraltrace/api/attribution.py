# neuraltrace/api/attribution.py
"""
OSINT attribution module for NeuralTrace.
Traces IPs using X API and WhoisXML.
"""
import asyncio
import logging
import random
import requests
from typing import Dict
from neuraltrace.utils.database import Database
from neuraltrace.utils.s3_storage import S3Storage
from brightdata import ProxyManager

logger = logging.getLogger(__name__)

class AttackAttribution:
    """Performs OSINT-based IP attribution."""
    
    def __init__(self, x_api_key: str, whois_api_key: str, brightdata_auth: str, db: Database, s3: S3Storage):
        """
        Initialize AttackAttribution.
        
        Args:
            x_api_key (str): X API key.
            whois_api_key (str): WhoisXML API key.
            brightdata_auth (str): Bright Data auth.
            db (Database): Database instance.
            s3 (S3Storage): S3 storage instance.
        """
        self.x_url = "https://api.x.com/2/users/by/username"
        self.whois_url = "https://api.whoisxmlapi.com/v1/who.is"
        self.x_api_key = x_api_key
        self.whois_api_key = whois_api_key
        self.proxy_manager = ProxyManager(auth=brightdata_auth)
        self.db = db
        self.s3 = s3

    async def trace_ip(self, ip: str, x_handle: str = None) -> Dict:
        """
        Trace IP origin.
        
        Args:
            ip (str): IP address.
            x_handle (str): X username (optional).
            
        Returns:
            Dict: Attribution data.
        """
        try:
            proxy = self.proxy_manager.get_proxy()
            headers = {
                "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.36",
                "Authorization": f"Bearer {self.x_api_key}"
            }
            profile = {"ip": ip, "attribution": "unknown", "whois": {}}
            
            # X API
            if x_handle:
                response = requests.get(
                    f"{self.x_url}/{x_handle}", headers=headers, proxies={"https": proxy}
                )
                response.raise_for_status()
                profile["attribution"] = response.json().get("data", {}).get("description", "unknown")
            
            # WhoisXML API
            response = requests.get(
                self.whois_url, params={"ip": ip, "apiKey": self.whois_api_key}, proxies={"https": proxy}, headers=headers
            )
            response.raise_for_status()
            profile["whois"] = response.json().get("registrant", {})
            
            # Store in DB/S3
            s3_key = f"telemetry/attribution/{ip}_{random.randint(1000, 9999)}.json"
            await self.s3.upload_json(profile, s3_key)
            await self.db.insert_telemetry(ip, "attribution", profile, s3_key)
            
            logger.info(f"Traced IP {ip}: {profile}")
            return profile
        except Exception as e:
            logger.error(f"IP tracing failed: {e}")
            self.proxy_manager.rotate_proxy()
            return {}