# neuraltrace/api/log_correlator.py
"""
Log correlation module for NeuralTrace.
Aggregates logs via FastAPI.
"""
import asyncio
import logging
import json
from typing import Dict
from fastapi import FastAPI
from neuraltrace.utils.database import Database
from neuraltrace.utils.s3_storage import S3Storage

logger = logging.getLogger(__name__)

class LogCorrelator:
    """Correlates telemetry logs with FastAPI routes."""
    
    def __init__(self, db: Database, s3: S3Storage):
        """
        Initialize LogCorrelator.
        
        Args:
            db (Database): Database instance.
            s3 (S3Storage): S3 storage instance.
        """
        self.db = db
        self.s3 = s3
        self.app = FastAPI()

        @self.app.get("/logs/{data_type}")
        async def get_logs(data_type: str):
            """Retrieve logs by data type."""
            logs = await self.db.get_telemetry([data_type])
            results = []
            for log in logs:
                content = json.loads(log["content"])
                if log["s3_key"]:
                    content.update(await self.s3.get_json(log["s3_key"]))
                results.append(content)
            return {"logs": results}

        @self.app.post("/analyze")
        async def analyze_packet(packet: Dict):
            """Placeholder for packet analysis endpoint."""
            return {"status": "Analysis queued"}

    async def correlate_logs(self, packet: Dict, analysis: Dict, attribution: Dict):
        """
        Correlate packet, analysis, and attribution.
        
        Args:
            packet (Dict): Packet metadata.
            analysis (Dict): Anomaly detection results.
            attribution (Dict): OSINT attribution data.
        """
        try:
            event_type = analysis["attack_type"]
            details = {
                "packet": packet,
                "analysis": analysis,
                "attribution": attribution,
                "timestamp": packet["timestamp"]
            }
            s3_key = f"telemetry/correlation/{event_type}_{random.randint(1000, 9999)}.json"
            await self.s3.upload_json(details, s3_key)
            await self.db.insert_telemetry(packet["src_ip"], "correlation", details, s3_key)
            logger.info(f"Correlated log for {event_type}")
        except Exception as e:
            logger.error(f"Log correlation failed: {e}")