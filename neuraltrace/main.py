# neuraltrace/main.py
"""
Main orchestration module for NeuralTrace.
Integrates all components.
"""
import asyncio
import logging
from typing import Dict, List
from neuraltrace.capture.packet_capture import PacketCapture
from neuraltrace.ml.anomaly_detector import AnomalyDetector
from neuraltrace.rag.rag_pipeline import RAGPipeline
from neuraltrace.api.attribution import AttackAttribution
from neuraltrace.api.log_correlator import LogCorrelator
from neuraltrace.utils.config import Config
from neuraltrace.utils.database import Database
from neuraltrace.utils.s3_storage import S3Storage
from xai_api import Grok3Client

logger = logging.getLogger(__name__)

class NeuralTrace:
    """Orchestrates NeuralTrace network forensic analysis."""
    
    def __init__(self, interface: str):
        """
        Initialize NeuralTrace.
        
        Args:
            interface (str): Network interface.
        """
        self.config = Config()
        self.db = Database(self.config.db_url)
        self.s3 = S3Storage(self.config.aws_access_key, self.config.aws_secret_key, self.config.aws_s3_bucket)
        self.capture = PacketCapture(interface, self.db, self.s3)
        self.rag = RAGPipeline(self.db, self.s3)
        self.grok = Grok3Client(api_key=self.config.xai_api_key)
        self.detector = AnomalyDetector(self.grok, self.config.dataset_path)
        self.attribution = AttackAttribution(
            self.config.x_api_key, self.config.whois_api_key, self.config.brightdata_auth, self.db, self.s3
        )
        self.correlator = LogCorrelator(self.db, self.s3)
        self.analysis_results: List[Dict] = []

    async def run_analysis(self, count: int = 100, x_handle: str = None) -> Dict:
        """
        Execute forensic analysis.
        
        Args:
            count (int): Number of packets to capture.
            x_handle (str): X username for OSINT.
            
        Returns:
            Dict: Analysis results and parameters.
        """
        try:
            packets = await self.capture.capture_packets(count)
            await self.rag.index_telemetry()
            for packet in packets:
                analysis = await self.detector.analyze_packet(packet, self.rag)
                await self.db.update_packet_analysis(packet, analysis)
                if analysis.get("anomaly_score", 0) > 0.7:
                    attribution = await self.attribution.trace_ip(packet["src_ip"], x_handle)
                    await self.correlator.correlate_logs(packet, analysis, attribution)
                    self.analysis_results.append({**packet, **analysis, **attribution})
            return {"results": self.analysis_results}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {}

    async def save_report(self, filename: str = "neuraltrace_report.jsonl"):
        """
        Save analysis report.
        
        Args:
            filename (str): Report file path.
        """
        try:
            with open(filename, "w") as f:
                for result in self.analysis_results:
                    f.write(json.dumps(result) + "\n")
            s3_key = f"reports/{filename}"
            await self.s3.upload_file(filename, s3_key)
            logger.info(f"Report saved to {filename} and S3: {s3_key}")
        except Exception as e:
            logger.error(f"Report saving failed: {e}")