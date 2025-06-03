# neuraltrace/capture/packet_capture.py
"""
Packet capture module for NeuralTrace.
Captures live network traffic and generates Zeek logs.
"""
import asyncio
import logging
from typing import Dict, List
import scapy.all as scapy
from neuraltrace.utils.database import Database
from neuraltrace.utils.s3_storage import S3Storage
import zeek

logger = logging.getLogger(__name__)

class PacketCapture:
    """Manages live packet capture and Zeek log generation."""
    
    def __init__(self, interface: str, db: Database, s3: S3Storage):
        """
        Initialize PacketCapture.
        
        Args:
            interface (str): Network interface (e.g., eth0).
            db (Database): Database instance for storage.
            s3 (S3Storage): S3 storage instance for telemetry.
        """
        self.interface = interface
        self.db = db
        self.s3 = s3
        self.packets: List[Dict] = []
        self.zeek = zeek.Zeek()

    async def capture_packets(self, count: int = 100) -> List[Dict]:
        """
        Capture live packets and store in DB/S3.
        
        Args:
            count (int): Number of packets to capture.
            
        Returns:
            List[Dict]: Captured packet metadata.
        """
        try:
            packets = scapy.sniff(iface=self.interface, count=count, timeout=30)
            for pkt in packets:
                packet_data = {
                    "timestamp": pkt.time,
                    "src_ip": pkt[scapy.IP].src if scapy.IP in pkt else "unknown",
                    "dst_ip": pkt[scapy.IP].dst if scapy.IP in pkt else "unknown",
                    "src_port": pkt[scapy.TCP].sport if scapy.TCP in pkt else 0,
                    "dst_port": pkt[scapy.TCP].dport if scapy.TCP in pkt else 0,
                    "protocol": pkt[scapy.IP].proto if scapy.IP in pkt else "unknown",
                    "payload": str(pkt.payload)[:1000]
                }
                self.packets.append(packet_data)
                
                # Store in DB
                await self.db.insert_packet(packet_data)
                
                # Generate and store Zeek log
                zeek_log = self.zeek.process_packet(pkt)
                s3_key = f"telemetry/zeek/{packet_data['timestamp']}.json"
                await self.s3.upload_json(zeek_log, s3_key)
                await self.db.insert_telemetry(packet_data["src_ip"], "zeek_log", zeek_log, s3_key)
            
            logger.info(f"Captured {len(packets)} packets")
            return self.packets
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            return []