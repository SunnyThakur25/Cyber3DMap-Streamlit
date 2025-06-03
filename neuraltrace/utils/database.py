# neuraltrace/utils/database.py
"""
Database management for NeuralTrace.
Handles PostgreSQL interactions.
"""
import asyncio
import logging
import psycopg2
from psycopg2.extras import DictCursor
from typing import Dict, List

logger = logging.getLogger(__name__)

class Database:
    """Manages PostgreSQL database operations."""
    
    def __init__(self, db_url: str):
        """
        Initialize Database.
        
        Args:
            db_url (str): PostgreSQL connection URL.
        """
        self.db_url = db_url
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        try:
            conn = psycopg2.connect(self.db_url)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR(50),
                    payload TEXT,
                    anomaly_score FLOAT,
                    attack_type VARCHAR(100),
                    mitre_attck VARCHAR(50)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source VARCHAR(255),
                    data_type VARCHAR(100),
                    content TEXT,
                    s3_key VARCHAR(255)
                )
            """)
            conn.commit()
            conn.close()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")

    async def insert_packet(self, packet: Dict):
        """Insert packet into database."""
        try:
            conn = psycopg2.connect(self.db_url)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, payload)
                VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s)
                """,
                (packet["timestamp"], packet["src_ip"], packet["dst_ip"], packet["src_port"],
                 packet["dst_port"], packet["protocol"], packet["payload"])
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Packet insertion failed: {e}")

    async def insert_telemetry(self, source: str, data_type: str, content: Dict, s3_key: str):
        """Insert telemetry into database."""
        try:
            conn = psycopg2.connect(self.db_url)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO telemetry (source, data_type, content, s3_key)
                VALUES (%s, %s, %s, %s)
                """,
                (source, data_type, json.dumps(content), s3_key)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Telemetry insertion failed: {e}")

    async def get_telemetry(self, data_types: List[str]) -> List[Dict]:
        """Retrieve telemetry by data types."""
        try:
            conn = psycopg2.connect(self.db_url)
            cursor = conn.cursor(cursor_factory=DictCursor)
            cursor.execute(
                "SELECT content, s3_key FROM telemetry WHERE data_type IN %s",
                (tuple(data_types),)
            )
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Telemetry retrieval failed: {e}")
            return []

    async def update_packet_analysis(self, packet: Dict, analysis: Dict):
        """Update packet with analysis results."""
        try:
            conn = psycopg2.connect(self.db_url)
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE packets SET anomaly_score=%s, attack_type=%s, mitre_attck=%s
                WHERE src_ip=%s AND dst_ip=%s AND timestamp=to_timestamp(%s)
                """,
                (analysis["anomaly_score"], analysis["attack_type"], analysis["mitre_attck"],
                 packet["src_ip"], packet["dst_ip"], packet["timestamp"])
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Packet update failed: {e}")