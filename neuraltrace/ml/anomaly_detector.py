# neuraltrace/ml/anomaly_detector.py
"""
Anomaly detection module for NeuralTrace.
Uses SVM and xAI Grok 3 for hybrid detection.
"""
import asyncio
import logging
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
import pandas as pd
from neuraltrace.rag.rag_pipeline import RAGPipeline
from xai_api import Grok3Client

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Detects network anomalies using SVM and Grok 3."""
    
    def __init__(self, grok_client: Grok3Client, dataset_path: str):
        """
        Initialize AnomalyDetector.
        
        Args:
            grok_client (Grok3Client): xAI API client.
            dataset_path (str): Path to CICIDS-2017/UNSW-NB15 dataset.
        """
        self.grok = grok_client
        self.scaler = StandardScaler()
        self.model = SVC(probability=True)
        self.previous_timestamp = None
        self._train_model(dataset_path)

    def _train_model(self, dataset_path: str):
        """Train SVM on CICIDS-2017 or UNSW-NB15 dataset."""
        try:
            df = pd.read_csv(dataset_path)
            X = df[["packet_size", "interval", "src_port", "dst_port", "tcp_flags"]].values
            y = df["label"].apply(lambda x: 1 if x != "BENIGN" else 0).values
            X = self.scaler.fit_transform(X)
            self.model.fit(X, y)
            logger.info(f"Trained SVM on {dataset_path}")
        except Exception as e:
            logger.error(f"Training failed: {e}")
            # Fallback to mock data
            X = np.random.rand(1000, 5)
            y = np.random.randint(0, 2, 1000)
            X = self.scaler.fit_transform(X)
            self.model.fit(X, y)

    async def analyze_packet(self, packet: Dict, rag: RAGPipeline) -> Dict:
        """
        Analyze packet for anomalies.
        
        Args:
            packet (Dict): Packet metadata.
            rag (RAGPipeline): RAG pipeline for telemetry.
            
        Returns:
            Dict: Analysis results.
        """
        try:
            features = np.array([[
                len(packet["payload"]),
                packet["timestamp"] - self.previous_timestamp if self.previous_timestamp else 0.1,
                packet["src_port"],
                packet["dst_port"],
                1 if "tcp" in packet["protocol"].lower() else 0
            ]])
            self.previous_timestamp = packet["timestamp"]
            features = self.scaler.transform(features)
            anomaly_score = self.model.predict_proba(features)[0][1]
            prediction = self.model.predict(features)[0]
            attack_type = "anomaly" if prediction == 1 else "normal"
            
            # Grok 3 analysis with RAG
            query = f"Analyze packet: src_ip={packet['src_ip']}, dst_ip={packet['dst_ip']}, src_port={packet['src_port']}, dst_port={packet['dst_port']}, protocol={packet['protocol']}, payload={packet['payload'][:100]}"
            telemetry = await rag.query_telemetry(query)
            context = "\n".join([json.dumps(t) for t in telemetry])
            prompt = f"""
            Context: {context}
            Query: {query}
            Classify as benign or malicious. Specify attack type (e.g., C2, DDoS) and MITRE ATT&CK technique.
            """
            grok_response = await self.grok.query(prompt)
            result = {
                "anomaly_score": anomaly_score,
                "attack_type": grok_response.get("attack_type", attack_type),
                "mitre_attck": grok_response.get("mitre_attck", "T1071.001" if prediction == 1 else ""),
                "explanation": grok_response.get("explanation", "SVM-based detection")
            }
            logger.info(f"Analyzed packet: {result}")
            return result
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return {}