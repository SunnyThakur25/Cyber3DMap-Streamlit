# neuraltrace/rag/rag_pipeline.py
"""
RAG pipeline module for NeuralTrace.
Indexes telemetry for Grok 3 analysis.
"""
import asyncio
import logging
import json
import faiss
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from llama_index.vector_stores.faiss import FaissVectorStore
from neuraltrace.utils.database import Database
from neuraltrace.utils.s3_storage import S3Storage

logger = logging.getLogger(__name__)

class RAGPipeline:
    """Manages telemetry indexing and retrieval for RAG."""
    
    def __init__(self, db: Database, s3: S3Storage):
        """
        Initialize RAGPipeline.
        
        Args:
            db (Database): Database instance.
            s3 (S3Storage): S3 storage instance.
        """
        self.db = db
        self.s3 = s3
        self.dimension = 384
        self.faiss_index = faiss.IndexFlatL2(self.dimension)
        self.vector_store = FaissVectorStore(faiss_index=self.faiss_index)
        self.index = None

    async def index_telemetry(self):
        """Index telemetry from DB and S3."""
        try:
            telemetry = await self.db.get_telemetry(["packet", "zeek_log", "attribution"])
            documents = []
            for row in telemetry:
                content = json.loads(row["content"])
                if row["s3_key"]:
                    content.update(await self.s3.get_json(row["s3_key"]))
                documents.append(SimpleDirectoryReader(input_files=[json.dumps(content)]).load_data())
            self.index = VectorStoreIndex.from_documents(documents, vector_store=self.vector_store)
            logger.info("Indexed telemetry")
        except Exception as e:
            logger.error(f"RAG indexing failed: {e}")

    async def query_telemetry(self, query: str) -> List[Dict]:
        """
        Retrieve telemetry for query.
        
        Args:
            query (str): Query string.
            
        Returns:
            List[Dict]: Relevant telemetry.
        """
        if not self.index:
            await self.index_telemetry()
        try:
            retriever = self.index.as_retriever(top_k=5)
            results = retriever.retrieve(query)
            return [json.loads(node.text) for node in results]
        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return []