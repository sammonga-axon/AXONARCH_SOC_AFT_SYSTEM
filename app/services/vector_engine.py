import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from pinecone import Pinecone, PineconeAsyncio
from sentence_transformers import SentenceTransformer
from app.core.config import settings

logger = logging.getLogger(__name__)

class VectorFilterService:
    """
    Enterprise Vector Filtering Engine.
    Handles non-blocking embedding generation and dynamic risk-weighted search.
    """
    def __init__(self):
        try:
            logger.info("Initializing Async VectorFilterService...")
            
            # 1. Resolve Control Plane metadata
            pc_control = Pinecone(api_key=settings.PINECONE_API_KEY)
            index_metadata = pc_control.describe_index(settings.PINECONE_INDEX_NAME)
            target_host = index_metadata.host
            
            # 2. Instantiate Data Plane (Async)
            self.pc = PineconeAsyncio(api_key=settings.PINECONE_API_KEY)
            self.index = self.pc.IndexAsyncio(host=target_host)
            
            # 3. ML Model & Execution Pool
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            self.executor = ThreadPoolExecutor(max_workers=4) 
            
            # 4. Dynamic Threshold Map: Higher severity requires higher mathematical identity
            self.threshold_map = {
                "Critical": 0.99,
                "High": 0.97,
                "Medium": 0.95,
                "Low": 0.92,
                "Info": 0.90
            }
            
            logger.info("VectorFilterService initialized successfully.")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to initialize Vector Engine: {str(e)}")
            raise

    async def _generate_embedding(self, payload: str) -> list[float]:
        """Offloads the CPU-heavy encoding to background thread pool."""
        loop = asyncio.get_running_loop()
        vector = await loop.run_in_executor(
            self.executor, 
            lambda: self.model.encode(payload).tolist()
        )
        return vector

    async def is_known_false_positive(self, payload: str, severity: str) -> bool:
        """
        Asynchronously searches for matches using a risk-weighted threshold.
        """
        try:
            # Determine threshold based on alert severity
            current_threshold = self.threshold_map.get(severity, 0.95)
            
            vector = await self._generate_embedding(payload)
            
            # Server-Side Metadata Filtering
            results = await self.index.query(
                vector=vector,
                top_k=1,
                include_metadata=False,
                filter={
                    "resolution": {"$eq": "false_positive"}
                }
            )
            
            if results.matches:
                score = results.matches[0].score
                if score > current_threshold:
                    logger.info(f"DYNAMIC MATCH: Score {score:.4f} > {current_threshold} for {severity} alert.")
                    return True
                else:
                    logger.info(f"SIMILARITY REJECTED: Score {score:.4f} below {current_threshold} for {severity}.")
                    
            return False
        except Exception as e:
            logger.error(f"Vector search failed: {str(e)}")
            return False 

    async def memorize_safe_behavior(self, alert_id: str, payload: str) -> bool:
        """Stores a known false positive with metadata."""
        try:
            vector = await self._generate_embedding(payload)
            await self.index.upsert(
                vectors=[{
                    "id": alert_id,
                    "values": vector,
                    "metadata": {"resolution": "false_positive"}
                }]
            )
            logger.info(f"SUCCESS: Memorized alert {alert_id} as false positive.")
            return True
        except Exception as e:
            logger.error(f"Failed to memorize payload for {alert_id}: {str(e)}")
            raise

vector_service = VectorFilterService()