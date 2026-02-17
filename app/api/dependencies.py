from app.services.sentinel import SovereignSentinel
from app.services.vector_engine import VectorFilterService

# Global singletons
_sentinel_instance = None
_vector_service_instance = None

def get_sentinel() -> SovereignSentinel:
    global _sentinel_instance
    if not _sentinel_instance:
        _sentinel_instance = SovereignSentinel()
    return _sentinel_instance

def get_vector_service() -> VectorFilterService:
    global _vector_service_instance
    if not _vector_service_instance:
        _vector_service_instance = VectorFilterService()
    return _vector_service_instance