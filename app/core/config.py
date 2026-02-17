from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    # Core Application Settings
    PROJECT_NAME: str = "AXON SOC Triage Engine"
    VERSION: str = "1.0.0" 
    API_V1_STR: str = "/api/v1"
    
    # Cloud API Keys
    PINECONE_API_KEY: str
    PINECONE_INDEX_NAME: str
    
    # Making OpenAI optional, and requiring Gemini 1.5 Pro
    OPENAI_API_KEY: str | None = None 
    GEMINI_API_KEY: str
    
    # Mission A: Local HMAC Secret for Render Deployment
    HMAC_SECRET_KEY: str = "super_secret_local_dev_key_override_in_render"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore" 
    )

@lru_cache
def get_settings() -> Settings:
    """
    Caches the state. Reading from disk is an I/O bound operation.
    @lru_cache ensures this file is evaluated strictly once at boot (O(1)).
    """
    return Settings()

# --- THE MISSING INSTANTIATION ---
# This executes at T_boot and holds the configuration in continuous RAM.
settings = get_settings()