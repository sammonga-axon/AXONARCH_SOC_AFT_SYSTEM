from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# 1. Local application imports (Pydantic handles the .env implicitly)
from app.api.routes import router
from app.core.config import settings
from app.core.logger import logger
from app.api.dependencies import get_sentinel, get_vector_service

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Enterprise Boot Sequence.
    Pre-allocates continuous memory for ML models to eliminate Cold Start latency.
    """
    logger.info(f"BOOT SEQUENCE INITIATED: {settings.PROJECT_NAME} v{settings.VERSION}")
    
    # Force heavy dependencies into RAM
    logger.info("Pre-loading Vector Engine and Sovereign Sentinel...")
    get_sentinel()
    get_vector_service()
    
    logger.info("SYSTEM ONLINE: ASGI event loop accepting traffic.")
    yield 
    
    logger.info("SHUTDOWN SEQUENCE: Draining active connections.")

app = FastAPI(
    title=settings.PROJECT_NAME, 
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=None 
)

# 2. Enterprise CORS Policy (Required for Frontend Dashboard integration)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Tighten this to strictly your dashboard IP in production
    allow_credentials=True,
    allow_methods=["GET", "POST"], 
    allow_headers=["*"],
)

# 3. Dynamic Versioning Routing
app.include_router(router, prefix=settings.API_V1_STR)

# 4. Kubernetes / Load Balancer Probe
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "operational", 
        "environment": "production" if "production" in settings.PINECONE_ENVIRONMENT.lower() else "development",
        "version": settings.VERSION
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)