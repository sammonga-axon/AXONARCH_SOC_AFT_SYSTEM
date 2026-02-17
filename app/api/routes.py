from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
from app.models.schemas import SOCAlert
from app.services.sentinel import SovereignSentinel
from app.services.vector_engine import VectorFilterService
from app.services.llm_analyzer import LLMAnalysisService
from app.services.integrity import integrity_service
from app.api.dependencies import get_sentinel, get_vector_service
from app.core.logger import logger

router = APIRouter(tags=["SOC Triage Engine"])

# Initialize the LLM Analyst (Stage 3)
llm_service = LLMAnalysisService()

@router.post(
    "/alerts/ingest", 
    status_code=status.HTTP_200_OK,
    summary="Ingest & Triage SIEM Alert",
    description="Enterprise pipeline: Stage 0 KMS HMAC, Stage 1.5 DPI Sentinel, Stage 2 Pinecone Vector Brain, Stage 3 Gemini 2.5 Flash."
)
async def ingest_alert(
    alert: SOCAlert, 
    sentinel: SovereignSentinel = Depends(get_sentinel),
    vector_db: VectorFilterService = Depends(get_vector_service)
) -> Dict[str, Any]:
    logger.info(f"Ingesting alert: {alert.alert_id}")

    # STAGE 0: Mission A - Cryptographic Provenance Gate
    if not integrity_service.verify_siem_payload(alert.raw_payload, alert.hmac_signature):
        logger.warning(f"INTEGRITY COMPROMISED: {alert.alert_id}. Merkle proof failed.")
        
        # Mandate: Intent Invalidation triggers immediate signal to LLM
        alert.threat_indicators.append("CRYPTOGRAPHIC_PROVENANCE_FAILURE: ADVERSARIAL POISONING INTENT")
        alert.severity = "Critical"
        
        logger.info("SIGNALING LLM: Analyzing poisoned payload intent.")
        llm_decision = await llm_service.analyze_alert(alert)
        
        return {
            "alert_id": alert.alert_id,
            "action": "CRITICAL_ESCALATION",
            "reason": f"HMAC Invalid. Poisoning Detected. LLM Verdict: {getattr(llm_decision, 'reasoning', 'Analysis failed.')}"
        }
    
    # STAGE 1.5: DPI Sentinel (Instant CPU-bound execution)
    if sentinel.scan_payload(alert.raw_payload):
        logger.warning(f"CRITICAL: Attack detected in payload for {alert.alert_id}")
        return {"alert_id": alert.alert_id, "action": "CRITICAL_ESCALATION", "reason": "DPI Sentinel detected malicious payload"}

    # STAGE 2: Vector Search (AWAITED to yield the event loop during network I/O)
    try:
        if await vector_db.is_known_false_positive(alert.raw_payload, alert.severity):
            logger.info(f"SUPPRESSING: {alert.alert_id} matches known false positive.")
            return {
                "alert_id": alert.alert_id, 
                "action": "SUPPRESS", 
                "reason": "Matches >95% confidence with historical false positive in Vector DB"
            }
    except Exception as e:
        logger.error(f"Vector DB integration failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Vector Database Error")

    # STAGE 3: Gemini 2.5 Flash Analyst (AWAITED to yield the event loop)
    logger.info(f"ROUTING: {alert.alert_id} requires Gemini 2.5 Flash analysis.")
    llm_decision = await llm_service.analyze_alert(alert)
    
    return {
        "alert_id": alert.alert_id,
        "action": getattr(llm_decision, "recommended_action", "MANUAL_REVIEW"),
        "reason": getattr(llm_decision, "reasoning", "No analysis provided.")
    }

@router.post(
    "/alerts/learn",
    status_code=status.HTTP_201_CREATED,
    summary="Memorize False Positive",
    description="Forces the Vector Database to memorize this payload as a safe false positive for future suppression."
)
async def teach_vector_brain(
    alert: SOCAlert,
    vector_db: VectorFilterService = Depends(get_vector_service)
) -> Dict[str, str]:
    logger.info(f"Teaching Vector Brain safe behavior for alert: {alert.alert_id}")
    
    # Strictly enforce provenance before polluting our vector memory
    if not integrity_service.verify_siem_payload(alert.raw_payload, alert.hmac_signature):
        raise HTTPException(status_code=403, detail="Cannot memorize unverified payloads. HMAC invalid.")

    try:
        success = await vector_db.memorize_safe_behavior(alert.alert_id, alert.raw_payload)
        if success:
            return {"status": "success", "message": f"Vector Brain successfully memorized {alert.alert_id} as a False Positive."}
    except Exception as e:
        logger.error(f"Learning endpoint failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to write to Pinecone Database")