from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone

class AssetData(BaseModel):
    hostname: Optional[str] = Field(None, description="The hostname of the affected asset.", examples=["fin-db-production-01"])
    ip_address: Optional[str] = Field(None, description="The IPv4 or IPv6 address.", examples=["10.0.4.55"])

class IdentityData(BaseModel):
    username: Optional[str] = Field(None, description="The username or service account involved.", examples=["svc_axon_admin"])

class SOCAlert(BaseModel):
    alert_id: str = Field(..., description="Unique identifier for the alert from the SIEM.")
    provider: str = Field(..., description="The source system (e.g., CrowdStrike, Splunk).")
    event_class: str = Field(..., description="OCSF Event Class (e.g., ProcessActivity).")
    severity: str = Field(..., description="Alert severity level (Info, Low, Medium, High, Critical).")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Time the alert was ingested into Axon.")
    asset: AssetData
    identity: IdentityData
    threat_indicators: List[str] = Field(..., description="List of specific malicious indicators.")
    raw_payload: str = Field(..., description="The unparsed raw log data for DPI inspection.")
    
    # Mission A: Cryptographic Provenance (Required for KMS Production)
    hmac_signature: Optional[str] = Field(None, description="Base64 encoded AWS KMS HMAC for payload provenance.")

    # This configuration automatically builds a professional testing payload in your /docs UI
    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_id": "cs-alert-9942a-2026",
                "provider": "CrowdStrike",
                "event_class": "ProcessActivity",
                "severity": "Critical",
                "asset": {
                    "hostname": "fin-db-production-01",
                    "ip_address": "10.0.4.55"
                },
                "identity": {
                    "username": "svc_axon_admin"
                },
                "threat_indicators": [
                    "Suspicious python child process spawned",
                    "Bypassed execution policy"
                ],
                "raw_payload": "Event Triggered: User executed script containing __import__('o'+'s').system('rm -rf /vault')",
                "hmac_signature": "aGVsbG8gd29ybGQgaG1hYyBieXBhc3M=" 
            }
        }
    }

# --- OUTPUT SCHEMA ---
class TriageDecision(BaseModel):
    confidence_score: int = Field(..., ge=0, le=100, description="0-100 threat validity calculated by Stage 3 Analyst.")
    recommended_action: str = Field(..., description="SUPPRESS or ESCALATE")
    reasoning: str = Field(..., description="Machine-generated justification for the action.")
    latency_ms: float = Field(..., description="Total execution overhead in milliseconds.")