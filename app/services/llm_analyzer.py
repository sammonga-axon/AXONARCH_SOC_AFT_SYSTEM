import json
from google import genai
from google.genai import types
from app.models.schemas import SOCAlert, TriageDecision
from app.core.config import settings
from app.core.logger import logger

class LLMAnalysisService:
    """
    Enterprise Stage 3: Gemini 1.5 Pro SOC Analyst.
    Utilizes the modern google-genai SDK for asynchronous reasoning.
    """
    def __init__(self):
        try:
            # Modern SDK Initialization
            self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
            self.model_name = "gemini-2.5-flash"
            logger.info("Stage 3: Gemini 2.5 Flash (Modern SDK) initialized.")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to initialize Gemini LLM: {str(e)}")
            raise

    async def analyze_alert(self, alert: SOCAlert) -> TriageDecision:
        """
        Asynchronously evaluates a SOC alert and forces deterministic JSON.
        """
        prompt = self._build_prompt(alert)
        
        try:
            # Use the .aio attribute for strictly non-blocking execution
            response = await self.client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                )
            )
            
            result_dict = json.loads(response.text)
            decision = TriageDecision(**result_dict)
            
            logger.info(f"LLM Verdict for {alert.alert_id}: {decision.recommended_action} (Score: {decision.confidence_score})")
            return decision

        except Exception as e:
            logger.error(f"LLM inference failed for {alert.alert_id}: {str(e)}")
            return TriageDecision(
                confidence_score=100,
                recommended_action="ESCALATE",
                reasoning=f"System degradation. LLM failure: {str(e)}. Mandatory manual review.",
                latency_ms=0.0
            )

    def _build_prompt(self, alert: SOCAlert) -> str:
        return f"""
        You are an elite Lead Enterprise Incident Responder. 
        Evaluate the following normalized security alert.
        
        Alert ID: {alert.alert_id}
        Provider: {alert.provider}
        Event Class: {alert.event_class}
        Severity: {alert.severity}
        Target Asset: {alert.asset.hostname} (IP: {alert.asset.ip_address})
        Identity: {alert.identity.username}
        Threat Indicators: {', '.join(alert.threat_indicators)}
        Raw Payload: {alert.raw_payload}
        
        Analyze the attack vector and determine if this is a benign administrative action or a genuine threat.
        Calculate a confidence_score (0-100) where >90 demands immediate escalation.
        
        Respond strictly in valid JSON matching this exact structure:
        {{
            "confidence_score": <int>,
            "recommended_action": "<SUPPRESS | ESCALATE>",
            "reasoning": "<Concise, objective justification max 2 sentences>",
            "latency_ms": 0.0
        }}
        """