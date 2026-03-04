import json
import os
from openai import AsyncOpenAI
from app.models.schemas import SOCAlert, TriageDecision
from app.core.logger import logger

class LLMAnalysisService:
    """
    Enterprise Stage 3: Gemini 3.1 Flash Lite via OpenRouter.
    Utilizes the standard OpenAI Async SDK for vendor-agnostic execution.
    """
    def __init__(self):
        try:
            # Dynamically pull the key from Render Environment Variables
            self.api_key = os.getenv("OPENROUTER_API_KEY")
            if not self.api_key:
                logger.warning("OPENROUTER_API_KEY is missing. LLM will fail.")

            # OpenRouter uses the standard OpenAI client architecture
            self.client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key,
            )
            self.model_name = "google/gemini-3.1-flash-lite-preview"
            logger.info(f"Stage 3: {self.model_name} (OpenRouter SDK) initialized.")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to initialize OpenRouter client: {str(e)}")
            raise

    async def analyze_alert(self, alert: SOCAlert) -> TriageDecision:
        """
        Asynchronously evaluates a SOC alert and forces deterministic JSON via OpenRouter.
        """
        prompt = self._build_prompt(alert)
        
        try:
            # Use the Async client for strictly non-blocking execution
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a deterministic security analysis agent. Output ONLY JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            
            result_dict = json.loads(response.choices[0].message.content)
            decision = TriageDecision(**result_dict)
            
            logger.info(f"LLM Verdict for {alert.alert_id}: {decision.recommended_action} (Score: {decision.confidence_score})")
            return decision

        except Exception as e:
            logger.error(f"LLM inference failed for {alert.alert_id}: {str(e)}")
            return TriageDecision(
                confidence_score=100,
                recommended_action="ESCALATE",
                reasoning=f"System degradation. OpenRouter failure: {str(e)}. Mandatory manual review.",
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