import hmac
import hashlib
import base64
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class SovereignIntegrityService:
    """
    AXON ARCH | Mission A: Guarding the Integrity of Intelligence.
    Executes local HMAC-SHA256 verification for Render deployment.
    """
    def __init__(self):
        try:
            # Load the symmetric key into local memory
            self.secret_key = settings.HMAC_SECRET_KEY.encode('utf-8')
            logger.info("Sovereign Integrity Service initialized. Local HMAC mode active.")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to load HMAC_SECRET_KEY: {str(e)}")
            raise

    def verify_siem_payload(self, raw_payload: str, provided_signature_b64: str) -> bool:
        """
        Computes local HMAC and securely compares it against the SIEM's signature.
        """
        if not provided_signature_b64:
            logger.error("Integrity Failure: Missing HMAC signature.")
            return False

        try:
            # 1. Compute the expected HMAC using our secret key and the raw payload
            payload_bytes = raw_payload.encode('utf-8')
            expected_hmac = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).digest()
            expected_signature_b64 = base64.b64encode(expected_hmac).decode('utf-8')

            # 2. Secure comparison to prevent timing side-channel attacks
            is_valid = hmac.compare_digest(expected_signature_b64, provided_signature_b64)
            
            if not is_valid:
                logger.warning("CRITICAL: HMAC verification failed. Payload Poisoned.")
                
            return is_valid

        except Exception as e:
            logger.error(f"Integrity check failed: {str(e)}")
            return False

integrity_service = SovereignIntegrityService()