import re
import hashlib
from typing import Optional
from app.core.logger import logger

class SovereignSentinel:
    """
    AXON ARCH | SATE ENGINE
    Stage 1.5: Deterministic Integrity & Bounded Fast-Fail Inspection.
    """
    def __init__(self):
        # Mission A: Merkle Proof configuration
        self.enforce_cryptographic_integrity = True
        
        # O(1) Compiled Regex with strict boundary conditions to prevent ReDoS
        # We drop wildcard quantifiers (.*) to guarantee linear O(n) execution.
        self.threat_patterns = [
            re.compile(r"(?i)(?:__import__|__builtins__|__globals__|__subclasses__)"),
            re.compile(r"(?i)(?:eval|exec|compile)\s*\("),
            re.compile(r"(?i)(?:os\.system|subprocess\.|rm\s+-rf)"),
            re.compile(r"(?i)(?:ignore\s+previous\s+instructions|system\s+override)"),
            re.compile(r"(?i)(?:BEGIN\s+PRIVATE\s+KEY|sk-[a-zA-Z0-9]{20,})")
        ]
        
        self.max_payload_bytes = 50000 

    def verify_merkle_leaf(self, payload: str, provided_hash: str) -> bool:
        """
        Cryptographic validation. If the SIEM payload hash does not match 
        the provided Merkle leaf, the data has been poisoned in transit.
        """
        calculated_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        return calculated_hash == provided_hash

    def scan_payload(self, text: str, expected_hash: Optional[str] = None) -> bool:
        """
        Executes sub-millisecond intent invalidation. 
        Returns True if THREAT DETECTED, False if CLEAN.
        """
        # 1. HARD BOUNDARY: Block memory exhaustion attacks instantly
        if len(text) > self.max_payload_bytes:
            logger.warning(f"Sentinel Block: Payload exceeds {self.max_payload_bytes} bytes.")
            return True

        # 2. CRYPTOGRAPHIC INTEGRITY: The Merkle Check
        if self.enforce_cryptographic_integrity and expected_hash:
            if not self.verify_merkle_leaf(text, expected_hash):
                logger.error("Sentinel Block: MERKLE PROOF FAILED. Payload poisoned.")
                return True

        # 3. FAST-FAIL PATTERN MATCHING
        # We return instantly on the FIRST match. Accumulating a "risk_score" 
        # wastes CPU cycles. If it's malicious, kill it immediately.
        for pattern in self.threat_patterns:
            if pattern.search(text):
                logger.warning(f"Sentinel Block: DPI matched signature {pattern.pattern}")
                return True 
        
        return False