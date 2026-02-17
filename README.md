# AXON ARCH | SOC Alert Triage Engine (SATE)

## 1. Executive Summary
Security Operations Centers (SOCs) are bounded by human cognitive limits. A standard enterprise SIEM generates alerts at a rate $\lambda$ that mathematically exceeds the processing capacity $\mu$ of human analysts, resulting in queue collapse. The AxonArch SATE is a deterministic, tri-phasic ingestion engine designed to execute high-speed payload invalidation, semantic noise suppression, and agentic reasoning to reduce SIEM alert volume by up to 96% before human intervention is required.

## 2. The Tri-Phasic Architecture

### Stage 0: Cryptographic Provenance Gate (Mission A)
Enforces a Zero-Trust boundary against network-level Man-in-the-Middle (MitM) poisoning. 
* Validates incoming SIEM payloads via an $O(1)$ constant-time HMAC-SHA256 comparison.
* Intent Invalidation: Cryptographic failures do not simply drop packets; they are isolated and routed to the LLM to analyze the adversarial intent of the injection attack.

### Stage 1.5: Sovereign Sentinel (DPI)
Executes deterministic Deep Packet Inspection on the raw payload. Utilizes optimized regular expressions to instantly trap direct execution commands (e.g., Python `__import__` or shell injections), failing-closed with a `< 5ms` latency penalty to preserve downstream compute.

### Stage 2: Semantic Vector Brain (Noise Suppression)
Standard SIEM deduplication relies on rigid string matching. SATE maps alert payloads into a 384-dimensional continuous vector space using a local PyTorch model (`all-MiniLM-L6-v2`) accelerated via Apple Metal Performance Shaders (MPS).
* Utilizes Cosine Similarity coupled with **Dynamic Risk-Weighted Thresholding**.
* Critical alerts demand $\tau = 0.99$ identity for suppression, while Low alerts allow $\tau = 0.90$, mathematically optimizing the Precision-Recall boundary to eliminate alert fatigue without increasing the False Negative rate ($P_{fn}$).

### Stage 3: Agentic Synthesis (Gemini 2.5 Flash)
Novel alerts that bypass the Sentinel and the Vector Brain are routed to a stochastic reasoning engine. Operating strictly at `temperature=0.0` with forced JSON schema output, the Flash engine calculates threat validity and generates concise, deterministic reasoning for SOAR handoff.

## 3. SIEM Integration & SOAR Handoff
SATE deploys as an asynchronous middleware proxy. 
1. **Ingestion:** SIEM webhooks (Splunk, CrowdStrike) POST JSON payloads to `/api/v1/alerts/ingest`.
2. **Processing:** The ASGI event loop multiplexes network I/O, maintaining total overhead mandates.
3. **Response:** SATE returns a strict `TriageDecision` schema (`SUPPRESS` or `ESCALATE`).
4. **Action:** Downstream SOAR platforms ingest the JSON. `SUPPRESS` triggers automated ticket closure; `ESCALATE` routes the alert to a human responder augmented by the Stage 3 LLM reasoning context.