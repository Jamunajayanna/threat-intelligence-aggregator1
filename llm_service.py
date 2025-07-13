"""
LLM Service for Threat Intelligence Summarization
Supports multiple backends: Ollama, OpenAI, and enhanced fallback
"""

import logging
import os
import requests

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self):
        self.ollama_url = "http://localhost:11434"
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.available_backends = []
        self._check_available_backends()
    
    def _check_available_backends(self):
        """Check which LLM backends are available"""
        self.available_backends.clear()  # Clear previous values

        # Check Ollama
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
            if response.status_code == 200:
                self.available_backends.append("ollama")
                logger.info("Ollama backend is available")
        except Exception:
            logger.debug("Ollama backend is not available")
        
        # Check OpenAI
        if self.openai_api_key:
            self.available_backends.append("openai")
            logger.info("OpenAI backend is available")
        
        logger.info(f"Available LLM backends: {self.available_backends}")
    
    def summarize_threat(self, text: str, max_length: int = 150) -> str:
        """
        Summarize threat intelligence text using available LLM backends
        Falls back to enhanced rule-based summarization if no LLM is available
        """
        if not text:
            return "No threat information available"
        
        for backend in self.available_backends:
            try:
                if backend == "ollama":
                    return self._summarize_with_ollama(text, max_length)
                elif backend == "openai":
                    return self._summarize_with_openai(text, max_length)
            except Exception as e:
                logger.warning(f"Failed to use {backend} backend: {e}")
                continue
        
        return self._enhanced_rule_based_summary(text, max_length)
    
    def _summarize_with_ollama(self, text: str, max_length: int) -> str:
        """Summarize using Ollama"""
        prompt = f"""Analyze this security threat and provide a concise summary in {max_length} characters or less:

{text}

Focus on:
- Threat type and severity
- Key indicators of compromise (IOCs)
- Potential impact
- Brief technical details

Summary:"""
        
        payload = {
            "model": "phi3",  # ✅ Use installed model
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "max_tokens": max_length // 4
            }
        }

        response = requests.post(
            f"{self.ollama_url}/api/generate",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            summary = result.get("response", "").strip()
            return summary[:max_length] if summary else self._enhanced_rule_based_summary(text, max_length)
        else:
            raise Exception(f"Ollama API error: {response.status_code}")
    
    def _summarize_with_openai(self, text: str, max_length: int) -> str:
        """Summarize using OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "gpt-3.5-turbo",  # ✅ Correct OpenAI model
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Provide concise, technical summaries of security threats."
                },
                {
                    "role": "user",
                    "content": f"Analyze this security threat and provide a summary in {max_length} characters or less:\n\n{text}"
                }
            ],
            "max_tokens": max_length // 4,
            "temperature": 0.3
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            summary = result["choices"][0]["message"]["content"].strip()
            return summary[:max_length] if summary else self._enhanced_rule_based_summary(text, max_length)
        else:
            raise Exception(f"OpenAI API error: {response.status_code}")
    
    def _enhanced_rule_based_summary(self, text: str, max_length: int) -> str:
        """Enhanced rule-based summarization when no LLM is available"""
        if not text:
            return "No threat information available"
        
        text_lower = text.lower()
        summary_parts = []

        # Detect threat types
        threat_types = []
        if any(k in text_lower for k in ['malware', 'trojan', 'virus', 'backdoor', 'payload']):
            threat_types.append('Malware')
        if any(k in text_lower for k in ['botnet', 'c2', 'c&c', 'command', 'control']):
            threat_types.append('C2/Botnet')
        if any(k in text_lower for k in ['phishing', 'scam', 'fake', 'credential']):
            threat_types.append('Phishing')
        if any(k in text_lower for k in ['ransomware', 'crypto', 'encrypt', 'ransom']):
            threat_types.append('Ransomware')

        malware_families = []
        known_families = {
            'stealc': 'Stealc', 'emotet': 'Emotet', 'trickbot': 'TrickBot',
            'dridex': 'Dridex', 'qakbot': 'QakBot', 'cobalt strike': 'Cobalt Strike',
            'redline': 'RedLine', 'vidar': 'Vidar', 'amadey': 'Amadey', 'raccoon': 'Raccoon'
        }

        for key, name in known_families.items():
            if key in text_lower:
                malware_families.append(name)

        if threat_types:
            summary_parts.append(f"🚨 {', '.join(threat_types[:2])}")
        if malware_families:
            summary_parts.append(f"👾 {', '.join(malware_families[:2])}")

        url_count = len([w for w in text.split() if w.startswith("http")])
        ip_count = len([w for w in text.split() if '.' in w and any(c.isdigit() for c in w)])
        iocs = []
        if url_count:
            iocs.append(f"{url_count} URLs")
        if ip_count:
            iocs.append(f"{ip_count} IPs")
        if iocs:
            summary_parts.append(f"🔍 IOCs: {', '.join(iocs)}")

        if not summary_parts:
            summary_parts.append("🔍 Security threat detected")

        final_summary = ' | '.join(summary_parts)
        return final_summary if len(final_summary) <= max_length else final_summary[:max_length - 3] + "..."

# Global LLM service instance
llm_service = LLMService()
