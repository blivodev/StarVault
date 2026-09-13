"""AI/LLM Vault Security & Hygiene Advisor for StarVault.

Supports multi-provider LLM integrations:
- OpenAI, Anthropic, Google Gemini, OpenRouter, DeepInfra, Fireworks AI, Ollama (local), and Custom endpoints.

Zero-Knowledge Architectural Guarantee:
Plaintext passwords, private keys, and raw tokens are NEVER passed to the AI!
Only sanitized metadata (titles, categories, tags, timestamps, entropy levels, expiry dates)
is analyzed to identify duplicates, stale credentials, and organizational improvements.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from starvault.models import VaultEntry


AI_PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "default_endpoint": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "o3-mini"],
        "requires_key": True,
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "default_endpoint": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-3-5-haiku-20241022",
        "models": ["claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"],
        "requires_key": True,
    },
    "gemini": {
        "name": "Google Gemini",
        "default_endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "default_model": "gemini-1.5-flash",
        "models": ["gemini-1.5-flash", "gemini-1.5-pro"],
        "requires_key": True,
    },
    "openrouter": {
        "name": "OpenRouter",
        "default_endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "default_model": "meta-llama/llama-3.1-8b-instruct",
        "models": ["meta-llama/llama-3.1-8b-instruct", "google/gemini-flash-1.5", "anthropic/claude-3.5-haiku"],
        "requires_key": True,
    },
    "deepinfra": {
        "name": "DeepInfra",
        "default_endpoint": "https://api.deepinfra.com/v1/openai/chat/completions",
        "default_model": "meta-llama/Meta-Llama-3-8B-Instruct",
        "models": ["meta-llama/Meta-Llama-3-8B-Instruct", "mistralai/Mistral-7B-Instruct-v0.3"],
        "requires_key": True,
    },
    "fireworks": {
        "name": "Fireworks AI",
        "default_endpoint": "https://api.fireworks.ai/inference/v1/chat/completions",
        "default_model": "accounts/fireworks/models/llama-v3p1-8b-instruct",
        "models": ["accounts/fireworks/models/llama-v3p1-8b-instruct", "accounts/fireworks/models/mixtral-8x7b-instruct"],
        "requires_key": True,
    },
    "ollama": {
        "name": "Ollama (Local)",
        "default_endpoint": "http://localhost:11434/v1/chat/completions",
        "default_model": "llama3",
        "models": ["llama3", "mistral", "qwen2.5", "llama3.2"],
        "requires_key": False,
    },
    "custom": {
        "name": "Custom OpenAI Compatible",
        "default_endpoint": "http://localhost:8000/v1/chat/completions",
        "default_model": "default",
        "models": ["default"],
        "requires_key": False,
    },
}


@dataclass
class AIRemediationAction:
    """Represents a discrete action recommended by AI."""
    action_type: str  # 'merge_duplicate', 'update_tags', 'flag_stale', 'set_category'
    entry_id: str
    entry_title: str
    reason: str
    suggested_value: Optional[str] = None


@dataclass
class AIAnalysisResult:
    """Result of AI vault audit."""
    summary: str
    findings: List[str]
    actions: List[AIRemediationAction]
    suggested_tags_map: Dict[str, List[str]] = field(default_factory=dict)
    raw_response: str = ""


class AIAdvisor:
    """Zero-Knowledge AI Security & Hygiene Advisor for StarVault."""

    def __init__(
        self,
        provider: str = "ollama",
        api_key: str = "",
        model: str = "",
        endpoint: str = "",
    ) -> None:
        self.provider = provider if provider in AI_PROVIDERS else "ollama"
        meta = AI_PROVIDERS[self.provider]
        self.api_key = api_key.strip()
        self.model = model.strip() or meta["default_model"]
        self.endpoint = endpoint.strip() or meta["default_endpoint"]

    def build_sanitized_metadata(self, entries: List[VaultEntry]) -> List[Dict[str, Any]]:
        """Extracts strictly non-sensitive structural metadata for AI analysis."""
        now = datetime.now(timezone.utc)
        sanitized = []
        for e in entries:
            # Calculate password / update age
            pwd_age_days = None
            if e.updated_at:
                try:
                    upd = datetime.fromisoformat(e.updated_at.replace("Z", "+00:00"))
                    pwd_age_days = (now - upd).days
                except Exception:
                    pass

            days_until_expiry = None
            if e.expires_at:
                try:
                    exp = datetime.fromisoformat(e.expires_at.replace("Z", "+00:00"))
                    days_until_expiry = (exp - now).days
                except Exception:
                    pass

            item = {
                "id": e.id,
                "title": e.title,
                "entry_type": e.entry_type,
                "key_type": getattr(e, "key_type", None),
                "category": e.category,
                "tags": e.tags,
                "has_password": bool(e.password),
                "has_token": bool(e.api_token),
                "has_public_key": bool(e.public_key),
                "has_private_key": bool(e.password if e.entry_type == "keypair" else False),
                "password_age_days": pwd_age_days,
                "days_until_expiry": days_until_expiry,
                "provider": e.provider or e.app_name or "",
                "environment": e.environment,
                "expires_at": e.expires_at,
                "custom_field_keys": [cf.get("key", "") for cf in e.custom_fields],
            }
            sanitized.append(item)
        return sanitized

    def analyze_vault(self, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Sends sanitized metadata to AI provider and parses structured recommendations."""
        if not entries:
            return AIAnalysisResult(
                summary="The vault is empty. No items to analyze.",
                findings=[],
                actions=[],
            )

        metadata = self.build_sanitized_metadata(entries)

        system_prompt = (
            "You are StarVault AI Security Advisor. You analyze non-sensitive credential vault metadata "
            "encompassing credentials, API tokens, self-signed certificates, SSH keys, GPG keys, and WireGuard/Age keypairs. "
            "Detect expiring certificates/keys (<30 days), duplicate services, stale credentials (>90 days), "
            "un-tagged cryptographic keys, and missing environment tags. "
            "You NEVER have access to secrets. Respond ONLY with a valid JSON object matching this exact schema:\n"
            "{\n"
            '  "summary": "Brief 1-2 sentence overall health summary",\n'
            '  "findings": ["finding 1", "finding 2"],\n'
            '  "actions": [\n'
            '    {"action_type": "merge_duplicate|flag_stale|update_tags|set_category|renew_cert|rotate_key", "entry_id": "...", "entry_title": "...", "reason": "...", "suggested_value": "..."}\n'
            "  ]\n"
            "}"
        )

        user_prompt = (
            f"Please analyze these {len(metadata)} vault entries and provide actionable hygiene improvements:\n"
            f"{json.dumps(metadata, indent=2)}"
        )

        try:
            response_text = self._call_llm(system_prompt, user_prompt)
            return self._parse_response(response_text, entries)
        except Exception:
            # Fallback to local heuristic security analysis
            return self.analyze_local_heuristics(entries)

    def analyze_local_heuristics(self, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Fast offline heuristic analysis for immediate security recommendations."""
        now = datetime.now(timezone.utc)
        findings: List[str] = []
        actions: List[AIRemediationAction] = []

        seen_titles = {}
        for e in entries:
            # Check duplicate titles
            tl = e.title.lower().strip()
            if tl in seen_titles:
                findings.append(f"Duplicate entry label detected: '{e.title}'")
                actions.append(AIRemediationAction(
                    action_type="merge_duplicate",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason=f"Duplicate title matching existing entry '{seen_titles[tl]}'",
                ))
            else:
                seen_titles[tl] = e.title

            # Check expiring certificates or keys
            if e.expires_at:
                try:
                    exp = datetime.fromisoformat(e.expires_at.replace("Z", "+00:00"))
                    days_left = (exp - now).days
                    if days_left < 0:
                        findings.append(f"Expired asset: '{e.title}' expired {abs(days_left)} days ago.")
                        actions.append(AIRemediationAction(
                            action_type="renew_cert",
                            entry_id=e.id,
                            entry_title=e.title,
                            reason=f"Asset has expired ({e.expires_at})",
                        ))
                    elif days_left <= 30:
                        findings.append(f"Asset expiring soon: '{e.title}' expires in {days_left} days.")
                        actions.append(AIRemediationAction(
                            action_type="renew_cert",
                            entry_id=e.id,
                            entry_title=e.title,
                            reason=f"Asset expires in {days_left} days",
                        ))
                except Exception:
                    pass

            # Check untagged keys
            if e.entry_type == "keypair" and not e.tags:
                actions.append(AIRemediationAction(
                    action_type="update_tags",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason="Cryptographic keypair has no relational tags assigned",
                    suggested_value="keys, infra",
                ))

        summary = f"Audit analyzed {len(entries)} items: identified {len(actions)} security and organizational recommendations."
        return AIAnalysisResult(
            summary=summary,
            findings=findings,
            actions=actions,
        )

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Executes HTTP request to the configured AI provider."""
        if self.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        else:
            return self._call_openai_compatible(system_prompt, user_prompt)

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as ex:
            err_body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"AI Provider HTTP {ex.code}: {err_body}")
        except Exception as ex:
            raise RuntimeError(f"AI Request failed: {str(ex)}")

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": 1500,
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                content = result.get("content", [])
                if content and isinstance(content, list):
                    return content[0].get("text", "")
                return ""
        except urllib.error.HTTPError as ex:
            err_body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Anthropic API Error {ex.code}: {err_body}")
        except Exception as ex:
            raise RuntimeError(f"Anthropic Request failed: {str(ex)}")

    def _parse_response(self, text: str, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Parses LLM output into structured AIAnalysisResult."""
        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

        try:
            data = json.loads(cleaned)
        except Exception:
            # Fallback if json parsing fails
            return AIAnalysisResult(
                summary="AI analysis completed with non-standard formatting.",
                findings=[text[:300]],
                actions=[],
                raw_response=text,
            )

        actions = []
        id_title_map = {e.id: e.title for e in entries}
        for act in data.get("actions", []):
            eid = act.get("entry_id", "")
            title = act.get("entry_title", id_title_map.get(eid, "Unknown"))
            actions.append(
                AIRemediationAction(
                    action_type=act.get("action_type", "flag_stale"),
                    entry_id=eid,
                    entry_title=title,
                    reason=act.get("reason", "Suggested by AI"),
                    suggested_value=act.get("suggested_value"),
                )
            )

        return AIAnalysisResult(
            summary=data.get("summary", "AI Analysis Complete"),
            findings=data.get("findings", []),
            actions=actions,
            raw_response=text,
        )
