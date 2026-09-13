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
    "neural": {
        "name": "🧠 Internal Neural Network (Local & Offline - Zero-Knowledge)",
        "default_endpoint": "local://neural-net",
        "default_model": "StarVault-MLP-v2.4",
        "models": ["StarVault-MLP-v2.4"],
        "requires_key": False,
    },
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
        provider: str = "neural",
        api_key: str = "",
        model: str = "",
        endpoint: str = "",
    ) -> None:
        self.provider = provider if provider in AI_PROVIDERS else "neural"
        meta = AI_PROVIDERS[self.provider]
        self.api_key = api_key.strip()
        self.model = model.strip() or meta["default_model"]
        self.endpoint = endpoint.strip() or meta["default_endpoint"]

    @property
    def current_provider(self) -> str:
        return self.provider

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

    def analyze_neural(self, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Executes full internal neural network audit (100% offline, zero-knowledge)."""
        from starvault.neural_health import audit_vault_neural
        neural_audit = audit_vault_neural(entries)
        findings: List[str] = []
        actions: List[AIRemediationAction] = []

        findings.append(f"🧠 Neural Safety Index: {neural_audit.safety_index}/100 (Grade {neural_audit.letter_grade})")
        findings.append(f"⚡ Analyzed {neural_audit.total_entries_evaluated} entries in {neural_audit.execution_time_ms}ms with 100% offline zero-knowledge inference.")
        if neural_audit.anomalies_flagged_count > 0:
            findings.append(f"⚠️ Flagged {neural_audit.anomalies_flagged_count} security anomalies requiring attention.")

        for vuln in neural_audit.top_vulnerabilities:
            for rec in vuln.get("recommendations", []):
                findings.append(f"[{vuln['title']}] {rec}")

        for assessment in neural_audit.entry_assessments:
            if assessment.auto_fix_action:
                actions.append(AIRemediationAction(
                    action_type=assessment.auto_fix_action,
                    entry_id=assessment.entry_id,
                    entry_title=assessment.entry_title,
                    reason=assessment.recommendations[0] if assessment.recommendations else f"Neural Risk: {assessment.risk_score}% ({assessment.predicted_class})",
                    suggested_value="Auto-generated high entropy credential" if assessment.auto_fix_action == "generate_password" else None,
                ))
            if assessment.anomalies:
                for anom in assessment.anomalies:
                    if "Unorganized" in anom:
                        actions.append(AIRemediationAction(
                            action_type="assign_groups",
                            entry_id=assessment.entry_id,
                            entry_title=assessment.entry_title,
                            reason="Neural engine detected missing group assignments",
                            suggested_value=", ".join(assessment.recommended_groups),
                        ))

        summary = (
            f"StarVault Neural Network Audit: Safety Index {neural_audit.safety_index}/100 "
            f"(Grade {neural_audit.letter_grade}). Evaluated {len(entries)} items offline. "
            f"{neural_audit.high_risk_entries_count} high-risk entries identified."
        )

        return AIAnalysisResult(
            summary=summary,
            findings=findings,
            actions=actions,
            raw_response=f"StarVault Neural Engine v2.4 (Local MLP • {neural_audit.execution_time_ms}ms)",
        )

    def analyze_vault(self, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Sends sanitized metadata to AI provider and parses structured recommendations."""
        if not entries:
            return AIAnalysisResult(
                summary="The vault is empty. No items to analyze.",
                findings=[],
                actions=[],
            )

        # Route to internal neural network directly when selected (Default)
        if self.provider == "neural":
            return self.analyze_neural(entries)

        metadata = self.build_sanitized_metadata(entries)

        system_prompt = (
            "You are StarVault AI Security & Vault Organization Advisor. You analyze non-sensitive credential vault metadata "
            "encompassing credentials, API tokens, self-signed certificates, SSH keys, GPG keys, and WireGuard/Age keypairs. "
            "Detect expiring certificates/keys (<30 days), duplicate services, stale credentials (>90 days), "
            "un-categorized/un-tagged entries, unnormalized titles, and redundant duplicate records. "
            "Suggest optimal categories (e.g. 'Cloud & Infrastructure', 'Dev & Repositories', 'Databases & Storage', 'AI & LLM Services', 'Finance & Payments', 'Security & Networking', 'Keys & Certificates'). "
            "You NEVER have access to secrets. Respond ONLY with a valid JSON object matching this exact schema:\n"
            "{\n"
            '  "summary": "Brief 1-2 sentence overall health & organization summary",\n'
            '  "findings": ["finding 1", "finding 2"],\n'
            '  "actions": [\n'
            '    {"action_type": "merge_duplicate|flag_stale|update_tags|set_category|normalize_title|renew_cert|rotate_key", "entry_id": "...", "entry_title": "...", "reason": "...", "suggested_value": "..."}\n'
            "  ]\n"
            "}"
        )

        user_prompt = (
            f"Please analyze these {len(metadata)} vault entries and provide actionable hygiene and auto-organization improvements:\n"
            f"{json.dumps(metadata, indent=2)}"
        )

        try:
            response_text = self._call_llm(system_prompt, user_prompt)
            return self._parse_response(response_text, entries)
        except Exception:
            # Fallback to local neural network and heuristic security and organization analysis
            return self.analyze_neural(entries)

    def analyze_local_heuristics(self, entries: List[VaultEntry]) -> AIAnalysisResult:
        """Fast offline heuristic analysis for immediate security and organization recommendations."""
        from starvault.organizer import find_duplicates, find_ghost_and_stale, infer_category, infer_groups, infer_services, infer_tags, normalize_title

        now = datetime.now(timezone.utc)
        findings: List[str] = []
        actions: List[AIRemediationAction] = []

        # 1. Deduplication Detection
        dup_groups = find_duplicates(entries)
        for g in dup_groups:
            findings.append(f"Duplicate cluster detected: '{g.primary_title}' ({g.match_reason})")
            for dup_id, dup_title in zip(g.duplicate_ids, g.duplicate_titles):
                actions.append(AIRemediationAction(
                    action_type="merge_duplicate",
                    entry_id=dup_id,
                    entry_title=dup_title,
                    reason=f"Merge into '{g.primary_title}' ({g.match_reason})",
                    suggested_value=g.primary_id,
                ))

        # 2. Ghost and Orphan Detection
        ghost_data = find_ghost_and_stale(entries)
        for gh in ghost_data["ghosts"]:
            actions.append(AIRemediationAction(
                action_type="purge_ghost",
                entry_id=gh.id,
                entry_title=gh.title or "Untitled Ghost",
                reason="Empty ghost record with no secrets or destination",
            ))

        for e in entries:
            # 3. Multi-Group Suggestions
            inferred_grps = infer_groups(e)
            current_grps = set(getattr(e, "groups", []))
            if set(inferred_grps) - current_grps:
                actions.append(AIRemediationAction(
                    action_type="assign_groups",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason=f"Assign groups: {', '.join(inferred_grps)}",
                    suggested_value=", ".join(inferred_grps),
                ))

            # 3b. Multi-Service Suggestions
            inferred_srvs = infer_services(e)
            current_srvs = set(getattr(e, "services", []))
            if set(inferred_srvs) - current_srvs:
                actions.append(AIRemediationAction(
                    action_type="assign_services",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason=f"Assign services: {', '.join(inferred_srvs)}",
                    suggested_value=", ".join(inferred_srvs),
                ))

            # 4. Tagging Suggestions
            missing_tags = [t for t in infer_tags(e) if t not in e.tags]
            if missing_tags:
                actions.append(AIRemediationAction(
                    action_type="update_tags",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason=f"Add inferred tags: {', '.join(missing_tags[:3])}",
                    suggested_value=", ".join(missing_tags),
                ))

            # 5. Title Normalization Suggestions
            norm = normalize_title(e)
            if norm != e.title:
                actions.append(AIRemediationAction(
                    action_type="normalize_title",
                    entry_id=e.id,
                    entry_title=e.title,
                    reason="Standardize title formatting and acronyms",
                    suggested_value=norm,
                ))

            # 6. Expiring certificates or keys
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

        summary = f"Audit analyzed {len(entries)} items: identified {len(actions)} security, grouping, and organizational recommendations."
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
