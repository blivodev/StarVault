"""Vault Health Advisor engine for StarVault.

Analyzes decrypted entries in-memory to detect security vulnerabilities,
reused credentials, stale passwords, expiring tokens, and accidental duplicates.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from rapidfuzz import fuzz

from starvault.models import VaultEntry


@dataclass
class HealthIssue:
    """Represents a discrete security finding or recommendation."""
    issue_type: str  # 'duplicate_password', 'duplicate_name', 'weak_password', 'stale_password', 'expiring_key'
    severity: str    # 'high', 'medium', 'low'
    title: str
    description: str
    entry_ids: List[str]
    entry_titles: List[str]
    recommendation: str


@dataclass
class VaultHealthReport:
    """Aggregated health score and findings report."""
    overall_score: int
    grade: str
    total_entries_analyzed: int
    issues: List[HealthIssue]
    duplicate_passwords_count: int = 0
    duplicate_names_count: int = 0
    weak_passwords_count: int = 0
    stale_passwords_count: int = 0
    expiring_keys_count: int = 0


def calculate_entropy(password: str) -> float:
    """Calculates password entropy in bits based on character pool size and length."""
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33
    if pool == 0:
        pool = 1
    return round(len(password) * math.log2(pool), 1)


def parse_date_safely(date_str: str) -> Optional[datetime]:
    """Attempts to parse varied date representations into a timezone-aware UTC datetime."""
    if not date_str or not isinstance(date_str, str):
        return None
    cleaned = date_str.strip()
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%d-%m-%Y",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(cleaned.split("Z")[0].split("+")[0], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        # Fallback to ISO parsing
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except Exception:
        return None


class VaultHealthAdvisor:
    """Intelligent scanner for evaluating security posture of vault entries."""

    EXPIRY_FIELD_KEYWORDS = {"expires", "expiry", "expiration", "valid_until", "expire_date", "valid_to"}

    def __init__(self, stale_days_threshold: int = 180) -> None:
        self.stale_days_threshold = stale_days_threshold

    def analyze(self, entries: List[VaultEntry]) -> VaultHealthReport:
        """Runs full health analysis across all decrypted vault entries in memory."""
        if not entries:
            return VaultHealthReport(
                overall_score=100,
                grade="A",
                total_entries_analyzed=0,
                issues=[],
            )

        now = datetime.now(timezone.utc)
        issues: List[HealthIssue] = []

        # 1. Duplicate Passwords Check
        password_map: Dict[str, List[VaultEntry]] = {}
        for e in entries:
            pwd = e.password.strip() if e.password else ""
            if pwd:
                password_map.setdefault(pwd, []).append(e)

        dup_pwd_count = 0
        for pwd, matched_entries in password_map.items():
            if len(matched_entries) > 1:
                dup_pwd_count += len(matched_entries)
                titles = [m.title for m in matched_entries]
                ids = [m.id for m in matched_entries]
                issues.append(
                    HealthIssue(
                        issue_type="duplicate_password",
                        severity="high",
                        title=f"Reused Password ({len(matched_entries)} entries)",
                        description=f"The exact same password is shared between {len(matched_entries)} services: {', '.join(titles)}.",
                        entry_ids=ids,
                        entry_titles=titles,
                        recommendation="Generate unique passwords for each service to prevent credential stuffing attacks.",
                    )
                )

        # 2. Accidental Duplicate Entry Names Check
        name_issues = self._check_duplicate_names(entries)
        dup_names_count = len(name_issues)
        issues.extend(name_issues)

        # 3. Weak Passwords Check
        weak_pwd_count = 0
        for e in entries:
            pwd = e.password.strip() if e.password else ""
            if pwd:
                entropy = calculate_entropy(pwd)
                if len(pwd) < 8 or entropy < 30.0:
                    weak_pwd_count += 1
                    issues.append(
                        HealthIssue(
                            issue_type="weak_password",
                            severity="high",
                            title=f"Very Weak Password: '{e.title}'",
                            description=f"Password is only {len(pwd)} characters with low entropy ({entropy} bits).",
                            entry_ids=[e.id],
                            entry_titles=[e.title],
                            recommendation="Replace with a generated passphrase or high-entropy key of at least 16 characters.",
                        )
                    )
                elif len(pwd) < 12 or entropy < 48.0:
                    weak_pwd_count += 1
                    issues.append(
                        HealthIssue(
                            issue_type="weak_password",
                            severity="medium",
                            title=f"Moderate/Weak Password: '{e.title}'",
                            description=f"Password length ({len(pwd)} chars, {entropy} bits) could be strengthened.",
                            entry_ids=[e.id],
                            entry_titles=[e.title],
                            recommendation="Use StarVault's Key Studio to generate a secure random password.",
                        )
                    )

        # 4. Stale Passwords Check (> 180 or > 365 days)
        stale_pwd_count = 0
        for e in entries:
            pwd = e.password.strip() if e.password else ""
            if pwd and e.updated_at:
                updated_dt = parse_date_safely(e.updated_at)
                if updated_dt:
                    age_days = (now - updated_dt).days
                    if age_days > 365:
                        stale_pwd_count += 1
                        issues.append(
                            HealthIssue(
                                issue_type="stale_password",
                                severity="medium",
                                title=f"Ancient Password: '{e.title}'",
                                description=f"Last modified {age_days} days ago (over a year old).",
                                entry_ids=[e.id],
                                entry_titles=[e.title],
                                recommendation="Review and rotate credentials on critical VPS and homelab instances annually.",
                            )
                        )
                    elif age_days > self.stale_days_threshold:
                        stale_pwd_count += 1
                        issues.append(
                            HealthIssue(
                                issue_type="stale_password",
                                severity="low",
                                title=f"Stale Password: '{e.title}'",
                                description=f"Password has not been updated in {age_days} days.",
                                entry_ids=[e.id],
                                entry_titles=[e.title],
                                recommendation="Consider rotating this password if associated with sensitive infrastructure.",
                            )
                        )

        # 5. Expiring or Expired Custom Fields / Keys
        expiring_keys_count = 0
        for e in entries:
            for field_dict in e.custom_fields:
                field_key = field_dict.get("key", "").strip().lower()
                field_val = field_dict.get("value", "").strip()
                if any(kw in field_key for kw in self.EXPIRY_FIELD_KEYWORDS):
                    exp_date = parse_date_safely(field_val)
                    if exp_date:
                        delta = (exp_date - now).days
                        if delta < 0:
                            expiring_keys_count += 1
                            issues.append(
                                HealthIssue(
                                    issue_type="expiring_key",
                                    severity="high",
                                    title=f"Expired Token/Key: '{e.title}'",
                                    description=f"Field '{field_dict.get('key')}' expired {abs(delta)} days ago ({exp_date.strftime('%Y-%m-%d')}).",
                                    entry_ids=[e.id],
                                    entry_titles=[e.title],
                                    recommendation="Renew or replace the expired certificate, license, or API key immediately.",
                                )
                            )
                        elif delta <= 30:
                            expiring_keys_count += 1
                            issues.append(
                                HealthIssue(
                                    issue_type="expiring_key",
                                    severity="medium",
                                    title=f"Expiring Soon: '{e.title}'",
                                    description=f"Field '{field_dict.get('key')}' expires in {delta} days ({exp_date.strftime('%Y-%m-%d')}).",
                                    entry_ids=[e.id],
                                    entry_titles=[e.title],
                                    recommendation="Schedule rotation for this credential before it expires.",
                                )
                            )

        # Compute Overall Score (100 down to 0)
        score = 100
        for issue in issues:
            if issue.severity == "high":
                score -= 15
            elif issue.severity == "medium":
                score -= 8
            elif issue.severity == "low":
                score -= 3

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Sort issues: High severity first, then Medium, then Low
        severity_rank = {"high": 0, "medium": 1, "low": 2}
        issues.sort(key=lambda x: severity_rank.get(x.severity, 3))

        return VaultHealthReport(
            overall_score=score,
            grade=grade,
            total_entries_analyzed=len(entries),
            issues=issues,
            duplicate_passwords_count=dup_pwd_count,
            duplicate_names_count=dup_names_count,
            weak_passwords_count=weak_pwd_count,
            stale_passwords_count=stale_pwd_count,
            expiring_keys_count=expiring_keys_count,
        )

    def _check_duplicate_names(self, entries: List[VaultEntry]) -> List[HealthIssue]:
        """Detects identical or fuzzy-matching titles that likely indicate duplicate records."""
        issues: List[HealthIssue] = []
        seen_pairs = set()

        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                e1 = entries[i]
                e2 = entries[j]
                t1 = e1.title.strip().lower()
                t2 = e2.title.strip().lower()

                pair_key = tuple(sorted([e1.id, e2.id]))
                if pair_key in seen_pairs:
                    continue

                if t1 and t2:
                    if t1 == t2:
                        seen_pairs.add(pair_key)
                        issues.append(
                            HealthIssue(
                                issue_type="duplicate_name",
                                severity="medium",
                                title=f"Identical Entry Titles: '{e1.title}'",
                                description=f"Two entries share the exact same title '{e1.title}' ({e1.entry_type} & {e2.entry_type}).",
                                entry_ids=[e1.id, e2.id],
                                entry_titles=[e1.title, e2.title],
                                recommendation="Consolidate duplicate records or rename them with specific environment tags (e.g., -prod, -stage).",
                            )
                        )
                    else:
                        ratio = fuzz.token_sort_ratio(t1, t2)
                        if ratio >= 90.0 and len(t1) >= 4 and len(t2) >= 4:
                            seen_pairs.add(pair_key)
                            issues.append(
                                HealthIssue(
                                    issue_type="duplicate_name",
                                    severity="low",
                                    title=f"Similar Entry Titles: '{e1.title}' & '{e2.title}'",
                                    description=f"Titles match with {ratio:.0f}% similarity. May be accidental duplicates.",
                                    entry_ids=[e1.id, e2.id],
                                    entry_titles=[e1.title, e2.title],
                                    recommendation="Verify if these are redundant duplicate entries.",
                                )
                            )
        return issues
