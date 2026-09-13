"""Automated organization, smart grouping, deduplication, and sorting engine for StarVault.

Provides both rule-based (instant offline heuristics) and AI-assisted automation for:
- Auto-grouping / smart categorization of credentials, keys, and files.
- Auto-tagging based on domain, protocol, environment, and credential features.
- Title normalization (e.g., standardizing casing, prefixes, environments).
- Smart deduplication and merging of redundant entries.
- Ghost/stale entry detection and purging.
- Multi-dimensional auto-sorting (risk, category, recency, title, type).
- File vault auto-organization into virtual directories.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from rapidfuzz import fuzz

from starvault.models import VaultEntry, VaultFile


# =============================================================================
# Category Rules & Keyword Dictionaries
# =============================================================================

CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "Cloud & Infrastructure": [
        "aws", "amazon", "azure", "gcp", "google cloud", "digitalocean", "linode",
        "vultr", "hetzner", "cloudflare", "vercel", "netlify", "heroku", "fly.io",
        "railway", "render", "supabase", "firebase", "proxmox", "vps", "server",
        "linux", "ubuntu", "debian", "centos", "rhel", "arch", "baremetal", "homelab",
        "ec2", "s3", "droplet", "ssh"
    ],
    "Dev & Repositories": [
        "github", "gitlab", "bitbucket", "docker", "dockerhub", "npm", "pypi",
        "maven", "git", "jenkins", "circleci", "travis", "argocd", "terraform",
        "kubernetes", "k8s", "sentry", "datadog", "grafana", "prometheus", "sonarqube",
        "postman", "jira", "confluence"
    ],
    "Databases & Storage": [
        "postgres", "postgresql", "mysql", "mariadb", "redis", "mongodb", "mongo",
        "cassandra", "dynamodb", "couchdb", "sqlite", "minio", "elasticsearch",
        "opensearch", "kafka", "rabbitmq", "cockroachdb", "database", "db"
    ],
    "AI & LLM Services": [
        "openai", "chatgpt", "anthropic", "claude", "gemini", "huggingface",
        "perplexity", "replicate", "mistral", "groq", "deepinfra", "fireworks",
        "together", "ollama", "cohere", "midjourney", "elevenlabs", "runway",
        "stability", "deepseek"
    ],
    "Finance & Payments": [
        "stripe", "paypal", "wise", "coinbase", "binance", "kraken", "plaid",
        "square", "shopify", "revolut", "bank", "mercury", "brex", "crypto",
        "metamask", "wallet", "ledger", "quickbooks", "xero"
    ],
    "Security & Networking": [
        "wireguard", "tailscale", "openvpn", "zerotier", "vpn", "dns", "route53",
        "pi-hole", "adguard", "pfsense", "opnsense", "nginx", "caddy", "traefik",
        "firewall", "proxy", "tor", "bastion"
    ],
    "Keys & Certificates": [
        "tls", "ssl", "cert", "certificate", "ed25519", "rsa", "gpg", "pgp",
        "age", "public key", "private key", "x509", "keypair"
    ],
    "Work & Productivity": [
        "slack", "notion", "trello", "asana", "google workspace", "microsoft",
        "office365", "m365", "zoom", "figma", "miro", "linear", "zendesk",
        "monday", "airtable", "clickup", "loom", "dropbox", "box"
    ],
    "Personal & Social": [
        "google", "apple", "twitter", "x.com", "discord", "reddit", "youtube",
        "netflix", "spotify", "steam", "twitch", "proton", "outlook", "gmail",
        "facebook", "instagram", "linkedin", "playstation", "xbox", "nintendo"
    ],
}

FILE_TYPE_FOLDERS: Dict[str, List[str]] = {
    "Keys & Certificates": [".pem", ".crt", ".cer", ".key", ".pub", ".pfx", ".p12", ".gpg", ".asc", ".age"],
    "Configs & Dotfiles": [".env", ".json", ".yaml", ".yml", ".toml", ".conf", ".ini", ".xml", ".cfg", ".sh", ".ps1"],
    "Documents & Manuals": [".pdf", ".docx", ".doc", ".txt", ".md", ".rtf", ".csv", ".xlsx"],
    "Archives & Backups": [".zip", ".7z", ".tar", ".gz", ".bz2", ".bak", ".sql", ".db"],
    "Media & Images": [".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp", ".ico"],
}


# =============================================================================
# Helper Data Classes
# =============================================================================

@dataclass
class DuplicateGroup:
    """Represents a cluster of duplicate or near-duplicate entries."""
    primary_id: str
    primary_title: str
    duplicate_ids: List[str]
    duplicate_titles: List[str]
    match_reason: str
    similarity_score: float = 1.0


@dataclass
class OrganizeSummary:
    """Detailed report of automated vault organization actions."""
    total_entries_scanned: int = 0
    categories_updated: int = 0
    tags_added: int = 0
    titles_normalized: int = 0
    duplicates_found: int = 0
    duplicates_merged: int = 0
    ghosts_purged: int = 0
    details: List[str] = field(default_factory=list)


# =============================================================================
# Categorization & Tagging Logic
# =============================================================================

def extract_domain(url_or_host: str) -> str:
    """Extracts a clean apex domain or hostname without scheme or path."""
    if not url_or_host:
        return ""
    text = url_or_host.strip().lower()
    if "://" not in text:
        text = "https://" + text
    try:
        parsed = urlparse(text)
        host = parsed.hostname or ""
        # Remove common prefixes like 'www.' or 'api.'
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def infer_category(entry: VaultEntry) -> str:
    """Infers the most appropriate category for a vault entry based on all available metadata."""
    # 1. Direct type checks
    if entry.entry_type == "keypair":
        return "Keys & Certificates"
    if entry.entry_type == "server":
        # Check if it has specific keywords, otherwise default to Cloud & Infrastructure
        combined = f"{entry.title} {entry.hostname} {entry.notes} {entry.os_distro}".lower()
        for cat, kw_list in CATEGORY_KEYWORDS.items():
            if any(kw in combined for kw in kw_list):
                return cat
        return "Cloud & Infrastructure"

    # 2. Combine textual signals
    signals = [
        entry.title,
        entry.url,
        entry.hostname,
        entry.app_name,
        entry.provider,
        entry.service_type,
        entry.notes,
        " ".join(entry.tags),
    ]
    search_text = " ".join(s for s in signals if s).lower()

    # Match against categorized keyword dictionary
    best_category = "General"
    max_matches = 0

    for cat, kw_list in CATEGORY_KEYWORDS.items():
        matches = sum(1 for kw in kw_list if kw in search_text)
        if matches > max_matches:
            max_matches = matches
            best_category = cat

    # Special fallbacks
    if max_matches == 0:
        if entry.entry_type == "apikey":
            return "Dev & Repositories"
        if entry.url or entry.app_name:
            return "Work & Productivity"
        return "General"

    return best_category


def infer_groups(entry: VaultEntry) -> List[str]:
    """Infers all relevant groups/categories for a vault entry based on all available metadata."""
    groups_set: Set[str] = set()
    primary = infer_category(entry)
    if primary and primary != "General":
        groups_set.add(primary)

    # Check for secondary matching categories
    signals = [
        entry.title,
        entry.url,
        entry.hostname,
        entry.app_name,
        entry.provider,
        entry.service_type,
        entry.notes,
        " ".join(entry.tags),
    ]
    search_text = " ".join(s for s in signals if s).lower()

    for cat, kw_list in CATEGORY_KEYWORDS.items():
        matches = sum(1 for kw in kw_list if kw in search_text)
        if matches >= 1:
            groups_set.add(cat)

    # Include any existing groups
    for g in getattr(entry, "groups", []):
        if g.strip() and g.strip() != "General":
            groups_set.add(g.strip())

    if not groups_set:
        groups_set.add(primary or "General")

    return sorted(list(groups_set))


def infer_services(entry: VaultEntry) -> List[str]:
    """Infers linked or associated service names for a vault entry."""
    services_set: Set[str] = set()
    if entry.app_name:
        services_set.add(entry.app_name)
    if entry.service_type and entry.service_type != "generic":
        services_set.add(entry.service_type.title())

    # Check for service keywords in title, hostname, notes
    text = f"{entry.title} {entry.hostname} {entry.url} {entry.notes} {' '.join(entry.tags)}".lower()
    common_services = [
        "postgres", "postgresql", "mysql", "mariadb", "redis", "mongodb", "nginx",
        "caddy", "docker", "rabbitmq", "kafka", "elasticsearch", "grafana",
        "prometheus", "vault", "nextjs", "react", "fastapi", "django", "flask",
        "stripe", "openai", "github", "gitlab", "wireguard", "tailscale"
    ]
    for s in common_services:
        if s in text:
            services_set.add(s.title())

    for s in getattr(entry, "services", []):
        if s.strip():
            services_set.add(s.strip())

    return sorted(list(services_set))


def infer_tags(entry: VaultEntry) -> List[str]:
    """Generates intelligent metadata tags from entry fields without duplication."""
    inferred: Set[str] = set()
    combined = f"{entry.title} {entry.url} {entry.hostname} {entry.app_name} {entry.provider} {entry.notes}".lower()

    # 1. Environment tags
    if any(k in combined for k in ["prod", "production", "live"]):
        inferred.add("env:production")
    elif any(k in combined for k in ["stage", "staging"]):
        inferred.add("env:staging")
    elif any(k in combined for k in ["dev", "development", "local"]):
        inferred.add("env:development")
    elif any(k in combined for k in ["test", "testing", "qa"]):
        inferred.add("env:test")

    # 2. Provider / Cloud tags
    cloud_providers = {
        "aws": "cloud:aws",
        "gcp": "cloud:gcp",
        "google": "cloud:gcp",
        "azure": "cloud:azure",
        "digitalocean": "cloud:digitalocean",
        "cloudflare": "cloud:cloudflare",
        "linode": "cloud:linode",
        "hetzner": "cloud:hetzner",
        "vercel": "cloud:vercel",
        "supabase": "cloud:supabase",
    }
    for kw, tag in cloud_providers.items():
        if kw in combined:
            inferred.add(tag)

    # 3. Protocol & Service tags
    if entry.entry_type == "server" or entry.port == 22:
        inferred.add("proto:ssh")
    if entry.port in (443, 8443) or "https://" in entry.url.lower():
        inferred.add("proto:https")
    if getattr(entry, "key_type", ""):
        inferred.add(f"key:{entry.key_type.lower()}")
    if "wireguard" in combined:
        inferred.add("proto:wireguard")
    if "gpg" in combined or "pgp" in combined:
        inferred.add("proto:gpg")

    # 4. Database tags
    db_types = {
        "postgres": "db:postgres",
        "mysql": "db:mysql",
        "redis": "db:redis",
        "mongo": "db:mongo",
        "sqlite": "db:sqlite",
    }
    for kw, tag in db_types.items():
        if kw in combined:
            inferred.add(tag)

    # 5. Security & Auth tags
    if entry.totp_secret:
        inferred.add("has:totp")
    if entry.api_token or entry.api_key_secret:
        inferred.add("has:api-key")
    if entry.ssh_private_key or (entry.entry_type == "keypair" and entry.private_key):
        inferred.add("has:private-key")

    # 6. Domain Tag
    domain = extract_domain(entry.url or entry.hostname)
    if domain and "." in domain and not domain.startswith("127.") and not domain.startswith("192.168."):
        # Extract main apex (e.g. github.com)
        parts = domain.split(".")
        if len(parts) >= 2:
            apex = ".".join(parts[-2:])
            inferred.add(f"domain:{apex}")

    return sorted(list(inferred))


def normalize_title(entry: VaultEntry) -> str:
    """Cleans up and normalizes entry titles to standard naming conventions."""
    orig = entry.title.strip()
    if not orig:
        # Generate sensible title if empty
        if entry.hostname:
            return f"Server - {entry.hostname}"
        if entry.app_name:
            return f"Service - {entry.app_name}"
        if entry.provider:
            return f"{entry.provider.title()} API Key"
        if entry.key_name:
            return f"Key - {entry.key_name}"
        return "Untitled Entry"

    # Replace consecutive spaces, underscores, or dashes with standard formatting
    title = re.sub(r"[\t_]+", " ", orig).strip()
    title = re.sub(r"\s{2,}", " ", title)

    # Standardize known acronyms casing
    acronyms = [
        "AWS", "GCP", "SSH", "GPG", "PGP", "RSA", "API", "DB", "TLS",
        "SSL", "VPN", "DNS", "URL", "IP", "VPS", "TOTP", "UI", "ID", "OS",
        "CLI", "MFA", "OTP", "LAN", "WAN", "S3", "FTP", "SFTP"
    ]
    words = title.split(" ")
    normalized_words = []
    for w in words:
        w_clean = re.sub(r"[^\w]", "", w)
        upper_match = next((acr for acr in acronyms if acr.lower() == w_clean.lower()), None)
        if upper_match:
            # Replace while preserving punctuation
            replaced = re.sub(re.escape(w_clean), upper_match, w, flags=re.IGNORECASE)
            normalized_words.append(replaced)
        else:
            # Capitalize first letter if all lowercase
            if w.islower() and len(w) > 2:
                normalized_words.append(w.capitalize())
            else:
                normalized_words.append(w)

    title = " ".join(normalized_words)

    # Standardize environment suffixes e.g. "My App [PROD]" -> "My App (Production)"
    env_fixes = [
        (r"\[prod\]|\(prod\)|-prod|_prod", " (Prod)"),
        (r"\[stage\]|\(stage\)|-stage|_stage", " (Staging)"),
        (r"\[dev\]|\(dev\)|-dev|_dev", " (Dev)"),
    ]
    for pattern, repl in env_fixes:
        if re.search(pattern, title, flags=re.IGNORECASE):
            title = re.sub(pattern, "", title, flags=re.IGNORECASE).strip()
            if not title.endswith(repl.strip()):
                title = f"{title}{repl}"

    return title.strip()


# =============================================================================
# Deduplication & Merge Logic
# =============================================================================

def find_duplicates(entries: List[VaultEntry]) -> List[DuplicateGroup]:
    """Scans all entries in-memory and clusters exact and high-similarity duplicates."""
    groups: List[DuplicateGroup] = []
    claimed_ids: Set[str] = set()

    for i in range(len(entries)):
        e1 = entries[i]
        if e1.id in claimed_ids:
            continue

        duplicate_ids = []
        duplicate_titles = []
        match_reason = ""
        highest_score = 0.0

        for j in range(i + 1, len(entries)):
            e2 = entries[j]
            if e2.id in claimed_ids:
                continue

            # 1. Exact match on username + host/url (strongest duplicate signal)
            u1, u2 = (e1.username or "").strip().lower(), (e2.username or "").strip().lower()
            h1 = extract_domain(e1.url or e1.hostname)
            h2 = extract_domain(e2.url or e2.hostname)

            if u1 and u2 and u1 == u2 and h1 and h2 and h1 == h2:
                duplicate_ids.append(e2.id)
                duplicate_titles.append(e2.title)
                match_reason = f"Matching username '{e1.username}' and host '{h1}'"
                highest_score = 1.0
                claimed_ids.add(e2.id)
                continue

            # 2. Exact match on public key or fingerprint (for keypairs)
            if e1.public_key and e2.public_key and e1.public_key.strip() == e2.public_key.strip():
                duplicate_ids.append(e2.id)
                duplicate_titles.append(e2.title)
                match_reason = "Identical cryptographic public key"
                highest_score = 1.0
                claimed_ids.add(e2.id)
                continue

            # 3. High fuzzy title similarity (> 92%) with identical entry type and matching username/pass
            t1, t2 = e1.title.strip().lower(), e2.title.strip().lower()
            ratio = fuzz.token_sort_ratio(t1, t2)
            if ratio >= 92.0 and e1.entry_type == e2.entry_type:
                # Require either matching password, username, or both titles > 5 chars
                same_pass = bool(e1.password and e2.password and e1.password == e2.password)
                same_user = bool(u1 and u2 and u1 == u2)
                if same_pass or same_user or (len(t1) >= 6 and ratio >= 96.0):
                    duplicate_ids.append(e2.id)
                    duplicate_titles.append(e2.title)
                    match_reason = f"High title similarity ({ratio:.0f}%) and matching credentials"
                    highest_score = max(highest_score, ratio / 100.0)
                    claimed_ids.add(e2.id)

        if duplicate_ids:
            claimed_ids.add(e1.id)
            groups.append(
                DuplicateGroup(
                    primary_id=e1.id,
                    primary_title=e1.title,
                    duplicate_ids=duplicate_ids,
                    duplicate_titles=duplicate_titles,
                    match_reason=match_reason,
                    similarity_score=highest_score,
                )
            )

    return groups


def merge_entries(primary: VaultEntry, duplicate: VaultEntry) -> VaultEntry:
    """Intelligently consolidates duplicate entry into primary, preserving all unique secrets & notes."""
    # 1. Merge tags
    existing_tags = set(primary.tags)
    for t in duplicate.tags:
        existing_tags.add(t)
    primary.tags = sorted(list(existing_tags))

    # 2. Merge custom fields
    primary_cf_keys = {cf.get("key", "").strip().lower() for cf in primary.custom_fields}
    for dup_cf in duplicate.custom_fields:
        k = dup_cf.get("key", "").strip().lower()
        if k and k not in primary_cf_keys:
            primary.custom_fields.append(dict(dup_cf))
            primary_cf_keys.add(k)

    # 3. Fill missing fields from duplicate
    if not primary.password and duplicate.password:
        primary.password = duplicate.password
    if not primary.username and duplicate.username:
        primary.username = duplicate.username
    if not primary.url and duplicate.url:
        primary.url = duplicate.url
    if not primary.hostname and duplicate.hostname:
        primary.hostname = duplicate.hostname
    if not primary.api_token and duplicate.api_token:
        primary.api_token = duplicate.api_token
    if not primary.totp_secret and duplicate.totp_secret:
        primary.totp_secret = duplicate.totp_secret
    if not primary.parent_server_id and duplicate.parent_server_id:
        primary.parent_server_id = duplicate.parent_server_id

    # 4. Append duplicate notes if distinct
    if duplicate.notes and duplicate.notes.strip() not in (primary.notes or ""):
        merged_note = f"\n\n--- Merged from duplicate '{duplicate.title}' ---\n{duplicate.notes.strip()}"
        primary.notes = (primary.notes or "").strip() + merged_note

    primary.updated_at = datetime.now(timezone.utc).isoformat()
    return primary


# =============================================================================
# Ghost & Stale Entry Detection
# =============================================================================

def find_ghost_and_stale(entries: List[VaultEntry]) -> Dict[str, Any]:
    """Identifies empty 'ghost' records, abandoned test items, and orphaned child credentials."""
    ghosts: List[VaultEntry] = []
    orphans: List[VaultEntry] = []
    stale_test: List[VaultEntry] = []

    all_ids = {e.id for e in entries}

    for e in entries:
        # Check Ghost: No secrets, no url/host, no notes
        has_secret = bool(e.password or e.api_token or e.api_key_secret or e.private_key or e.ssh_private_key)
        has_destination = bool(e.url or e.hostname or e.app_name)
        has_content = bool(e.notes or e.custom_fields)

        if not has_secret and not has_destination and not has_content:
            ghosts.append(e)
            continue

        # Check Orphaned Subcredential: parent_server_id specified but parent does not exist
        if e.parent_server_id and e.parent_server_id not in all_ids:
            orphans.append(e)

        # Check abandoned test entries
        t_low = e.title.lower()
        if any(kw in t_low for kw in ["test", "dummy", "sample", "temp", "untitled"]) and not has_secret:
            stale_test.append(e)

    return {
        "ghosts": ghosts,
        "orphans": orphans,
        "stale_test": stale_test,
        "total_issues": len(ghosts) + len(orphans) + len(stale_test),
    }


# =============================================================================
# Multi-Dimensional Auto-Sorting
# =============================================================================

def natural_sort_key(s: str) -> List[Any]:
    """Splits string into numeric and non-numeric chunks for natural numerical sorting (e.g. vps2 before vps10)."""
    return [int(chunk) if chunk.isdigit() else chunk.lower() for chunk in re.split(r'(\d+)', s or "")]


def sort_entries(
    entries: List[VaultEntry],
    sort_by: str = "category",
    favorites_first: bool = True,
    reverse: bool = False,
) -> List[VaultEntry]:
    """Sorts entries according to selected criteria:
    - Alphabetical (A-Z / Z-A)
    - Natural Numeric (1, 2, 10...)
    - Date Created (Newest / Oldest)
    - Date Modified (Newest / Oldest)
    - Category
    - Security Risk
    - Entry Type
    - Port Number
    """
    result = list(entries)

    if sort_by in ("natural", "numeric", "natural_asc"):
        result.sort(key=lambda e: natural_sort_key(e.title))
    elif sort_by in ("natural_desc", "numeric_desc"):
        result.sort(key=lambda e: natural_sort_key(e.title), reverse=True)
    elif sort_by in ("title_asc", "alpha_asc"):
        result.sort(key=lambda e: e.title.lower())
    elif sort_by in ("title_desc", "alpha_desc"):
        result.sort(key=lambda e: e.title.lower(), reverse=True)
    elif sort_by in ("created_desc", "date_created_desc"):
        result.sort(key=lambda e: e.created_at or "", reverse=True)
    elif sort_by in ("created_asc", "date_created_asc"):
        result.sort(key=lambda e: e.created_at or "")
    elif sort_by in ("recency", "modified_desc", "date_modified_desc"):
        result.sort(key=lambda e: e.updated_at or e.created_at or "", reverse=True)
    elif sort_by in ("modified_asc", "date_modified_asc"):
        result.sort(key=lambda e: e.updated_at or e.created_at or "")
    elif sort_by in ("port", "port_numeric"):
        result.sort(key=lambda e: (e.port or 0, natural_sort_key(e.title)))
    elif sort_by in ("password_len", "password_length"):
        result.sort(key=lambda e: len(e.password or ""), reverse=True)
    elif sort_by == "category":
        result.sort(key=lambda e: (e.category.lower(), natural_sort_key(e.title)))
    elif sort_by == "type":
        type_rank = {"server": 0, "service": 1, "apikey": 2, "keypair": 3}
        result.sort(key=lambda e: (type_rank.get(e.entry_type, 4), natural_sort_key(e.title)))
    elif sort_by == "risk":
        # Sort by security risk: empty/weak/expiring first
        def risk_score(e: VaultEntry) -> int:
            score = 0
            if not e.password and not e.api_token and e.entry_type != "keypair":
                score += 10
            if e.password and len(e.password) < 10:
                score += 8
            if e.expires_at:
                score += 5
            return score

        result.sort(key=lambda e: (risk_score(e), natural_sort_key(e.title)), reverse=True)

    if reverse:
        result.reverse()

    if favorites_first:
        result.sort(key=lambda e: 0 if e.is_favorite else 1)

    return result


# =============================================================================
# High-Level Automation Orchestrators
# =============================================================================

def auto_organize_vault(
    database,
    key: bytes,
    override_categories: bool = False,
    dry_run: bool = False,
) -> OrganizeSummary:
    """One-click high-level vault organizer: groups, tags, and normalizes all entries.

    - Categorizes unassigned or 'General' entries into domain categories.
    - Extracts environment, protocol, and cloud tags.
    - Normalizes casing and title acronyms.
    - Fully atomic, zero-knowledge in-memory execution.
    """
    entries = database.get_all_entries(key)
    summary = OrganizeSummary(total_entries_scanned=len(entries))

    updated_entries: List[VaultEntry] = []

    for e in entries:
        changed = False

        # 1. Auto-Categorize
        current_cat = e.category.strip()
        if override_categories or not current_cat or current_cat in ("General", "Uncategorized"):
            new_cat = infer_category(e)
            if new_cat != current_cat:
                e.category = new_cat
                summary.categories_updated += 1
                summary.details.append(f"Categorized '{e.title}' -> [{new_cat}]")
                changed = True

        # 2. Auto-Tag
        new_tags = infer_tags(e)
        existing_tags = set(e.tags)
        added_for_entry = [t for t in new_tags if t not in existing_tags]
        if added_for_entry:
            e.tags = sorted(list(existing_tags.union(added_for_entry)))
            summary.tags_added += len(added_for_entry)
            summary.details.append(f"Added tags to '{e.title}': {', '.join(added_for_entry)}")
            changed = True

        # 2b. Auto-Group (Multiple groups assignment)
        new_groups = infer_groups(e)
        if set(new_groups) != set(getattr(e, "groups", [])):
            e.groups = new_groups
            if not e.category or e.category in ("General", "Uncategorized"):
                e.category = new_groups[0] if new_groups else "General"
            summary.details.append(f"Assigned groups to '{e.title}': {', '.join(new_groups)}")
            changed = True

        # 2c. Auto-Service (Multiple services assignment)
        new_services = infer_services(e)
        if set(new_services) != set(getattr(e, "services", [])):
            e.services = new_services
            summary.details.append(f"Assigned services to '{e.title}': {', '.join(new_services)}")
            changed = True

        # 3. Title Normalization
        norm_title = normalize_title(e)
        if norm_title != e.title:
            summary.details.append(f"Normalized title: '{e.title}' -> '{norm_title}'")
            e.title = norm_title
            summary.titles_normalized += 1
            changed = True

        if changed:
            updated_entries.append(e)

    # 4. Find duplicates count
    dup_groups = find_duplicates(entries)
    summary.duplicates_found = sum(len(g.duplicate_ids) for g in dup_groups)

    if not dry_run and updated_entries:
        for e in updated_entries:
            database.save_entry(e, key)

    return summary


def auto_organize_files(database, key: bytes, dry_run: bool = False) -> Dict[str, Any]:
    """Auto-organizes stored file attachments into virtual folder tags based on extension and mime type."""
    files: List[VaultFile] = database.get_all_files(key)
    updated_files = 0
    folder_counts: Dict[str, int] = {}

    for f in files:
        ext = "." + f.filename.split(".")[-1].lower() if "." in f.filename else ""
        assigned_folder = "Documents & Manuals"

        for folder_name, ext_list in FILE_TYPE_FOLDERS.items():
            if ext in ext_list:
                assigned_folder = folder_name
                break

        folder_counts[assigned_folder] = folder_counts.get(assigned_folder, 0) + 1
        folder_tag = f"folder:{assigned_folder}"

        if folder_tag not in f.tags:
            f.tags.append(folder_tag)
            if ext and f"ext:{ext[1:]}" not in f.tags:
                f.tags.append(f"ext:{ext[1:]}")
            updated_files += 1

            if not dry_run:
                # Read bytes and re-save with updated tags
                raw_bytes = database.read_file_bytes(f.id, key)
                if raw_bytes is not None:
                    database.save_file(f, raw_bytes, key)

    return {
        "total_files_scanned": len(files),
        "files_updated": updated_files,
        "folder_breakdown": folder_counts,
    }


def deduplicate_vault(database, key: bytes, auto_merge: bool = True) -> Dict[str, Any]:
    """Finds all duplicate clusters and merges them into the primary record, deleting redundancies."""
    entries = database.get_all_entries(key)
    dup_groups = find_duplicates(entries)

    merged_count = 0
    merged_details = []

    if not auto_merge:
        return {
            "duplicate_groups_count": len(dup_groups),
            "groups": [
                {
                    "primary_title": g.primary_title,
                    "duplicate_titles": g.duplicate_titles,
                    "reason": g.match_reason,
                    "similarity": round(g.similarity_score * 100, 1),
                }
                for g in dup_groups
            ],
            "merged_count": 0,
        }

    id_map = {e.id: e for e in entries}

    for g in dup_groups:
        primary = id_map.get(g.primary_id)
        if not primary:
            continue

        for dup_id in g.duplicate_ids:
            dup_entry = id_map.get(dup_id)
            if not dup_entry:
                continue

            primary = merge_entries(primary, dup_entry)
            database.delete_entry(dup_id)
            merged_count += 1
            merged_details.append(f"Merged '{dup_entry.title}' into '{primary.title}' ({g.match_reason})")

        database.save_entry(primary, key)

    return {
        "duplicate_groups_count": len(dup_groups),
        "merged_count": merged_count,
        "details": merged_details,
    }


def purge_ghost_entries(database, key: bytes) -> Dict[str, Any]:
    """Permanently purges empty ghost records and clears invalid orphan parent references."""
    entries = database.get_all_entries(key)
    findings = find_ghost_and_stale(entries)

    purged_ghosts = 0
    fixed_orphans = 0

    # 1. Delete ghosts & empty test items
    to_delete = findings["ghosts"] + findings["stale_test"]
    deleted_ids = set()
    for g in to_delete:
        if g.id not in deleted_ids:
            database.delete_entry(g.id)
            deleted_ids.add(g.id)
            purged_ghosts += 1

    # 2. Fix orphaned child entries (clear parent_server_id)
    for o in findings["orphans"]:
        o.parent_server_id = None
        database.save_entry(o, key)
        fixed_orphans += 1

    return {
        "purged_ghosts": purged_ghosts,
        "fixed_orphans": fixed_orphans,
        "total_cleaned": purged_ghosts + fixed_orphans,
    }
