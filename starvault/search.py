"""Fuzzy search engine and relational tagging indexer for StarVault."""

from typing import List, Optional, Tuple
from rapidfuzz import fuzz

from starvault.models import VaultEntry


def search_entries(
    entries: List[VaultEntry],
    query: str,
    selected_category: str = "All",
    selected_tag: Optional[str] = None,
    min_score: float = 40.0,
) -> List[Tuple[VaultEntry, float]]:
    """Filters and ranks entries based on query, tags, and category.

    Relational Tagging:
    Searching for 'VPS1' will return both the server VPS1 and any services/keys
    tagged with 'VPS1'.

    Returns:
        List of tuples (entry, relevance_score) sorted by highest score first.
    """
    cleaned_query = query.strip().lower()

    # 1. Filter by category
    filtered = []
    for e in entries:
        if selected_category == "Favorites" and not e.is_favorite:
            continue
        elif selected_category == "Servers" and e.entry_type != "server":
            continue
        elif selected_category == "Services" and e.entry_type != "service":
            continue
        elif selected_category == "Keys" and e.entry_type != "keypair":
            continue
        elif (
            selected_category not in ("All", "Favorites", "Servers", "Services", "Keys")
            and e.category != selected_category
        ):
            continue

        # Filter by selected tag if specified
        if selected_tag:
            clean_tag = selected_tag.strip().lower()
            if not any(clean_tag == t.lower() for t in e.tags):
                continue

        filtered.append(e)

    # 2. If query is empty, return filtered items (favorites first, then alphabetical)
    if not cleaned_query:
        return [(e, 100.0 if e.is_favorite else 50.0) for e in filtered]

    # 3. Fuzzy search and score ranking
    scored: List[Tuple[VaultEntry, float]] = []

    for entry in filtered:
        title_lower = entry.title.lower()
        tags_lower = [t.lower() for t in entry.tags]
        host_lower = (entry.hostname or entry.url or "").lower()
        user_lower = entry.username.lower()
        app_lower = entry.app_name.lower()
        type_lower = entry.entry_type.lower()

        score = 0.0

        # Exact / Prefix title match (Highest Priority)
        if cleaned_query == title_lower:
            score += 100.0
        elif title_lower.startswith(cleaned_query):
            score += 85.0
        elif cleaned_query in title_lower:
            score += 75.0
        else:
            title_ratio = fuzz.token_set_ratio(cleaned_query, title_lower)
            score = max(score, title_ratio * 0.8)

        # Relational Tag Match (Crucial: typing "VPS1" matches anything tagged "VPS1")
        for tag in tags_lower:
            if cleaned_query == tag:
                score = max(score, 90.0)  # Direct relational tag match
            elif cleaned_query in tag or tag in cleaned_query:
                score = max(score, 75.0)
            else:
                tag_ratio = fuzz.ratio(cleaned_query, tag)
                if tag_ratio >= 70:
                    score = max(score, tag_ratio * 0.75)

        # Host / URL match
        if cleaned_query in host_lower:
            score = max(score, 70.0)
        elif host_lower:
            score = max(score, fuzz.partial_ratio(cleaned_query, host_lower) * 0.6)

        # Username match
        if cleaned_query in user_lower:
            score = max(score, 60.0)

        # App name match
        if cleaned_query in app_lower:
            score = max(score, 80.0)

        # Entry type match
        if cleaned_query in type_lower:
            score = max(score, 50.0)

        # Favorite slight boost
        if entry.is_favorite:
            score += 5.0

        if score >= min_score:
            scored.append((entry, score))

    # Sort descending by score, then title
    scored.sort(key=lambda x: (x[1], x[0].is_favorite, x[0].title.lower()), reverse=True)
    return scored
