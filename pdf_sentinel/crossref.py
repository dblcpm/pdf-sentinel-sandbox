"""
CrossRef DOI verification for citation integrity analysis.
Uses the free CrossRef API (https://api.crossref.org) — no API key required.
"""

import json
import re
import urllib.request
import urllib.error
from collections import Counter
from typing import Dict, List, Any, Optional

CROSSREF_API = "https://api.crossref.org/works/"
REQUEST_TIMEOUT = 10  # seconds per request
MAX_DOI_LOOKUPS = 20  # cap per scan to keep latency reasonable
MAILTO = "pdf-sentinel@example.com"  # polite pool header for better rate limits


def extract_dois(text: str) -> List[str]:
    """Extract unique DOIs from text, cleaned of trailing punctuation."""
    pattern = re.compile(r'\b(10\.\d{4,}/[^\s)}\]>,;]+)')
    raw = pattern.findall(text)
    cleaned = []
    seen = set()
    for doi in raw:
        doi = doi.rstrip(".,;:'\"")
        if doi not in seen:
            seen.add(doi)
            cleaned.append(doi)
    return cleaned


def fetch_crossref_metadata(doi: str) -> Optional[Dict[str, Any]]:
    """
    Query CrossRef for a single DOI.
    Returns parsed JSON metadata or None if the DOI is invalid / unreachable.
    """
    url = f"{CROSSREF_API}{urllib.request.quote(doi, safe='')}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"PDFSentinel/1.0 (mailto:{MAILTO})",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {})
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, Exception):
        return None


def verify_dois(dois: List[str]) -> Dict[str, Any]:
    """
    Verify a list of DOIs against CrossRef.

    Returns a dict with:
        valid_dois: list of DOIs that resolved
        invalid_dois: list of DOIs that did not resolve
        metadata: dict of doi -> {title, journal, authors, year, retracted}
        errors: list of error strings
    """
    lookup_dois = dois[:MAX_DOI_LOOKUPS]
    skipped = len(dois) - len(lookup_dois)

    valid = []
    invalid = []
    metadata = {}
    errors = []

    if skipped > 0:
        errors.append(
            f"Only the first {MAX_DOI_LOOKUPS} of {len(dois)} DOIs were checked "
            f"(limit to keep scan time reasonable)."
        )

    for doi in lookup_dois:
        meta = fetch_crossref_metadata(doi)
        if meta is None:
            invalid.append(doi)
            continue

        valid.append(doi)

        # Extract useful fields
        title_list = meta.get("title", [])
        title = title_list[0] if title_list else ""

        journal_list = meta.get("container-title", [])
        journal = journal_list[0] if journal_list else ""

        authors = []
        for a in meta.get("author", []):
            name = f"{a.get('given', '')} {a.get('family', '')}".strip()
            if name:
                authors.append(name)

        year = None
        date_parts = (meta.get("published-print") or meta.get("published-online") or {}).get("date-parts", [[]])
        if date_parts and date_parts[0]:
            year = date_parts[0][0]

        # Check retraction status
        retracted = False
        for update in meta.get("update-to", []):
            if update.get("type") == "retraction":
                retracted = True
                break

        metadata[doi] = {
            "title": title,
            "journal": journal,
            "authors": authors,
            "year": year,
            "retracted": retracted,
        }

    return {
        "valid_dois": valid,
        "invalid_dois": invalid,
        "metadata": metadata,
        "skipped": skipped,
        "errors": errors,
    }


def analyze_citation_patterns(verification: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect suspicious patterns in verified citation metadata.

    Checks for:
        - Invalid/fake DOIs
        - Journal concentration (citation ring)
        - Author self-citation clusters
        - Retracted papers being cited
    """
    meta = verification["metadata"]
    indicators = []

    # 1. Invalid DOIs
    invalid = verification["invalid_dois"]
    if invalid:
        pct = len(invalid) / (len(invalid) + len(verification["valid_dois"])) * 100
        indicators.append({
            "type": "invalid_dois",
            "severity": "high" if pct > 30 else "medium",
            "description": (
                f"{len(invalid)} DOI(s) ({pct:.0f}%) did not resolve on CrossRef. "
                f"These may be fabricated references: {', '.join(invalid[:5])}"
                + ("..." if len(invalid) > 5 else "")
            ),
        })

    # 2. Journal concentration
    journals = [m["journal"] for m in meta.values() if m["journal"]]
    if journals:
        journal_counts = Counter(journals)
        total = len(journals)
        for journal, count in journal_counts.most_common(3):
            ratio = count / total
            if total >= 5 and ratio > 0.5:
                indicators.append({
                    "type": "journal_concentration",
                    "severity": "high",
                    "description": (
                        f"{count}/{total} verified citations ({ratio:.0%}) come from "
                        f'"{journal}". This concentration suggests a possible citation ring.'
                    ),
                })

    # 3. Author self-citation cluster
    all_authors = []
    for m in meta.values():
        all_authors.extend(m["authors"])
    if all_authors:
        author_counts = Counter(all_authors)
        total_papers = len(meta)
        for author, count in author_counts.most_common(3):
            if total_papers >= 5 and count / total_papers > 0.4:
                indicators.append({
                    "type": "author_cluster",
                    "severity": "medium",
                    "description": (
                        f'Author "{author}" appears in {count}/{total_papers} '
                        f"cited works ({count/total_papers:.0%}). "
                        f"High self-citation or coordinated citation pattern."
                    ),
                })

    # 4. Retracted papers
    retracted = [doi for doi, m in meta.items() if m["retracted"]]
    if retracted:
        indicators.append({
            "type": "retracted_citations",
            "severity": "critical",
            "description": (
                f"{len(retracted)} cited paper(s) have been retracted: "
                + ", ".join(retracted[:5])
                + (". " if len(retracted) <= 5 else "... ")
                + "Citing retracted work may indicate paper-mill origin."
            ),
        })

    return {
        "total_checked": len(verification["valid_dois"]) + len(verification["invalid_dois"]),
        "valid_count": len(verification["valid_dois"]),
        "invalid_count": len(verification["invalid_dois"]),
        "retracted_count": len(retracted) if 'retracted' in dir() else 0,
        "indicators": indicators,
        "metadata": meta,
    }
