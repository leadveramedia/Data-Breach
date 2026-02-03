import csv
import hashlib
import json
import os
import re
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from dateutil.parser import UnknownTimezoneWarning
from dotenv import load_dotenv
import feedparser


MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|November|December"
)
DATE_RE = re.compile(rf"({MONTHS})\s+\d{{1,2}},\s+\d{{4}}")
TIME_RE = re.compile(r"\d{1,2}:\d{2}|\bAM\b|\bPM\b", re.IGNORECASE)

# Dark web leak site extraction patterns
DATA_SIZE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(GB|TB|MB|gigabytes?|terabytes?|megabytes?)",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"(?:website|domain|url|site)[:\s]*((?:https?://)?[\w.-]+\.[a-z]{2,})",
    re.IGNORECASE,
)
COUNTRY_RE = re.compile(
    r"(?:country|location|region)[:\s]*([A-Za-z\s]+?)(?:\s*[|<\n]|$)",
    re.IGNORECASE,
)
SECTOR_RE = re.compile(
    r"(?:sector|industry|activity|business)[:\s]*([^<\n|]{3,50})",
    re.IGNORECASE,
)
DEADLINE_RE = re.compile(
    r"(?:deadline|expires?|timer|countdown)[:\s]*([^<\n]{5,30})",
    re.IGNORECASE,
)
POST_DATE_RE = re.compile(
    r"(?:posted|published|added|date)[:\s]*(\d{1,4}[-/]\d{1,2}[-/]\d{1,4})",
    re.IGNORECASE,
)

# Skip words for filtering navigation elements
SKIP_WORDS = frozenset([
    "home", "contact", "about", "login", "register", "download",
    "more", "read", "click", "view", "menu", "search", "faq",
])

# Country name to ISO code mapping
COUNTRY_CODES = {
    "united states": "US", "usa": "US", "u.s.": "US", "u.s.a.": "US", "america": "US",
    "united kingdom": "GB", "uk": "GB", "great britain": "GB", "britain": "GB",
    "germany": "DE", "france": "FR", "canada": "CA", "australia": "AU",
    "italy": "IT", "spain": "ES", "brazil": "BR", "japan": "JP",
    "netherlands": "NL", "belgium": "BE", "switzerland": "CH",
    "mexico": "MX", "india": "IN", "china": "CN", "russia": "RU",
    "south korea": "KR", "korea": "KR", "singapore": "SG",
    "israel": "IL", "sweden": "SE", "norway": "NO", "denmark": "DK",
    "finland": "FI", "austria": "AT", "poland": "PL", "portugal": "PT",
    "ireland": "IE", "new zealand": "NZ", "south africa": "ZA",
    "argentina": "AR", "chile": "CL", "colombia": "CO", "peru": "PE",
    "thailand": "TH", "malaysia": "MY", "indonesia": "ID", "philippines": "PH",
    "vietnam": "VN", "taiwan": "TW", "hong kong": "HK", "uae": "AE",
    "saudi arabia": "SA", "egypt": "EG", "turkey": "TR", "greece": "GR",
    "czech republic": "CZ", "czechia": "CZ", "hungary": "HU", "romania": "RO",
    "ukraine": "UA", "pakistan": "PK", "bangladesh": "BD", "nigeria": "NG",
}

# Sector keywords for detection
SECTOR_KEYWORDS = frozenset([
    "healthcare", "medical", "hospital", "clinic", "pharmaceutical", "biotech",
    "financial", "banking", "insurance", "investment", "fintech", "credit union",
    "education", "university", "school", "college", "academy", "training",
    "manufacturing", "industrial", "automotive", "aerospace", "electronics",
    "retail", "e-commerce", "store", "wholesale", "consumer goods",
    "technology", "software", "it services", "saas", "cloud", "cybersecurity",
    "legal", "law firm", "attorney", "solicitor", "consulting",
    "government", "municipal", "federal", "state", "public sector", "military",
    "energy", "utilities", "oil", "gas", "power", "renewable",
    "construction", "real estate", "property", "architecture", "engineering",
    "transportation", "logistics", "shipping", "freight", "aviation", "maritime",
    "telecommunications", "telecom", "media", "entertainment", "broadcasting",
    "agriculture", "food", "beverage", "farming", "agribusiness",
    "hospitality", "hotel", "restaurant", "tourism", "travel",
    "nonprofit", "ngo", "charity", "foundation",
])

# Data type indicators for breach classification
DATA_TYPE_INDICATORS = {
    "pii": ["ssn", "social security", "personal information", "pii", "identity",
            "passport", "driver license", "date of birth", "dob"],
    "financial": ["credit card", "bank account", "financial", "payment", "billing",
                  "tax", "accounting", "invoice", "wire transfer"],
    "medical": ["health records", "medical", "hipaa", "patient", "phi",
                "prescription", "diagnosis", "healthcare", "insurance claims"],
    "credentials": ["password", "credentials", "login", "authentication",
                    "api key", "token", "ssh key", "certificate"],
    "corporate": ["contracts", "proprietary", "trade secret", "intellectual property",
                  "nda", "internal", "confidential", "strategic"],
    "employee": ["employee records", "hr records", "payroll", "personnel",
                 "salary", "benefits", "w-2", "performance review"],
    "customer": ["customer data", "client information", "user data",
                 "subscriber", "member", "contact list", "crm"],
}

# Data attribute mappings for HTML data-* attributes
DATA_ATTR_MAPPING = {
    "data-name": "name", "data-company": "name", "data-victim": "name", "data-title": "name",
    "data-country": "country", "data-location": "country", "data-region": "country",
    "data-sector": "sector", "data-industry": "sector", "data-activity": "sector",
    "data-size": "data_size", "data-volume": "data_size",
    "data-date": "post_date", "data-published": "post_date", "data-time": "post_date",
    "data-deadline": "deadline", "data-timer": "deadline",
    "data-website": "website", "data-url": "website", "data-domain": "website",
}


@dataclass
class Finding:
    source_id: str
    kind: str
    source_url: str
    title: str
    url: str
    published: str
    published_dt: Optional[datetime]
    has_time: bool
    summary: str

    def uid(self) -> str:
        payload = f"{self.source_id}|{self.title}|{self.url}|{self.published}".encode(
            "utf-8"
        )
        return hashlib.sha256(payload).hexdigest()


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_seen(path: str) -> set:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("seen_ids", []))


def save_seen(path: str, seen: set) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"seen_ids": sorted(seen)}, f, indent=2)


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def parse_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UnknownTimezoneWarning)
            dt = dateparser.parse(value, fuzzy=True)
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def has_time_label(value: str) -> bool:
    return bool(TIME_RE.search(value or ""))


def format_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    return dt.isoformat()


def keyword_hit(text: str, keywords: Iterable[str]) -> bool:
    hay = (text or "").lower()
    for kw in keywords:
        if kw.lower() in hay:
            return True
    return False


def http_get(url: str, headers: Optional[Dict[str, str]], timeout: int) -> requests.Response:
    resp = requests.get(url, headers=headers or {}, timeout=timeout)
    resp.raise_for_status()
    return resp


# Tor proxy settings for dark web access
TOR_PROXY = "socks5h://127.0.0.1:9050"
RANSOMWATCH_GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"


def http_get_tor(url: str, headers: Optional[Dict[str, str]], timeout: int) -> requests.Response:
    """Make HTTP request through Tor proxy for .onion sites."""
    session = requests.Session()
    session.proxies = {
        "http": TOR_PROXY,
        "https": TOR_PROXY,
    }
    resp = session.get(url, headers=headers or {}, timeout=timeout)
    resp.raise_for_status()
    return resp


def load_ransomwatch_groups(headers: Dict[str, str], timeout: int) -> List[Dict]:
    """Fetch current ransomware group onion addresses from ransomwatch."""
    resp = http_get(RANSOMWATCH_GROUPS_URL, headers, timeout)
    return resp.json()


def parse_rss(urls: List[str], headers: Dict[str, str], timeout: int) -> List[Dict]:
    entries: List[Dict] = []
    for url in urls:
        try:
            resp = http_get(url, headers=headers, timeout=timeout)
            feed = feedparser.parse(resp.content)
            for entry in feed.entries:
                entries.append(entry)
        except Exception:
            continue
    return entries


def find_csv_link(soup: BeautifulSoup, base_url: str) -> Optional[str]:
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = (a.get_text() or "").lower()
        if "csv" in href.lower() or "csv" in text:
            return urljoin(base_url, href)
    return None


def fetch_hhs_ocr(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    url = source["url"]
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    resp = http_get(url, headers=headers, timeout=timeout)
    soup = BeautifulSoup(resp.text, "lxml")
    csv_url = find_csv_link(soup, url)
    findings: List[Finding] = []

    if csv_url:
        csv_resp = http_get(csv_url, headers=headers, timeout=timeout)
        reader = csv.DictReader(csv_resp.text.splitlines())
        for row in reader:
            name = clean_text(row.get("Name of Covered Entity") or row.get("Covered Entity"))
            if not name:
                continue
            date_val = (
                row.get("Breach Submission Date")
                or row.get("Breach Submission Date (M/D/YYYY)")
                or ""
            )
            published_dt = parse_datetime(date_val)
            has_time = has_time_label(date_val)
            published = format_dt(published_dt)

            # Extract all available fields
            summary_parts = []
            affected = clean_text(row.get("Individuals Affected") or "")
            if affected:
                summary_parts.append(f"Persons affected: {affected}")
            state = clean_text(row.get("State") or "")
            if state:
                summary_parts.append(f"State: {state}")
            entity_type = clean_text(row.get("Covered Entity Type") or "")
            if entity_type:
                summary_parts.append(f"Entity type: {entity_type}")
            breach_type = clean_text(row.get("Type of Breach") or "")
            if breach_type:
                summary_parts.append(f"Breach type: {breach_type}")
            location = clean_text(row.get("Location of Breached Information") or "")
            if location:
                summary_parts.append(f"Info location: {location}")
            ba_present = clean_text(row.get("Business Associate Present") or "")
            if ba_present:
                summary_parts.append(f"Business associate: {ba_present}")
            web_desc = clean_text(row.get("Web Description") or "")
            if web_desc:
                summary_parts.append(f"Description: {web_desc}")
            summary = " | ".join(summary_parts)
            findings.append(
                Finding(
                    source_id=source["id"],
                    kind=source["kind"],
                    source_url=url,
                    title=name,
                    url=url,
                    published=published,
                    published_dt=published_dt,
                    has_time=has_time,
                    summary=summary,
                )
            )
        return findings

    # Fallback: parse table rows from HTML.
    table = soup.find("table")
    if not table:
        return findings
    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 2:
            continue
        name = clean_text(cells[0].get_text())
        if not name:
            continue
        date_val = clean_text(cells[1].get_text())
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        summary = clean_text(" ".join(c.get_text() for c in cells[2:]))
        findings.append(
            Finding(
                source_id=source["id"],
                kind=source["kind"],
                source_url=url,
                title=name,
                url=url,
                published=published,
                published_dt=published_dt,
                has_time=has_time,
                summary=summary,
            )
        )
    return findings


def fetch_ca_ag(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    url = source["url"]
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    resp = http_get(url, headers=headers, timeout=timeout)
    soup = BeautifulSoup(resp.text, "lxml")

    link_map: Dict[str, str] = {}
    for a in soup.find_all("a", href=True):
        if "/privacy/databreach/list" in a["href"]:
            continue
        name = clean_text(a.get_text())
        if not name:
            continue
        link_map[name] = urljoin(url, a["href"])

    csv_url = find_csv_link(soup, url)
    findings: List[Finding] = []
    if csv_url:
        csv_resp = http_get(csv_url, headers=headers, timeout=timeout)
        reader = csv.DictReader(csv_resp.text.splitlines())
        for row in reader:
            name = clean_text(row.get("Organization Name") or row.get("Organization"))
            if not name:
                continue
            date_val = (
                row.get("Reported Date")
                or row.get("Date Reported")
                or ""
            )
            published_dt = parse_datetime(date_val)
            has_time = has_time_label(date_val)
            published = format_dt(published_dt)
            notice_url = link_map.get(name, url)

            # Build detailed summary
            summary_parts = []
            breach_dates = clean_text(row.get("Date(s) of Breach") or "")
            if breach_dates:
                summary_parts.append(f"Breach date(s): {breach_dates}")
            breach_type = clean_text(row.get("Type of Breach") or "")
            if breach_type:
                summary_parts.append(f"Breach type: {breach_type}")
            info_type = clean_text(row.get("Type of Information") or "")
            if info_type:
                summary_parts.append(f"Info compromised: {info_type}")
            notice_to = clean_text(row.get("Notice Provided to") or "")
            if notice_to:
                summary_parts.append(f"Notice to: {notice_to}")
            summary = " | ".join(summary_parts)
            findings.append(
                Finding(
                    source_id=source["id"],
                    kind=source["kind"],
                    source_url=url,
                    title=name,
                    url=notice_url,
                    published=published,
                    published_dt=published_dt,
                    has_time=has_time,
                    summary=summary,
                )
            )
        return findings

    return findings


def fetch_me_ag_detail(detail_url: str, headers: Dict[str, str], timeout: int) -> Dict[str, str]:
    """Fetch additional breach details from individual Maine AG detail page."""
    details: Dict[str, str] = {}
    try:
        resp = http_get(detail_url, headers=headers, timeout=timeout)
        text = resp.text

        patterns = [
            ("persons_affected", r"Total number of persons affected[^:]*:\s*\**(\d[\d,]*)\**"),
            ("date_occurred", r"Date\(s\) Breach Occur+ed:\s*\**([^\n<*]+)\**"),
            ("date_discovered", r"Date Breach Discovered:\s*\**([^\n<*]+)\**"),
            ("description", r"Description of the Breach:\s*\**([^\n<*]+)\**"),
            ("info_acquired", r"Information Acquired[^:]*:\s*\**([^\n<*]+)\**"),
        ]

        for key, pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                details[key] = clean_text(match.group(1))
    except Exception:
        pass
    return details


def fetch_me_ag(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    url = source["url"]
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    resp = http_get(url, headers=headers, timeout=timeout)
    soup = BeautifulSoup(resp.text, "lxml")
    table = soup.find("table")
    findings: List[Finding] = []
    if not table:
        return findings
    for row in table.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        # Column 0 = Date Reported, Column 1 = Organization Name
        date_val = clean_text(cells[0].get_text())
        name = clean_text(cells[1].get_text())
        if not name or name.lower().startswith("organization") or date_val.lower().startswith("date"):
            continue
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        link = None
        for cell in cells:
            a = cell.find("a", href=True)
            if a:
                link = urljoin(url, a["href"])
                break

        # Fetch detail page for additional info
        summary_parts = []
        if link:
            details = fetch_me_ag_detail(link, headers, timeout)
            time.sleep(0.3)  # Be polite to the server
            if details.get("persons_affected"):
                summary_parts.append(f"Persons affected: {details['persons_affected']}")
            if details.get("date_occurred"):
                summary_parts.append(f"Breach occurred: {details['date_occurred']}")
            if details.get("date_discovered"):
                summary_parts.append(f"Discovered: {details['date_discovered']}")
            if details.get("description"):
                summary_parts.append(f"Description: {details['description']}")
            if details.get("info_acquired"):
                summary_parts.append(f"Info acquired: {details['info_acquired']}")

        summary = " | ".join(summary_parts) if summary_parts else ""

        findings.append(
            Finding(
                source_id=source["id"],
                kind=source["kind"],
                source_url=url,
                title=name,
                url=link or url,
                published=published,
                published_dt=published_dt,
                has_time=has_time,
                summary=summary,
            )
        )
    return findings


def fetch_ftc_press(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    urls = source["urls"]
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    keywords = cfg["app"]["keywords"]
    findings: List[Finding] = []

    for url in urls:
        try:
            resp = http_get(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        soup = BeautifulSoup(resp.text, "lxml")
        anchors = soup.find_all("a", href=True)
        for a in anchors:
            href = a["href"]
            if "/news-events/news/press-releases/" not in href:
                continue
            if re.search(r"/press-releases/\d{4}$", href):
                continue
            title = clean_text(a.get_text())
            if not title:
                continue
            row = a.find_parent()
            row_text = clean_text(row.get_text(" ", strip=True)) if row else title
            date_match = DATE_RE.search(row_text)
            date_val = date_match.group(0) if date_match else ""
            published_dt = parse_datetime(date_val) if date_val else None
            has_time = has_time_label(date_val)
            published = format_dt(published_dt)
            if not keyword_hit(f"{title} {row_text}", keywords):
                continue
            findings.append(
                Finding(
                    source_id=source["id"],
                    kind=source["kind"],
                    source_url=url,
                    title=title,
                    url=urljoin(url, href),
                    published=published,
                    published_dt=published_dt,
                    has_time=has_time,
                    summary=row_text,
                )
            )
    return findings


def fetch_doj_press(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    base_url = source["url"]
    params = {"pagesize": source.get("pagesize", 50)}
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    keywords = cfg["app"]["keywords"]
    resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    results = data.get("results", [])
    findings: List[Finding] = []
    for item in results:
        title = clean_text(item.get("title", ""))
        url = item.get("url") or item.get("field_pr_url") or ""
        summary = clean_text(item.get("teaser", "") or item.get("body", ""))
        date_val = item.get("date") or item.get("created") or ""
        date_val = str(date_val)
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        if not keyword_hit(f"{title} {summary}", keywords):
            continue
        findings.append(
            Finding(
                source_id=source["id"],
                kind=source["kind"],
                source_url=base_url,
                title=title,
                url=url,
                published=published,
                published_dt=published_dt,
                has_time=has_time,
                summary=summary,
            )
        )
    return findings


def fetch_cisa_rss(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    keywords = cfg["app"]["keywords"]
    entries = parse_rss(source["urls"], headers=headers, timeout=timeout)
    findings: List[Finding] = []
    for entry in entries:
        title = clean_text(entry.get("title", ""))
        summary = clean_text(entry.get("summary", ""))
        date_val = entry.get("published", "") or entry.get("updated", "")
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        url = entry.get("link", "")
        if not keyword_hit(f"{title} {summary}", keywords):
            continue
        findings.append(
            Finding(
                source_id=source["id"],
                kind=source["kind"],
                source_url=source["urls"][0],
                title=title,
                url=url,
                published=published,
                published_dt=published_dt,
                has_time=has_time,
                summary=summary,
            )
        )
    return findings


def derive_sec_txt_url(index_url: str) -> Optional[str]:
    if not index_url:
        return None
    if index_url.endswith("-index.html"):
        return index_url.replace("-index.html", ".txt")
    return None


def sec_filing_contains_item_105(txt_url: str, headers: Dict[str, str], timeout: int) -> bool:
    try:
        max_bytes = 5_000_000
        read_bytes = 0
        with requests.get(txt_url, headers=headers, timeout=timeout, stream=True) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                read_bytes += len(chunk)
                if b"Item 1.05" in chunk or b"ITEM 1.05" in chunk:
                    return True
                if read_bytes >= max_bytes:
                    break
    except Exception:
        return False
    return False


def fetch_sec_8k_item_105(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    rss_url = source["rss_url"]
    headers = {"User-Agent": cfg["app"]["sec_user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    max_entries = source.get("max_entries", 40)
    delay = source.get("filing_check_delay_seconds", 0.5)
    entries = parse_rss([rss_url], headers=headers, timeout=timeout)
    findings: List[Finding] = []
    for entry in entries[:max_entries]:
        title = clean_text(entry.get("title", ""))
        summary = clean_text(entry.get("summary", ""))
        url = entry.get("link", "")
        date_val = entry.get("published", "") or entry.get("updated", "")
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        if "item 1.05" in (title + " " + summary).lower():
            findings.append(
                Finding(
                    source_id=source["id"],
                    kind=source["kind"],
                    source_url=rss_url,
                    title=title,
                    url=url,
                    published=published,
                    published_dt=published_dt,
                    has_time=has_time,
                    summary=summary,
                )
            )
            continue
        txt_url = derive_sec_txt_url(url)
        if txt_url and sec_filing_contains_item_105(txt_url, headers, timeout):
            findings.append(
                Finding(
                    source_id=source["id"],
                    kind=source["kind"],
                    source_url=rss_url,
                    title=title,
                    url=url,
                    published=published,
                    published_dt=published_dt,
                    has_time=has_time,
                    summary=summary,
                )
            )
        time.sleep(delay)
    return findings


def fetch_ransomware_live(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    base_url = source["base_url"].rstrip("/")
    endpoint = source["endpoint"]
    url = f"{base_url}{endpoint}"
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = cfg["app"]["request_timeout_seconds"]
    resp = http_get(url, headers=headers, timeout=timeout)
    data = resp.json()
    allowlist = set(source.get("country_allowlist", []))
    include_unknown = source.get("include_unknown_country", False)
    findings: List[Finding] = []
    for item in data:
        country = (item.get("country") or "").upper()
        if country:
            if country not in allowlist:
                continue
        elif not include_unknown:
            continue
        # Support both old and new API field names
        victim = clean_text(item.get("post_title") or item.get("victim", ""))
        if not victim:
            continue
        date_val = str(item.get("discovered") or item.get("published") or item.get("attackdate") or "")
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        link = item.get("post_url") or item.get("url") or item.get("post") or ""

        # Build detailed summary
        summary_parts = []
        group = clean_text(item.get("group_name") or item.get("group", ""))
        if group:
            summary_parts.append(f"Ransomware group: {group}")
        if country:
            summary_parts.append(f"Country: {country}")
        activity = clean_text(item.get("activity", ""))
        if activity:
            summary_parts.append(f"Sector: {activity}")
        website = clean_text(item.get("website", ""))
        if website:
            summary_parts.append(f"Website: {website}")
        description = clean_text(item.get("description", ""))
        if description:
            summary_parts.append(f"Description: {description}")
        extrainfos = item.get("extrainfos") or {}
        if isinstance(extrainfos, dict):
            data_size = clean_text(str(extrainfos.get("data_size", "")))
            if data_size:
                summary_parts.append(f"Data size: {data_size}")
            ransom = clean_text(str(extrainfos.get("ransom", "")))
            if ransom:
                summary_parts.append(f"Ransom: {ransom}")
        summary = " | ".join(summary_parts)

        findings.append(
            Finding(
                source_id=source["id"],
                kind=source["kind"],
                source_url=url,
                title=victim,
                url=link or base_url,
                published=published,
                published_dt=published_dt,
                has_time=has_time,
                summary=summary,
            )
        )
    return findings


def extract_data_attributes(element) -> Dict[str, str]:
    """Extract information from HTML data-* attributes."""
    details = {}
    for attr, field in DATA_ATTR_MAPPING.items():
        if element.has_attr(attr):
            value = clean_text(element[attr])
            if value and field not in details:
                details[field] = value
    return details


def extract_victim_name(element) -> Optional[str]:
    """Extract victim/company name from an HTML element."""
    # Try heading tags first
    for tag in element.find_all(["h1", "h2", "h3", "h4", "h5", "strong", "b"]):
        text = clean_text(tag.get_text())
        if 3 < len(text) < 100:
            if not any(skip in text.lower() for skip in SKIP_WORDS):
                return text

    # Try data-* attributes
    for attr in ["data-name", "data-company", "data-victim", "data-title"]:
        if element.has_attr(attr):
            return clean_text(element[attr])

    # Fallback to full element text (truncated)
    text = clean_text(element.get_text())
    if 3 < len(text) < 200:
        if not any(skip in text.lower() for skip in SKIP_WORDS):
            return text[:100]

    return None


def extract_victim_details(element) -> Dict[str, str]:
    """Extract detailed information from a victim entry element."""
    details = {}
    el_text = element.get_text()
    el_text_lower = el_text.lower()

    # 1. Extract from data-* attributes first
    details.update(extract_data_attributes(element))

    # 2. Extract website from href attributes or text
    if not details.get("website"):
        for a in element.find_all("a", href=True):
            href = a["href"]
            if ".onion" not in href and href.startswith("http"):
                details["website"] = href
                break
        if not details.get("website"):
            match = DOMAIN_RE.search(el_text)
            if match:
                details["website"] = match.group(1)

    # 3. Extract data size
    if not details.get("data_size"):
        match = DATA_SIZE_RE.search(el_text)
        if match:
            details["data_size"] = f"{match.group(1)} {match.group(2).upper()}"

    # 4. Extract country
    if not details.get("country"):
        match = COUNTRY_RE.search(el_text)
        if match:
            country_text = match.group(1).strip().lower()
            details["country"] = COUNTRY_CODES.get(country_text, country_text.upper()[:3])
        else:
            # Check for country names in text
            for country_name, code in COUNTRY_CODES.items():
                if country_name in el_text_lower:
                    details["country"] = code
                    break

    # 5. Extract sector/industry
    if not details.get("sector"):
        match = SECTOR_RE.search(el_text)
        if match:
            details["sector"] = clean_text(match.group(1))
        else:
            # Keyword-based detection
            for sector in SECTOR_KEYWORDS:
                if sector in el_text_lower:
                    details["sector"] = sector.title()
                    break

    # 6. Extract description (look for longer text blocks)
    if not details.get("description"):
        for tag in element.find_all(["p", "div", "span"]):
            text = clean_text(tag.get_text())
            if 20 < len(text) < 500:
                if not any(skip in text.lower() for skip in ["download", "click here", "view more"]):
                    details["description"] = text[:200]
                    break

    # 7. Extract deadline
    if not details.get("deadline"):
        match = DEADLINE_RE.search(el_text)
        if match:
            details["deadline"] = clean_text(match.group(1))

    # 8. Extract post date
    if not details.get("post_date"):
        match = POST_DATE_RE.search(el_text)
        if match:
            details["post_date"] = match.group(1)

    # 9. Detect data types compromised
    data_types_found = []
    for dtype, keywords in DATA_TYPE_INDICATORS.items():
        if any(kw in el_text_lower for kw in keywords):
            data_types_found.append(dtype.upper())
    if data_types_found:
        details["data_types"] = ", ".join(data_types_found[:4])

    return details


def build_victim_summary(victim: Dict, group_name: str) -> str:
    """Build pipe-delimited summary from victim details."""
    summary_parts = []

    # Always include ransomware group
    summary_parts.append(f"Ransomware group: {group_name}")

    # Add country if available
    if victim.get("country"):
        summary_parts.append(f"Country: {victim['country']}")

    # Add sector/industry
    if victim.get("sector"):
        summary_parts.append(f"Sector: {victim['sector']}")

    # Add website
    if victim.get("website"):
        summary_parts.append(f"Website: {victim['website']}")

    # Add data size
    if victim.get("data_size"):
        summary_parts.append(f"Data size: {victim['data_size']}")

    # Add data types compromised
    if victim.get("data_types"):
        summary_parts.append(f"Data types: {victim['data_types']}")

    # Add deadline if present
    if victim.get("deadline"):
        summary_parts.append(f"Deadline: {victim['deadline']}")

    # Add description (truncated)
    if victim.get("description"):
        desc = victim["description"][:100]
        if len(victim["description"]) > 100:
            desc += "..."
        summary_parts.append(f"Description: {desc}")

    # Always add source indicator
    summary_parts.append("Source: Dark web leak site")

    return " | ".join(summary_parts)


def parse_leak_site_victims(html: str, group_name: str, site_url: str) -> List[Dict]:
    """Extract victim entries from a ransomware leak site HTML page."""
    soup = BeautifulSoup(html, "lxml")
    victims = []

    # Common patterns across leak sites:
    # 1. Card/box layouts with company names
    # 2. Table rows with victim info
    # 3. List items with links

    # Try finding cards/boxes (common in modern leak sites)
    for selector in [
        "div.card", "div.post", "div.victim", "div.target",
        "article", "div.item", "div.entry", "div.blog-post",
        "div.leak", "div.company", "tr", "li.victim"
    ]:
        elements = soup.select(selector)
        if len(elements) >= 3:  # Likely found the victim list
            for el in elements[:50]:  # Limit to avoid huge lists
                # Extract victim name using helper
                name = extract_victim_name(el)
                if not name:
                    continue

                # Extract detailed information
                details = extract_victim_details(el)

                victims.append({
                    "name": name,
                    "group": group_name,
                    "url": site_url,
                    **details,  # Merge extracted details
                })
            if victims:
                break

    # Fallback: look for text that looks like company names
    if not victims:
        # Find all text nodes that look like company names
        for tag in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b", "a"]):
            name = extract_victim_name(tag)
            if not name:
                continue

            # Extract details from parent element if available
            parent = tag.parent
            details = extract_victim_details(parent) if parent else {}

            victims.append({
                "name": name,
                "group": group_name,
                "url": site_url,
                **details,
            })
            if len(victims) >= 30:
                break

    return victims


def fetch_darkweb_leak_sites(source: Dict[str, Any], cfg: Dict[str, Any]) -> List[Finding]:
    """Directly scrape ransomware leak sites via Tor."""
    headers = {"User-Agent": cfg["app"]["user_agent"]}
    timeout = source.get("tor_timeout_seconds", 60)
    request_delay = source.get("request_delay_seconds", 2)
    max_sites = source.get("max_sites_per_run", 20)
    target_groups = set(g.lower() for g in source.get("groups", []))

    # Load current group list from ransomwatch
    try:
        groups = load_ransomwatch_groups(headers, cfg["app"]["request_timeout_seconds"])
    except Exception:
        return []

    findings: List[Finding] = []
    sites_checked = 0

    for group in groups:
        group_name = group.get("name", "")
        if target_groups and group_name.lower() not in target_groups:
            continue

        for location in group.get("locations", []):
            if sites_checked >= max_sites:
                break

            # Only try available and enabled onion sites
            if not location.get("available") or not location.get("enabled"):
                continue
            if location.get("version", 0) < 2:  # Skip clearnet (version 0)
                continue

            onion_url = location.get("slug", "")
            if not onion_url or ".onion" not in onion_url:
                continue

            try:
                resp = http_get_tor(onion_url, headers, timeout)
                victims = parse_leak_site_victims(resp.text, group_name, onion_url)

                now = datetime.now(timezone.utc)
                for victim in victims:
                    # Use extracted post_date if available, otherwise use current time
                    if victim.get("post_date"):
                        published_dt = parse_datetime(victim["post_date"])
                        has_time = has_time_label(victim["post_date"])
                        # Fall back to now if parsing fails
                        if not published_dt:
                            published_dt = now
                            has_time = True
                    else:
                        published_dt = now
                        has_time = True
                    published = format_dt(published_dt)

                    # Build rich summary with all extracted details
                    summary = build_victim_summary(victim, group_name)

                    findings.append(
                        Finding(
                            source_id=source["id"],
                            kind=source["kind"],
                            source_url=onion_url,
                            title=victim["name"],
                            url=onion_url,
                            published=published,
                            published_dt=published_dt,
                            has_time=has_time,
                            summary=summary,
                        )
                    )

                sites_checked += 1
            except Exception:
                # Onion sites are unreliable, continue to next
                pass

            time.sleep(request_delay)

        if sites_checked >= max_sites:
            break

    return findings


def collect_findings(cfg: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for source in cfg["sources"]:
        source_type = source["type"]
        try:
            if source_type == "hhs_ocr":
                findings.extend(fetch_hhs_ocr(source, cfg))
            elif source_type == "ca_ag":
                findings.extend(fetch_ca_ag(source, cfg))
            elif source_type == "me_ag":
                findings.extend(fetch_me_ag(source, cfg))
            elif source_type == "ftc_press":
                findings.extend(fetch_ftc_press(source, cfg))
            elif source_type == "doj_press":
                findings.extend(fetch_doj_press(source, cfg))
            elif source_type == "rss":
                findings.extend(fetch_cisa_rss(source, cfg))
            elif source_type == "sec_8k_item_105":
                findings.extend(fetch_sec_8k_item_105(source, cfg))
            elif source_type == "ransomware_live":
                findings.extend(fetch_ransomware_live(source, cfg))
            elif source_type == "darkweb_leak_site":
                findings.extend(fetch_darkweb_leak_sites(source, cfg))
        except Exception:
            continue
    return findings


def load_smtp_settings() -> Dict[str, str]:
    load_dotenv()
    settings = {
        "host": os.getenv("SMTP_HOST", ""),
        "port": os.getenv("SMTP_PORT", "587"),
        "user": os.getenv("SMTP_USER", ""),
        "pass": os.getenv("SMTP_PASS", ""),
        "from_name": os.getenv("SMTP_FROM_NAME", "Breach Notifier"),
        "from_email": os.getenv("SMTP_FROM_EMAIL", ""),
        "to_email": os.getenv("SMTP_TO_EMAIL", ""),
    }
    missing = [k for k, v in settings.items() if not v and k not in ("from_name",)]
    if missing:
        raise RuntimeError(f"Missing SMTP settings: {', '.join(missing)}")
    return settings


def send_email(settings: Dict[str, str], findings: List[Finding]) -> None:
    msg = EmailMessage()
    count = len(findings)
    msg["Subject"] = f"[Breach Alert] {count} new data breach{'es' if count != 1 else ''} found"
    msg["From"] = f"{settings['from_name']} <{settings['from_email']}>"
    msg["To"] = settings["to_email"]

    sections = []
    for i, finding in enumerate(findings, 1):
        section = "\n".join(
            [
                f"{'=' * 60}",
                f"#{i}: {finding.title}",
                f"{'=' * 60}",
                f"Source: {finding.source_id}",
                f"Source URL: {finding.source_url}",
                f"Type: {finding.kind}",
                f"Published: {finding.published or 'unknown'}",
                f"URL: {finding.url}",
                f"Summary: {finding.summary}",
            ]
        )
        sections.append(section)

    body = f"Daily Data Breach Report - {count} new finding{'s' if count != 1 else ''}\n\n"
    body += "\n\n".join(sections)
    msg.set_content(body)

    import smtplib

    with smtplib.SMTP(settings["host"], int(settings["port"])) as server:
        server.starttls()
        server.login(settings["user"], settings["pass"])
        server.send_message(msg)


def main() -> None:
    config_path = os.environ.get("BREACH_CONFIG", "config.yaml")
    cfg = load_config(config_path)
    seen_path = cfg["app"]["seen_store"]
    seen = load_seen(seen_path)
    findings = collect_findings(cfg)
    new_findings = []
    now = datetime.now(timezone.utc)
    for finding in findings:
        fid = finding.uid()
        if fid in seen:
            continue
        if not finding.published_dt:
            continue
        # Skip future dates (likely data errors)
        if finding.published_dt > now:
            continue
        if finding.has_time:
            if now - finding.published_dt > timedelta(hours=24):
                continue
        else:
            if (now.date() - finding.published_dt.date()).days > 1:
                continue
        seen.add(fid)
        new_findings.append(finding)
        if len(new_findings) >= cfg["app"]["max_new_per_run"]:
            break

    if not new_findings:
        save_seen(seen_path, seen)
        return

    smtp = load_smtp_settings()
    send_email(smtp, new_findings)

    save_seen(seen_path, seen)


if __name__ == "__main__":
    main()
