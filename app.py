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
            state = clean_text(row.get("State") or "")
            affected = clean_text(row.get("Individuals Affected") or "")
            summary = f"State: {state} | Individuals affected: {affected}".strip(" |")
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
                or row.get("Date(s) of Breach")
                or ""
            )
            published_dt = parse_datetime(date_val)
            has_time = has_time_label(date_val)
            published = format_dt(published_dt)
            notice_url = link_map.get(name, url)
            summary = clean_text(
                " | ".join(
                    filter(
                        None,
                        [
                            row.get("Type of Breach"),
                            row.get("Type of Information"),
                            row.get("Notice Provided to"),
                        ],
                    )
                )
            )
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
        name = clean_text(cells[0].get_text())
        if not name or name.lower().startswith("company"):
            continue
        date_val = clean_text(cells[1].get_text())
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        link = None
        for cell in cells:
            a = cell.find("a", href=True)
            if a:
                link = urljoin(url, a["href"])
                break
        summary = clean_text(" ".join(c.get_text() for c in cells[2:]))
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
        victim = clean_text(item.get("victim", ""))
        if not victim:
            continue
        date_val = str(item.get("discovered") or item.get("attackdate") or "")
        published_dt = parse_datetime(date_val)
        has_time = has_time_label(date_val)
        published = format_dt(published_dt)
        group = clean_text(item.get("group", ""))
        link = item.get("url") or item.get("post") or ""
        summary = clean_text(f"Group: {group} | Country: {country}")
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
