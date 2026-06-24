import html, io, json, re, urllib.parse
from collections import Counter
from typing import List
import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="WaybackBlueApp PII PRO", page_icon="🔎", layout="wide")
st.markdown("""
<style>
.main{background:#F5F9FF}.block-container{padding-top:2rem}.hero{background:linear-gradient(135deg,#fff 0%,#F5FAFF 60%,#EAF4FF 100%);border:1px solid #DCE8F6;border-radius:22px;padding:28px;box-shadow:0 12px 30px rgba(16,32,51,.08);margin-bottom:20px}.title{font-size:34px;font-weight:800;color:#102033;letter-spacing:-.04em}.subtitle{color:#62738A;font-size:15px;margin-top:4px}.pill{display:inline-block;background:#E8F2FF;color:#0A4FA8;border:1px solid #CFE3FF;border-radius:999px;padding:6px 10px;font-family:monospace;font-size:12px;margin-top:12px}.warning-box{border:1px solid #F3C8C8;background:#FFF6F6;color:#C43D3D;padding:12px;border-radius:14px;font-weight:700}.good-box{border:1px solid #BDE8D7;background:#F3FFF9;color:#12805C;padding:12px;border-radius:14px;font-weight:700}
</style>""", unsafe_allow_html=True)

HEADERS = {"User-Agent": "Mozilla/5.0 WaybackBlueAppStreamlitBulk/2.0", "Accept": "*/*"}

# ---------- Auth ----------
def valid_keys():
    try:
        keys = st.secrets.get("APP_KEYS", [])
        return [keys] if isinstance(keys, str) else list(keys)
    except Exception:
        return []

def require_key():
    keys = valid_keys()
    st.sidebar.header("Access")
    key = st.sidebar.text_input("API Key", type="password")
    if not keys:
        st.sidebar.warning("No APP_KEYS configured. Local dev mode.")
        return True
    if key in keys:
        st.sidebar.success("Access granted")
        return True
    st.sidebar.error("Enter a valid API key.")
    return False

# ---------- Wayback ----------
TWITTER_DOMAINS = {"twitter.com", "x.com", "mobile.twitter.com", "www.twitter.com", "www.x.com"}

def build_targets(raw: str) -> List[str]:
    raw = raw.strip()
    if not raw:
        return []
    # Full URL: strip scheme, then fall through to the same domain-aware logic below.
    if re.match(r"^https?://", raw, re.I):
        u = urllib.parse.urlparse(raw)
        netloc = u.netloc.replace("www.", "")
        path = u.path.rstrip("/")
        candidate = netloc + path
    elif "." in raw and "/" in raw:
        candidate = re.sub(r"^https?://", "", raw, flags=re.I).replace("www.", "").rstrip("/")
    elif "." in raw and "/" not in raw:
        return [re.sub(r"^https?://", "", raw, flags=re.I).replace("www.", "").rstrip("/")]
    else:
        h = raw.lstrip("@").strip()
        return [f"x.com/{h}", f"twitter.com/{h}", f"mobile.twitter.com/{h}"] if h else []

    # candidate is "domain/path...". If the domain is a known Twitter/X variant,
    # expand to all variants so a handle captured under x.com isn't missed when the
    # person typed twitter.com (or vice versa) - this was silently dropping results.
    parts = candidate.split("/", 1)
    domain = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    if domain in TWITTER_DOMAINS and rest:
        return [f"x.com/{rest}", f"twitter.com/{rest}", f"mobile.twitter.com/{rest}"]
    return [candidate] if candidate else []

def snapshot_url(ts, original, raw=True):
    return f"https://web.archive.org/web/{ts}{'id_/' if raw else '/'}{original}"

def fmt_ts(ts):
    if not ts or len(ts) < 8:
        return ts
    hh = ts[8:10] if len(ts) >= 10 else "00"
    mm = ts[10:12] if len(ts) >= 12 else "00"
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {hh}:{mm} UTC"

@st.cache_data(ttl=3600, show_spinner=False)
def http_text(url):
    r = requests.get(url, headers=HEADERS, timeout=45)
    r.raise_for_status()
    if not r.encoding:
        r.encoding = "utf-8"
    return r.text

def _cdx_request(params, attempts=3):
    """Low-level CDX call with basic retry on transient failures (timeouts, 429s, bad JSON)."""
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    last_err = None
    for attempt in range(attempts):
        try:
            r = requests.get(url, headers=HEADERS, timeout=60)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                return []
            return data
        except Exception as e:
            last_err = e
            if attempt < attempts - 1:
                continue
    raise RuntimeError(f"CDX request failed after {attempts} attempt(s): {last_err}") from last_err

def _rows_from_cdx(data, target, search_mode):
    if len(data) < 2:
        return []
    header = data[0]
    rows = []
    for row in data[1:]:
        obj = dict(zip(header, row))
        obj["target"] = target
        obj["search_mode"] = search_mode
        rows.append(obj)
    return rows

@st.cache_data(ttl=1800, show_spinner=False)
def cdx_search_exact(target, limit=5000, fields="timestamp,original,mimetype,statuscode,digest,length"):
    """Step 1: exact match on the target itself - mirrors a normal Wayback URL lookup.
    This intentionally does NOT use matchType=prefix, so a target with no capture
    of its own (but with many captures under it, e.g. /status/... pages) correctly
    returns 0 here and triggers the prefix fallback below.
    No statuscode filter: some real captures report '-' instead of '200' and would
    otherwise be silently dropped."""
    params = {"url": target, "matchType": "exact", "output": "json", "fl": fields,
              "collapse": "digest", "limit": str(limit)}
    data = _cdx_request(params)
    return _rows_from_cdx(data, target, "direct_capture")

@st.cache_data(ttl=1800, show_spinner=False)
def cdx_search_prefix(target, limit=10000, fields="original,mimetype,timestamp,statuscode,digest,length"):
    """Step 2: prefix match - mirrors Wayback's 'Click here to search for all archived
    pages under this URL' behavior, returning every URL captured under the prefix.
    Deliberately does NOT filter by statuscode: many real captures (e.g. JSON API
    responses crawled without a recorded HTTP status) report statuscode '-' rather
    than '200', and filtering them out was silently dropping legitimate results."""
    params = {"url": target, "matchType": "prefix", "output": "json", "fl": fields,
              "collapse": "urlkey", "limit": str(limit)}
    data = _cdx_request(params)
    return _rows_from_cdx(data, target, "url_index_fallback")

def _dedupe(rows, key_fn):
    seen, out = set(), []
    for r in rows:
        k = key_fn(r)
        if k and k not in seen:
            seen.add(k)
            out.append(r)
    return out

def search_all(targets, fallback=True):
    """Step 1 for every target variant (exact). If ALL variants come back empty,
    fall back to step 2 (prefix) for every variant, exactly mirroring what a human
    clicking the Wayback 'search all archived pages under this URL prefix' link would see."""
    rows, errors = [], []
    for t in targets:
        try:
            rows.extend(cdx_search_exact(t))
        except Exception as e:
            errors.append({"target": t, "phase": "direct_exact", "error": str(e)})
    direct = _dedupe(rows, lambda r: (r.get("timestamp"), r.get("original")))
    direct.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    meta = {"direct_count": len(direct), "fallback_used": False, "fallback_count": 0, "fallback_attempted": False}
    if direct or not fallback:
        return direct, errors, meta
    meta["fallback_attempted"] = True
    fb = []
    for t in targets:
        try:
            fb.extend(cdx_search_prefix(t))
        except Exception as e:
            errors.append({"target": t, "phase": "url_index_fallback_prefix", "error": str(e)})
    out = _dedupe(fb, lambda r: r.get("original"))
    out.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    meta.update({"fallback_used": bool(out), "fallback_count": len(out)})
    return out, errors, meta

# ---------- PII extraction ----------
FALSE_NAMES = {"Something Went Wrong", "Try Again", "Enhanced Tracking Protection", "Internet Archive", "Wayback Machine", "Privacy Policy", "Terms Conditions", "Contact Us", "Page Not Found", "Access Denied"}
GENERIC = {"home", "about", "contact", "privacy", "terms", "login", "signup", "search", "follow", "share", "archive", "wayback", "machine", "javascript", "browser", "error", "something", "wrong", "again"}

def clean_text(raw):
    x = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", raw)
    x = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", x)
    x = re.sub(r"(?is)<noscript\b[^>]*>.*?</noscript>", " ", x)
    x = re.sub(r"(?is)<svg\b[^>]*>.*?</svg>", " ", x)
    x = re.sub(r"(?is)<iframe\b[^>]*>.*?</iframe>", " ", x)
    x = re.sub(r"(?is)<!--.*?-->", " ", x)
    x = re.sub(r"(?is)<br\s*/?>", "\n", x)
    x = re.sub(r"(?is)</(p|div|li|h1|h2|h3|h4|tr|td|section|article)>", "\n", x)
    x = re.sub(r"(?is)<[^>]+>", " ", x)
    text = html.unescape(x)
    text = re.sub(r"https?://web\.archive\.org/web/\d+[a-z_]*?/", "", text)
    text = text.replace("\u00a0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def html_signals(raw):
    sig = {"title": [], "meta": [], "mailto": [], "tel": [], "links": [], "jsonld": [], "alt": []}
    for m in re.finditer(r"(?is)<title[^>]*>(.*?)</title>", raw):
        sig["title"].append(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))).strip())
    for m in re.finditer(r'''(?is)<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]*content=["'](.*?)["']''', raw):
        sig["meta"].append({"key": html.unescape(m.group(1)), "value": html.unescape(m.group(2))})
    for m in re.finditer(r'''(?is)<a[^>]+href=["']mailto:([^"']+)["']''', raw):
        sig["mailto"].append(html.unescape(urllib.parse.unquote(m.group(1))).split("?")[0])
    for m in re.finditer(r'''(?is)<a[^>]+href=["']tel:([^"']+)["']''', raw):
        sig["tel"].append(html.unescape(urllib.parse.unquote(m.group(1))))
    for m in re.finditer(r'''(?is)<a[^>]+href=["']([^"']+)["']''', raw):
        href = html.unescape(m.group(1)).strip()
        if href and not href.startswith("#") and len(href) < 500:
            sig["links"].append(href)
    for m in re.finditer(r'''(?is)<(?:img|a|span|div|button)[^>]+(?:alt|title|aria-label)=["']([^"']{2,200})["']''', raw):
        sig["alt"].append(html.unescape(m.group(1)).strip())
    for m in re.finditer(r'''(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>''', raw):
        try:
            sig["jsonld"].append(json.loads(html.unescape(m.group(1)).strip()))
        except Exception:
            pass
    return sig

def evidence(text, value, radius=150):
    if not value:
        return ""
    i = text.lower().find(str(value).lower())
    if i < 0:
        return ""
    return re.sub(r"\s+", " ", text[max(0, i - radius):min(len(text), i + len(str(value)) + radius)]).strip()

def norm_phone(raw):
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 8 or len(digits) > 16:
        return ""
    if len(set(digits)) <= 2:
        return ""
    return raw.strip()

def add(findings, ftype, value, text, conf="medium", source="text", subtype="", count=None):
    value = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n,;|()[]{}<>")
    if not value:
        return
    if ftype in {"likely_person_name", "likely_location", "likely_organization"}:
        if value in FALSE_NAMES or len(value) > 120:
            return
        parts = [p.lower() for p in re.findall(r"[A-Za-z]+", value)]
        if parts and all(p in GENERIC for p in parts):
            return
    key = (ftype, value.lower())
    for f in findings:
        if (f["type"], f["value"].lower()) == key:
            if source not in f["sources"]:
                f["sources"].append(source)
            order = {"low": 1, "medium": 2, "high": 3}
            if order.get(conf, 1) > order.get(f.get("confidence", "low"), 1):
                f["confidence"] = conf
            return
    findings.append({"type": ftype, "subtype": subtype, "value": value, "confidence": conf, "sources": [source], "evidence": evidence(text, value), **({"count": count} if count else {})})

def flatten_jsonld(obj):
    out = []
    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                lk = str(k).lower()
                if lk in {"name", "givenname", "familyname", "email", "telephone", "faxnumber", "address", "streetaddress", "addresslocality", "addressregion", "postalcode", "addresscountry", "sameas", "url", "jobtitle", "worksfor", "affiliation"}:
                    out.append((lk, v))
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)
    walk(obj)
    return out

def detect_bad(text):
    low = text.lower()
    markers = ["something went wrong", "try again", "enhanced tracking protection", "strict mode", "known to cause issues", "this browser is no longer supported", "enable javascript", "access denied", "forbidden", "page not found"]
    hits = [m for m in markers if m in low]
    if len(hits) >= 2:
        return {"unusable": True, "reason": "error_shell", "message": "The archived capture appears to be an error shell, not real page content.", "markers": hits}
    if len(text.strip()) < 80:
        return {"unusable": True, "reason": "empty_or_too_short", "message": "The archived capture has almost no readable text.", "markers": []}
    return {"unusable": False}

def analyze_html(raw):
    sig = html_signals(raw)
    text = "\n".join(sig["title"] + [m["value"] for m in sig["meta"]] + sig["alt"] + [clean_text(raw)]).strip()
    quality = detect_bad(text)
    if quality.get("unusable"):
        return {"snapshot_quality": quality, "risk": "unusable", "total_findings": 0, "grouped": {}, "findings": [], "top_words": [], "raw_text": text[:120000], "raw_text_length": len(text), "extraction_version": "streamlit_bulk_excel_v2"}
    findings = []
    def cf_decode(h):
        try:
            r = int(h[:2], 16)
            return "".join(chr(int(h[i:i+2], 16) ^ r) for i in range(2, len(h), 2))
        except Exception:
            return ""
    for h in re.findall(r"/cdn-cgi/l/email-protection#([a-fA-F0-9]+)", raw):
        e = cf_decode(h)
        if e:
            add(findings, "email", e, text, "high", "cloudflare_decoded")
    for e in sig["mailto"]:
        add(findings, "email", e, text, "high", "mailto")
    for p in sig["tel"]:
        np = norm_phone(p)
        if np:
            add(findings, "phone", np, text, "high", "tel_link")
    for e in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, re.I):
        add(findings, "email", e, text, "high", "text")
    for m in re.finditer(r"\b([A-Z0-9._%+-]{2,})\s*(?:\[at\]|\(at\)| at )\s*([A-Z0-9.-]{2,})\s*(?:\[dot\]|\(dot\)| dot )\s*([A-Z]{2,})\b", text, re.I):
        add(findings, "email", f"{m.group(1)}@{m.group(2)}.{m.group(3)}", text, "medium", "obfuscated_email")
    for p in re.findall(r"(?:\+?\d[\d\s().-]{7,}\d)", text):
        np = norm_phone(p)
        if np:
            ev = evidence(text, np, 80).lower()
            conf = "high" if any(k in ev for k in ["phone", "tel", "mobile", "call", "fax", "contact"]) else "medium"
            add(findings, "phone", np, text, conf, "text")
    urls = list(dict.fromkeys(re.findall(r'''https?://[^\s"'<>]+''', text, re.I) + [u for u in sig["links"] if u.startswith("http")]))
    socials = ["linkedin.com", "facebook.com", "instagram.com", "youtube.com", "tiktok.com", "github.com", "x.com", "twitter.com", "threads.net", "telegram.me", "t.me"]
    for u in urls:
        subtype = "social_profile_or_link" if any(d in u.lower() for d in socials) else ""
        add(findings, "url", u, text, "high" if subtype else "medium", "href_or_text", subtype)
    for h in re.findall(r"(?<![A-Za-z0-9_])@[A-Za-z0-9_]{2,30}", text):
        add(findings, "handle_or_username", h, text, "medium", "text")
    for ip in list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))):
        parts = [int(x) for x in ip.split(".") if x.isdigit()]
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            add(findings, "ip_address", ip, text, "medium", "text")
    for pat in [r"\b\d{1,6}\s+[A-Z][A-Za-z0-9.'-]*(?:\s+[A-Z][A-Za-z0-9.'-]*){0,6}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Highway|Hwy|Parkway|Pkwy|Square|Sq)\b(?:,?\s+[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+)*)?(?:,?\s+[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?", r"\bP\.?\s*O\.?\s*Box\s+\d{1,8}\b(?:,?\s+[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+)*)?(?:,?\s+[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?"]:
        for a in re.findall(pat, text):
            add(findings, "address", a, text, "medium", "text")
    for d in re.findall(r"(?:date of birth|dob|born|birthdate|birthday)\s*[:\-]?\s*([A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4}|\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})", text, re.I):
        add(findings, "possible_date_of_birth", d, text, "medium", "labeled_text")
    for obj in sig["jsonld"]:
        for key, val in flatten_jsonld(obj):
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if isinstance(v, dict):
                    fields = [str(v[k]) for k in ["streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry", "name"] if k in v]
                    if fields:
                        add(findings, "address" if "address" in key else "likely_location", ", ".join(fields), text, "high", "jsonld")
                    continue
                v = str(v)
                if key == "email": add(findings, "email", v, text, "high", "jsonld")
                elif key in {"telephone", "faxnumber"}:
                    np = norm_phone(v)
                    if np: add(findings, "phone", np, text, "high", "jsonld")
                elif key in {"name", "givenname", "familyname"}: add(findings, "likely_person_name", v, text, "high", "jsonld")
                elif key in {"streetaddress", "address", "addresslocality", "addressregion", "postalcode", "addresscountry"}: add(findings, "likely_location", v, text, "high", "jsonld")
                elif key in {"sameas", "url"}: add(findings, "url", v, text, "high", "jsonld")
    for ftype, pat, conf in [("likely_person_name", r"(?:name|full name|owner|author|contact person|profile)\s*[:\-]\s*([A-Z][^\n,|]{2,90})", "medium"), ("likely_location", r"(?:location|address|city|based in|located in|from)\s*[:\-]\s*([^\n]{3,120})", "medium"), ("likely_organization", r"(?:company|organization|employer|works at|business)\s*[:\-]\s*([^\n]{3,120})", "medium")]:
        for v in re.findall(pat, text, re.I):
            add(findings, ftype, v, text, conf, "labeled_text")
    candidates = re.findall(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b", "\n".join(sig["title"] + [m["value"] for m in sig["meta"]] + [clean_text(raw)]))
    for v, c in Counter(candidates).most_common(60):
        if any(x in v.lower() for x in ["privacy policy", "terms", "read more", "contact us", "wayback machine"]):
            continue
        add(findings, "likely_person_name", v, text, "medium" if c >= 2 else "low", "capitalized_sequence", count=c)
    for v, c in Counter(re.findall(r"\b[A-Z][a-z]+,\s*(?:[A-Z]{2}|[A-Z][a-z]+)\b", text)).most_common(50):
        add(findings, "likely_location", v, text, "medium" if c >= 2 else "low", "city_region_pattern", count=c)
    org_re = r"\b[A-Z][A-Za-z&.'-]*(?:\s+[A-Z][A-Za-z&.'-]*){0,4}\s+(?:Inc|LLC|Ltd|GmbH|Company|Co|Club|Association|University|School|Church|Synagogue|Cycles|Motorcycles|Foundation|Agency|Department|Institute|Group|Partners)\b"
    for v, c in Counter(re.findall(org_re, text)).most_common(60):
        add(findings, "likely_organization", v, text, "medium", "org_suffix", count=c)
    grouped = {}
    for f in findings:
        grouped.setdefault(f["type"], []).append(f)
    strong = {"email", "phone", "address", "possible_date_of_birth", "handle_or_username", "ip_address"}
    high = sum(1 for f in findings if f["type"] in strong and f.get("confidence") == "high")
    med = sum(1 for f in findings if f["type"] in strong and f.get("confidence") == "medium")
    score = high * 2 + med
    risk = "high" if score >= 6 else "medium" if score >= 3 else "low" if score >= 1 else "none"
    stop = GENERIC | {"the", "and", "for", "with", "from", "this", "that", "you", "your", "are", "was", "were", "have", "has", "not", "but", "http", "https", "www", "com", "org", "net", "html", "mobile"}
    words = [w.lower() for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9'_-]{2,}", text) if w.lower() not in stop]
    return {"snapshot_quality": {"unusable": False}, "risk": risk, "total_findings": len(findings), "grouped": grouped, "findings": findings, "top_words": Counter(words).most_common(100), "raw_text": text[:120000], "raw_text_length": len(text), "extraction_version": "streamlit_bulk_excel_v2"}

# ---------- Excel ----------
def build_excel(captures_rows, analyses, errors):
    captures_df = pd.DataFrame(captures_rows)
    summary, findings = [], []
    for item in analyses:
        row = item["capture"]
        a = item["analysis"]
        summary.append({"timestamp": row.get("timestamp", ""), "date": fmt_ts(row.get("timestamp", "")), "original": row.get("original", ""), "mimetype": row.get("mimetype", ""), "search_mode": row.get("search_mode", ""), "risk": a.get("risk", ""), "total_findings": a.get("total_findings", 0), "unusable": a.get("snapshot_quality", {}).get("unusable", False), "raw_text_length": a.get("raw_text_length", 0)})
        for f in a.get("findings", []):
            findings.append({"timestamp": row.get("timestamp", ""), "date": fmt_ts(row.get("timestamp", "")), "original": row.get("original", ""), "mimetype": row.get("mimetype", ""), "search_mode": row.get("search_mode", ""), "risk": a.get("risk", ""), "type": f.get("type", ""), "subtype": f.get("subtype", ""), "value": f.get("value", ""), "confidence": f.get("confidence", ""), "sources": " | ".join(f.get("sources", [])), "evidence": f.get("evidence", "")})
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        captures_df.to_excel(writer, sheet_name="captures", index=False)
        pd.DataFrame(summary).to_excel(writer, sheet_name="summary", index=False)
        pd.DataFrame(findings).to_excel(writer, sheet_name="pii_findings", index=False)
        pd.DataFrame(errors).to_excel(writer, sheet_name="errors", index=False)
        for sheet in writer.book.worksheets:
            sheet.freeze_panes = "A2"
            for col in sheet.columns:
                letter = col[0].column_letter
                max_len = 0
                for cell in col[:100]:
                    max_len = max(max_len, len(str(cell.value or "")))
                sheet.column_dimensions[letter].width = min(max(max_len + 2, 12), 60)
    return out.getvalue()

# ---------- UI ----------
st.markdown('<div class="hero"><div class="title">WaybackBlueApp PII PRO</div><div class="subtitle">Search archived captures, fallback to URL-index results, and export bulk PII findings to Excel.</div><div class="pill">STREAMLIT · WAYBACK CDX · BULK EXCEL</div></div>', unsafe_allow_html=True)
if not require_key():
    st.stop()
for k, v in {"captures": [], "targets": [], "search_meta": {}, "bulk_results": [], "bulk_errors": []}.items():
    if k not in st.session_state:
        st.session_state[k] = v
query = st.text_input("Handle, username, domain, or full URL", placeholder="@example_user | example_user | example.com/profile | https://site.com/page")
fallback_enabled = st.checkbox("If direct captures are not found, search archived URLs under this prefix", value=True, help="Mimics Wayback: Click here to search for all archived pages under this URL.")
if st.button("Search captures", type="primary"):
    targets = build_targets(query)
    st.session_state.targets = targets
    st.session_state.bulk_results = []
    st.session_state.bulk_errors = []
    if not targets:
        st.error("Enter a username, handle, domain, or URL.")
    else:
        with st.spinner("Fetching Wayback capture index..."):
            captures, errors, meta = search_all(targets, fallback_enabled)
        st.session_state.captures = captures
        st.session_state.search_meta = meta
        if errors:
            st.warning(f"{len(errors)} target variant(s) returned errors. See details below.")
            for e in errors:
                st.caption(f"⚠️ {e.get('phase')} · {e.get('target')} · {e.get('error')}")
        if meta.get("fallback_used"):
            st.info(f"No direct captures were found. Fallback URL-prefix search found {meta.get('fallback_count', 0):,} archived URLs under this prefix.")
        elif meta.get("fallback_attempted") and not captures:
            st.markdown("<div class='warning-box'>No direct captures and the URL-prefix fallback also returned 0 results. This usually means the handle truly has no archived captures under any target variant, or all CDX requests failed (check errors above).</div>", unsafe_allow_html=True)
        elif captures:
            st.success(f"Found {len(captures):,} captures.")
        else:
            st.markdown("<div class='warning-box'>No captures found and fallback was not attempted (it may be disabled, or check the checkbox above).</div>", unsafe_allow_html=True)

captures = st.session_state.captures
if captures:
    st.caption("Target variants are checked behind the scenes. Results are displayed source-neutrally.")
    st.write(" ".join([f"`Target variant {i+1}`" for i, _ in enumerate(st.session_state.targets)]))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Visible source rows", f"{len(captures):,}")
    c2.metric("HTML", f"{sum(1 for r in captures if 'html' in (r.get('mimetype') or '')):,}")
    c3.metric("JSON", f"{sum(1 for r in captures if 'json' in (r.get('mimetype') or '')):,}")
    c4.metric("Fallback used", "Yes" if st.session_state.search_meta.get("fallback_used") else "No")
    filter_text = st.text_input("Filter results", placeholder="URL, MIME type, timestamp...").strip().lower()
    visible = captures
    if filter_text:
        visible = [r for r in captures if filter_text in (r.get("original") or "").lower() or filter_text in (r.get("mimetype") or "").lower() or filter_text in (r.get("timestamp") or "")]
    st.download_button("Download capture list JSON", data=json.dumps(visible, indent=2, ensure_ascii=False).encode("utf-8"), file_name="captures.json", mime="application/json")
    max_rows = st.slider("Visible rows", min_value=10, max_value=max(10, min(1000, len(visible))), value=min(100, max(10, len(visible))), step=10)
    st.subheader("Bulk PII extraction")
    bulk_limit = st.number_input("How many visible rows should be processed in bulk?", min_value=1, max_value=min(1000, max(1, len(visible))), value=min(50, max(1, len(visible))), step=10)
    if st.button("Run bulk PII and prepare Excel", type="primary"):
        selected = visible[:bulk_limit]
        results, errors = [], []
        progress = st.progress(0)
        status = st.empty()
        for i, row in enumerate(selected):
            ts = row.get("timestamp", "")
            original = row.get("original", "")
            status.write(f"Processing {i+1}/{len(selected)}: {original}")
            try:
                raw = http_text(snapshot_url(ts, original, raw=True))
                results.append({"capture": row, "analysis": analyze_html(raw)})
            except Exception as e:
                errors.append({"timestamp": ts, "original": original, "error": str(e)})
            progress.progress((i + 1) / len(selected))
        st.session_state.bulk_results = results
        st.session_state.bulk_errors = errors
        status.write(f"Done. Processed {len(results)} captures, errors: {len(errors)}.")
    if st.session_state.bulk_results or st.session_state.bulk_errors:
        excel = build_excel(visible[:bulk_limit], st.session_state.bulk_results, st.session_state.bulk_errors)
        st.download_button("Download bulk PII Excel", data=excel, file_name="bulk_pii_results.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        flat = []
        for item in st.session_state.bulk_results:
            row = item["capture"]
            a = item["analysis"]
            for f in a.get("findings", []):
                flat.append({"date": fmt_ts(row.get("timestamp", "")), "original": row.get("original", ""), "risk": a.get("risk", ""), "type": f.get("type", ""), "value": f.get("value", ""), "confidence": f.get("confidence", ""), "sources": " | ".join(f.get("sources", [])), "evidence": f.get("evidence", "")})
        st.dataframe(pd.DataFrame(flat), use_container_width=True, hide_index=True)
    st.subheader("Captures / URL-index rows")
    for idx, row in enumerate(visible[:max_rows]):
        ts = row.get("timestamp", "")
        original = row.get("original", "")
        mimetype = row.get("mimetype", "unknown")
        with st.container(border=True):
            st.code(original, language=None)
            st.caption(f"{fmt_ts(ts)} · {mimetype} · {row.get('search_mode', '')}")
            st.link_button("Open capture in Wayback", snapshot_url(ts, original, raw=False))
            key = f"analysis_{idx}_{ts}_{abs(hash(original))}"
            if st.button("Surface PII", key=f"btn_{key}"):
                with st.spinner("Extracting PII indicators..."):
                    try:
                        st.session_state[key] = analyze_html(http_text(snapshot_url(ts, original, raw=True)))
                    except Exception as e:
                        st.error(f"PII extraction failed: {e}")
            a = st.session_state.get(key)
            if a:
                q = a.get("snapshot_quality", {})
                if q.get("unusable"):
                    st.markdown(f"<div class='warning-box'>Unusable capture: {html.escape(q.get('message', q.get('reason', 'unknown')))}</div>", unsafe_allow_html=True)
                st.write(f"**PII risk:** `{a.get('risk')}` · **Total findings:** `{a.get('total_findings')}` · **Extraction:** `{a.get('extraction_version')}`")
                df = pd.DataFrame([{"type": f.get("type", ""), "subtype": f.get("subtype", ""), "value": f.get("value", ""), "confidence": f.get("confidence", ""), "sources": " | ".join(f.get("sources", [])), "evidence": f.get("evidence", "")} for f in a.get("findings", [])])
                st.dataframe(df, use_container_width=True, hide_index=True)
                d1, d2 = st.columns(2)
                with d1:
                    st.download_button("Download findings CSV", data=df.to_csv(index=False).encode("utf-8-sig"), file_name=f"pii_findings_{ts}.csv", mime="text/csv", key=f"csv_{key}")
                with d2:
                    st.download_button("Download analysis JSON", data=json.dumps(a, indent=2, ensure_ascii=False).encode("utf-8"), file_name=f"pii_analysis_{ts}.json", mime="application/json", key=f"json_{key}")
                with st.expander("Top words"):
                    st.write(pd.DataFrame(a.get("top_words", []), columns=["word", "count"]))
                with st.expander("Raw extracted text"):
                    st.text(a.get("raw_text", ""))
else:
    st.info("Search for a handle, username, domain, or full URL to begin.")
