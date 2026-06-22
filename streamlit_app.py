
import csv
import html
import io
import json
import re
import urllib.parse
from collections import Counter

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="WaybackBlueApp PII PRO", page_icon="🔎", layout="wide")

st.markdown("""
<style>
.main { background:#F5F9FF; }
.block-container { padding-top:2rem; }
.hero { background:linear-gradient(135deg,#fff 0%,#F5FAFF 58%,#EAF4FF 100%);
border:1px solid #DCE8F6;border-radius:22px;padding:28px;box-shadow:0 12px 30px rgba(16,32,51,.08);margin-bottom:20px; }
.title { font-size:34px;font-weight:800;color:#102033;letter-spacing:-.04em; }
.subtitle { color:#62738A;font-size:15px;margin-top:4px; }
.pill { display:inline-block;background:#E8F2FF;color:#0A4FA8;border:1px solid #CFE3FF;border-radius:999px;padding:6px 10px;font-family:monospace;font-size:12px;margin-top:12px; }
.warning-box { border:1px solid #F3C8C8;background:#FFF6F6;color:#C43D3D;padding:12px;border-radius:14px;font-weight:700; }
</style>
""", unsafe_allow_html=True)

HEADERS = {"User-Agent": "Mozilla/5.0 WaybackBlueAppStreamlit/1.0", "Accept": "*/*"}

def valid_keys():
    try:
        keys = st.secrets.get("APP_KEYS", [])
        if isinstance(keys, str):
            return [keys]
        return list(keys)
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

@st.cache_data(ttl=3600, show_spinner=False)
def http_text(url):
    r = requests.get(url, headers=HEADERS, timeout=45)
    r.raise_for_status()
    if not r.encoding:
        r.encoding = "utf-8"
    return r.text

def build_targets(raw):
    raw = raw.strip()
    if not raw:
        return []
    if re.match(r"^https?://", raw, re.I):
        u = urllib.parse.urlparse(raw)
        return [u.netloc.replace("www.", "") + u.path.rstrip("/")]
    if "." in raw and "/" in raw:
        return [re.sub(r"^https?://", "", raw, flags=re.I).replace("www.", "").rstrip("/")]
    if "." in raw and "/" not in raw:
        return [re.sub(r"^https?://", "", raw, flags=re.I).replace("www.", "").rstrip("/")]
    h = raw.lstrip("@").strip()
    return [f"x.com/{h}", f"twitter.com/{h}", f"mobile.twitter.com/{h}"] if h else []

@st.cache_data(ttl=1800, show_spinner=False)
def cdx_search(target):
    params = {
        "url": target, "matchType": "prefix", "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest,length",
        "filter": "statuscode:200", "collapse": "digest", "limit": "5000",
    }
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    data = requests.get(url, headers=HEADERS, timeout=45).json()
    if not isinstance(data, list) or len(data) < 2:
        return []
    header = data[0]
    out = []
    for row in data[1:]:
        obj = dict(zip(header, row))
        obj["target"] = target
        out.append(obj)
    return out

def search_all(targets):
    rows, errors = [], []
    for t in targets:
        try:
            rows.extend(cdx_search(t))
        except Exception as e:
            errors.append({"target": t, "error": str(e)})
    seen, out = set(), []
    for r in rows:
        k = (r.get("timestamp"), r.get("original"))
        if k not in seen:
            seen.add(k)
            out.append(r)
    out.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return out, errors

def snapshot_url(ts, original, raw=True):
    return f"https://web.archive.org/web/{ts}{'id_/' if raw else '/'}{original}"

def fmt_ts(ts):
    if not ts or len(ts) < 8:
        return ts
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10] or '00'}:{ts[10:12] or '00'} UTC"

FALSE_NAMES = {"Something Went Wrong","Try Again","Enhanced Tracking Protection","Internet Archive","Wayback Machine","Privacy Policy","Terms Conditions","Contact Us","Page Not Found"}
GENERIC = {"home","about","contact","privacy","terms","login","signup","search","follow","share","archive","wayback","machine","javascript","browser","error","something","wrong","again"}

def clean_text(raw):
    raw2 = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", raw)
    raw2 = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", raw2)
    raw2 = re.sub(r"(?is)<noscript\b[^>]*>.*?</noscript>", " ", raw2)
    raw2 = re.sub(r"(?is)<svg\b[^>]*>.*?</svg>", " ", raw2)
    raw2 = re.sub(r"(?is)<iframe\b[^>]*>.*?</iframe>", " ", raw2)
    raw2 = re.sub(r"(?is)<!--.*?-->", " ", raw2)
    raw2 = re.sub(r"(?is)<br\s*/?>", "\n", raw2)
    raw2 = re.sub(r"(?is)</(p|div|li|h1|h2|h3|h4|tr|td|section|article)>", "\n", raw2)
    raw2 = re.sub(r"(?is)<[^>]+>", " ", raw2)
    text = html.unescape(raw2)
    text = re.sub(r"https?://web\.archive\.org/web/\d+[a-z_]*?/", "", text)
    text = text.replace("\u00a0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def html_signals(raw):
    sig = {"title": [], "meta": [], "mailto": [], "tel": [], "links": [], "jsonld": [], "alt": []}
    for m in re.finditer(r"(?is)<title[^>]*>(.*?)</title>", raw):
        sig["title"].append(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))).strip())
    for m in re.finditer(r'(?is)<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]*content=["\'](.*?)["\']', raw):
        sig["meta"].append({"key": html.unescape(m.group(1)), "value": html.unescape(m.group(2))})
    for m in re.finditer(r'(?is)<a[^>]+href=["\']mailto:([^"\']+)["\']', raw):
        sig["mailto"].append(html.unescape(urllib.parse.unquote(m.group(1))).split("?")[0])
    for m in re.finditer(r'(?is)<a[^>]+href=["\']tel:([^"\']+)["\']', raw):
        sig["tel"].append(html.unescape(urllib.parse.unquote(m.group(1))))
    for m in re.finditer(r'(?is)<a[^>]+href=["\']([^"\']+)["\']', raw):
        href = html.unescape(m.group(1)).strip()
        if href and not href.startswith("#") and len(href) < 500:
            sig["links"].append(href)
    for m in re.finditer(r'(?is)<(?:img|a|span|div|button)[^>]+(?:alt|title|aria-label)=["\']([^"\']{2,200})["\']', raw):
        sig["alt"].append(html.unescape(m.group(1)).strip())
    for m in re.finditer(r'(?is)<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', raw):
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
    return re.sub(r"\s+", " ", text[max(0, i-radius):min(len(text), i+len(str(value))+radius)]).strip()

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
    if ftype in {"likely_person_name","likely_location","likely_organization"}:
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
            return
    findings.append({"type": ftype, "subtype": subtype, "value": value, "confidence": conf, "sources": [source], "evidence": evidence(text, value), **({"count": count} if count else {})})

def flatten_jsonld(obj):
    out = []
    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                lk = str(k).lower()
                if lk in {"name","givenname","familyname","email","telephone","faxnumber","address","streetaddress","addresslocality","addressregion","postalcode","addresscountry","sameas","url","jobtitle","worksfor","affiliation"}:
                    out.append((lk, v))
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)
    walk(obj)
    return out

def detect_bad(text):
    low = text.lower()
    markers = ["something went wrong","try again","enhanced tracking protection","strict mode","known to cause issues","this browser is no longer supported","enable javascript","access denied","forbidden","page not found"]
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
        return {"snapshot_quality": quality, "risk": "unusable", "total_findings": 0, "grouped": {}, "findings": [], "top_words": [], "raw_text": text[:120000], "raw_text_length": len(text), "extraction_version": "streamlit_pii_pro"}
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
            conf = "high" if any(k in ev for k in ["phone","tel","mobile","call","fax","contact"]) else "medium"
            add(findings, "phone", np, text, conf, "text")

    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>]+", text, re.I) + [u for u in sig["links"] if u.startswith("http")]))
    socials = ["linkedin.com","facebook.com","instagram.com","youtube.com","tiktok.com","github.com","x.com","twitter.com","threads.net","telegram.me","t.me"]
    for u in urls:
        subtype = "social_profile_or_link" if any(d in u.lower() for d in socials) else ""
        add(findings, "url", u, text, "high" if subtype else "medium", "href_or_text", subtype)

    for h in re.findall(r"(?<![A-Za-z0-9_])@[A-Za-z0-9_]{2,30}", text):
        add(findings, "handle_or_username", h, text, "medium", "text")
    for ip in list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))):
        parts = [int(x) for x in ip.split(".") if x.isdigit()]
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            add(findings, "ip_address", ip, text, "medium", "text")

    for pat in [
        r"\b\d{1,6}\s+[A-Z][A-Za-z0-9.'-]*(?:\s+[A-Z][A-Za-z0-9.'-]*){0,6}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Highway|Hwy|Parkway|Pkwy|Square|Sq)\b(?:,?\s+[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+)*)?(?:,?\s+[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?",
        r"\bP\.?\s*O\.?\s*Box\s+\d{1,8}\b(?:,?\s+[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+)*)?(?:,?\s+[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?"
    ]:
        for a in re.findall(pat, text):
            add(findings, "address", a, text, "medium", "text")

    for d in re.findall(r"(?:date of birth|dob|born|birthdate|birthday)\s*[:\-]?\s*([A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4}|\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})", text, re.I):
        add(findings, "possible_date_of_birth", d, text, "medium", "labeled_text")

    for obj in sig["jsonld"]:
        for key, val in flatten_jsonld(obj):
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if isinstance(v, dict):
                    fields = [str(v[k]) for k in ["streetAddress","addressLocality","addressRegion","postalCode","addressCountry","name"] if k in v]
                    if fields:
                        add(findings, "address" if "address" in key else "likely_location", ", ".join(fields), text, "high", "jsonld")
                    continue
                v = str(v)
                if key == "email":
                    add(findings, "email", v, text, "high", "jsonld")
                elif key in {"telephone","faxnumber"}:
                    np = norm_phone(v)
                    if np:
                        add(findings, "phone", np, text, "high", "jsonld")
                elif key in {"name","givenname","familyname"}:
                    add(findings, "likely_person_name", v, text, "high", "jsonld")
                elif key in {"streetaddress","address","addresslocality","addressregion","postalcode","addresscountry"}:
                    add(findings, "likely_location", v, text, "high", "jsonld")
                elif key in {"sameas","url"}:
                    add(findings, "url", v, text, "high", "jsonld")

    for ftype, pat, conf in [
        ("likely_person_name", r"(?:name|full name|owner|author|contact person|profile)\s*[:\-]\s*([A-Z][^\n,|]{2,90})", "medium"),
        ("likely_location", r"(?:location|address|city|based in|located in|from)\s*[:\-]\s*([^\n]{3,120})", "medium"),
        ("likely_organization", r"(?:company|organization|employer|works at|business)\s*[:\-]\s*([^\n]{3,120})", "medium"),
    ]:
        for v in re.findall(pat, text, re.I):
            add(findings, ftype, v, text, conf, "labeled_text")

    candidates = re.findall(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b", "\n".join(sig["title"] + [m["value"] for m in sig["meta"]] + [clean_text(raw)]))
    for v, c in Counter(candidates).most_common(60):
        if any(x in v.lower() for x in ["privacy policy","terms","read more","contact us","wayback machine"]):
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

    strong = {"email","phone","address","possible_date_of_birth","handle_or_username","ip_address"}
    high = sum(1 for f in findings if f["type"] in strong and f.get("confidence") == "high")
    med = sum(1 for f in findings if f["type"] in strong and f.get("confidence") == "medium")
    score = high * 2 + med
    risk = "high" if score >= 6 else "medium" if score >= 3 else "low" if score >= 1 else "none"

    stop = GENERIC | {"the","and","for","with","from","this","that","you","your","are","was","were","have","has","not","but","http","https","www","com","org","net","html","mobile"}
    words = [w.lower() for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9'_-]{2,}", text) if w.lower() not in stop]
    return {"snapshot_quality": {"unusable": False}, "risk": risk, "total_findings": len(findings), "grouped": grouped, "findings": findings, "top_words": Counter(words).most_common(100), "raw_text": text[:120000], "raw_text_length": len(text), "extraction_version": "streamlit_pii_pro"}

def findings_df(findings):
    return pd.DataFrame([{"type": f.get("type",""), "subtype": f.get("subtype",""), "value": f.get("value",""), "confidence": f.get("confidence",""), "sources": " | ".join(f.get("sources",[])), "evidence": f.get("evidence","")} for f in findings]) if findings else pd.DataFrame(columns=["type","subtype","value","confidence","sources","evidence"])

st.markdown("""<div class="hero"><div class="title">WaybackBlueApp PII PRO</div><div class="subtitle">Search archived captures and extract PII indicators with evidence snippets.</div><div class="pill">STREAMLIT · WAYBACK CDX · PII PRO</div></div>""", unsafe_allow_html=True)

if not require_key():
    st.stop()

query = st.text_input("Handle, username, domain, or full URL", placeholder="@example_user | example_user | example.com/profile | https://site.com/page")
if "captures" not in st.session_state:
    st.session_state.captures = []
if "targets" not in st.session_state:
    st.session_state.targets = []

if st.button("Search captures", type="primary"):
    targets = build_targets(query)
    st.session_state.targets = targets
    if not targets:
        st.error("Enter a username, handle, domain, or URL.")
    else:
        with st.spinner("Fetching Wayback capture index..."):
            captures, errors = search_all(targets)
        st.session_state.captures = captures
        if errors:
            st.warning(f"{len(errors)} target variant(s) returned errors.")
        st.success(f"Found {len(captures):,} captures.")

captures = st.session_state.captures
if captures:
    st.caption("Target variants are checked behind the scenes. Results are displayed source-neutrally.")
    st.write(" ".join([f"`Target variant {i+1}`" for i, _ in enumerate(st.session_state.targets)]))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total captures", f"{len(captures):,}")
    c2.metric("HTML captures", f"{sum(1 for r in captures if 'html' in (r.get('mimetype') or '')):,}")
    c3.metric("Images", f"{sum(1 for r in captures if (r.get('mimetype') or '').startswith('image/')):,}")
    c4.metric("PDF files", f"{sum(1 for r in captures if 'pdf' in (r.get('mimetype') or '')):,}")

    filter_text = st.text_input("Filter captures", placeholder="URL, MIME type, timestamp...").strip().lower()
    visible = captures
    if filter_text:
        visible = [r for r in captures if filter_text in (r.get("original") or "").lower() or filter_text in (r.get("mimetype") or "").lower() or filter_text in (r.get("timestamp") or "")]

    st.download_button("Download capture list JSON", data=json.dumps(visible, indent=2, ensure_ascii=False).encode("utf-8"), file_name="captures.json", mime="application/json")
    max_rows = st.slider("Visible rows", min_value=10, max_value=max(10, min(500, len(visible))), value=min(80, max(10, len(visible))), step=10)

    for idx, row in enumerate(visible[:max_rows]):
        ts, original, mimetype = row.get("timestamp",""), row.get("original",""), row.get("mimetype","unknown")
        with st.container(border=True):
            st.code(original, language=None)
            st.caption(f"{fmt_ts(ts)} · {mimetype}")
            st.link_button("Open capture in Wayback", snapshot_url(ts, original, raw=False))
            key = f"analysis_{idx}_{ts}_{abs(hash(original))}"
            if st.button("Surface PII", key=f"btn_{key}"):
                with st.spinner("Extracting PII indicators..."):
                    try:
                        raw = http_text(snapshot_url(ts, original, raw=True))
                        st.session_state[key] = analyze_html(raw)
                    except Exception as e:
                        st.error(f"PII extraction failed: {e}")

            analysis = st.session_state.get(key)
            if analysis:
                q = analysis.get("snapshot_quality", {})
                if q.get("unusable"):
                    st.markdown(f"<div class='warning-box'>Unusable capture: {html.escape(q.get('message', q.get('reason', 'unknown')))}</div>", unsafe_allow_html=True)
                st.write(f"**PII risk:** `{analysis.get('risk')}` · **Total findings:** `{analysis.get('total_findings')}` · **Extraction:** `{analysis.get('extraction_version')}`")
                df = findings_df(analysis.get("findings", []))
                st.dataframe(df, use_container_width=True, hide_index=True)
                d1, d2 = st.columns(2)
                with d1:
                    st.download_button("Download findings CSV", data=df.to_csv(index=False).encode("utf-8-sig"), file_name=f"pii_findings_{ts}.csv", mime="text/csv", key=f"csv_{key}")
                with d2:
                    st.download_button("Download analysis JSON", data=json.dumps(analysis, indent=2, ensure_ascii=False).encode("utf-8"), file_name=f"pii_analysis_{ts}.json", mime="application/json", key=f"json_{key}")
                with st.expander("Top words"):
                    st.write(pd.DataFrame(analysis.get("top_words", []), columns=["word", "count"]))
                with st.expander("Raw extracted text"):
                    st.text(analysis.get("raw_text", ""))
else:
    st.info("Search for a handle, username, domain, or full URL to begin.")
