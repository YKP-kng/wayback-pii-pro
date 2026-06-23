"""
Standalone debug script - run this LOCALLY (not in the Streamlit app) to see
exactly what the Wayback CDX API returns for each query variant, with no
caching and no filtering getting in the way.

Usage:
    python debug_cdx.py gooberlolhi
"""
import sys
import json
import urllib.parse
import requests

HEADERS = {"User-Agent": "Mozilla/5.0 WaybackBlueAppStreamlitBulk/2.0", "Accept": "*/*"}

def run(label, params):
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    print(f"\n=== {label} ===")
    print(url)
    try:
        r = requests.get(url, headers=HEADERS, timeout=60)
        print(f"HTTP status: {r.status_code}")
        text = r.text
        print(f"Raw response length: {len(text)} chars")
        print(f"First 300 chars of raw response:\n{text[:300]!r}")
        try:
            data = r.json()
            if isinstance(data, list):
                print(f"Parsed JSON rows (including header): {len(data)}")
                if len(data) > 1:
                    print("Header:", data[0])
                    print("First data row:", data[1])
                    print("Last data row:", data[-1])
            else:
                print("Parsed JSON is not a list:", type(data), data)
        except Exception as je:
            print(f"JSON parse FAILED: {je}")
    except Exception as e:
        print(f"REQUEST FAILED: {e}")

def main():
    handle = sys.argv[1] if len(sys.argv) > 1 else "gooberlolhi"
    targets = [f"x.com/{handle}", f"twitter.com/{handle}", f"mobile.twitter.com/{handle}"]

    for t in targets:
        # 1. Exact match, no filter, no collapse - the absolute simplest possible query.
        run(f"EXACT (bare, no filter/collapse) - {t}",
            {"url": t, "matchType": "exact", "output": "json"})

        # 2. Prefix match, no filter, no collapse - the absolute simplest possible query.
        run(f"PREFIX (bare, no filter/collapse) - {t}",
            {"url": t, "matchType": "prefix", "output": "json", "limit": "20"})

        # 3. Prefix match WITH the filter/collapse the app currently uses.
        run(f"PREFIX (app's exact params) - {t}",
            {"url": t, "matchType": "prefix", "output": "json",
             "fl": "original,mimetype,timestamp,statuscode,digest,length",
             "filter": "statuscode:200", "collapse": "urlkey", "limit": "20"})

        # 4. Prefix match with filter but NO collapse - isolates whether collapse is the culprit.
        run(f"PREFIX (filter only, no collapse) - {t}",
            {"url": t, "matchType": "prefix", "output": "json",
             "fl": "original,mimetype,timestamp,statuscode,digest,length",
             "filter": "statuscode:200", "limit": "20"})

if __name__ == "__main__":
    main()
