import os
import argparse
import base64
import requests
import sys

VIRUSTOTAL_API_KEY="your_virustotal_key_here"
ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
HYBRID_API_KEY="your_hybrid_key_here"

def vt_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        print(f"\n[VirusTotal] Request failed: {e}")
        return
    if r.status_code == 200:
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        fname = attrs.get("meaningful_name", "Unknown")
        ftype = attrs.get("type_description", "Unknown")
        print("\n[VirusTotal] File report")
        print(f"  File Name : {fname}")
        print(f"  File Type : {ftype}")
        print(f"  Malicious : {stats.get('malicious', 0)}")
        print(f"  Suspicious: {stats.get('suspicious', 0)}")
        print(f"  Harmless  : {stats.get('harmless', 0)}")
    elif r.status_code == 404:
        print("\n[VirusTotal] Hash not found")
    else:
        print(f"\n[VirusTotal] Error: {r.status_code} - {r.text[:200]}")

def vt_ip_report(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        print(f"\n[VirusTotal] Request failed: {e}")
        return
    if r.status_code == 200:
        data = r.json().get("data", {}).get("attributes", {})
        last_analysis = data.get("last_analysis_stats", {})
        print("\n[VirusTotal] IP report")
        print(f"  Country : {data.get('country', 'Unknown')}")
        print(f"  ASN     : {data.get('as_owner', 'Unknown')}")
        print(f"  Harmless  : {last_analysis.get('harmless', 0)}")
        print(f"  Malicious : {last_analysis.get('malicious', 0)}")
    else:
        print(f"\n[VirusTotal] IP lookup error: {r.status_code}")

def hybrid_analysis_lookup(indicator, itype="ip"):
    """
    Query Hybrid Analysis for an indicator.
    Requires HYBRID_API_KEY in environment or fallback above.
    """
    if not HYBRID_API_KEY:
        print("\n[HybridAnalysis] API key not set; skipping Hybrid Analysis lookup")
        return

    headers = {
        "api-key": HYBRID_API_KEY,
        "User-Agent": "VT-Scanner/1.0",
        "Accept": "application/json",
    }

    try:
        if itype == "hash":
            endpoints = [
                f"https://www.hybrid-analysis.com/api/v2/report/{indicator}",
                f"https://www.hybrid-analysis.com/api/v2/overview/{indicator}"
            ]
        elif itype == "ip":
            endpoints = [f"https://www.hybrid-analysis.com/api/v2/summary/ip/{indicator}"]
        elif itype == "url":
            endpoints = [f"https://www.hybrid-analysis.com/api/v2/summary/url/{indicator}"]
        else:
            endpoints = [f"https://www.hybrid-analysis.com/api/v2/summary/{indicator}"]

        for url in endpoints:
            try:
                r = requests.get(url, headers=headers, timeout=15)
            except Exception as e:
                print(f"\n[HybridAnalysis] Request failed: {e}")
                return

            if r.status_code == 200:
                j = r.json()
                print(f"\n[HybridAnalysis] {itype} {indicator}")
                if isinstance(j, dict):
                    # common/possible fields: threat_score, verdict, analysis info
                    if j.get("threat_score") is not None:
                        print(f"  Threat Score : {j.get('threat_score')}")
                    if j.get("verdict") is not None:
                        print(f"  Verdict      : {j.get('verdict')}")
                    # show short snippet of response for manual inspection
                    snippet = str(j)
                    print(f"  raw-snippet  : {snippet[:400]}")
                else:
                    print(f"  raw-response : {str(j)[:400]}")
                return
            elif r.status_code == 404:
                continue
            else:
                print(f"\n[HybridAnalysis] Error {r.status_code} - {r.text[:200]} for {url}")
                return

        print(f"\n[HybridAnalysis] No data found for {indicator}")
    except Exception as e:
        print(f"\n[HybridAnalysis] Request failed: {e}")

def abuseipdb_check(ip, sample_reports=5):
    if not ABUSEIPDB_API_KEY:
        print("\n[AbuseIPDB] API key not set; skipping AbuseIPDB lookup")
        return
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
    except Exception as e:
        print(f"\n[AbuseIPDB] Request failed: {e}")
        return
    if r.status_code == 200:
        data = r.json().get("data", {})
        print(f"\n[AbuseIPDB] {ip}")
        print(f"  Abuse Confidence Score: {data.get('abuseConfidenceScore')}")
        print(f"  Total Reports         : {data.get('totalReports')}")
        print(f"  Country               : {data.get('countryCode')}")
        print(f"  Domain                : {data.get('domain')}")
        print(f"  Last Reported At      : {data.get('lastReportedAt')}")
        reports = data.get('reports') or []
        if reports:
            print(f"\n  Showing up to {sample_reports} report(s):")
            for i, rep in enumerate(reports[:sample_reports], start=1):
                reported_at = rep.get('reportedAt') or rep.get('reported_at') or 'N/A'
                comment = rep.get('comment') or ''
                comment = (comment[:200] + '...') if len(comment) > 200 else comment
                categories = rep.get('categories') or rep.get('category', [])
                reporter_country = rep.get('reporterCountry') or rep.get('reporter_country') or 'N/A'
                print(f"    [{i}] {reported_at} | country: {reporter_country} | categories: {categories}")
                if comment:
                    print(f"         comment: {comment}")
        else:
            print("  No individual reports available (try increasing maxAgeInDays or using the reports endpoint).")
    else:
        print(f"\n[AbuseIPDB] Error {r.status_code} - {r.text[:200]}")

def detect_type(value):
    # Simple detection: IPv4, SHA256-like hex, URL
    if value.count(".") == 3 and all(part.isdigit() for part in value.split(".")):
        return "ip"
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "hash"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    return "unknown"

def main():
    parser = argparse.ArgumentParser(description="Multi-platform threat intelligence lookup")
    parser.add_argument("value", nargs="?", help="hash | ip | url (if omitted, interactive prompt)")
    args = parser.parse_args()

    val = args.value or input("Enter hash / ip / url: ").strip()
    kind = detect_type(val)

    if kind == "hash":
        vt_file_report(val)
        hybrid_analysis_lookup(val, "hash")
    elif kind == "ip":
        vt_ip_report(val)
        hybrid_analysis_lookup(val, "ip")
        abuseipdb_check(val)
    elif kind == "url":
        print("\n[Info] URL provided; querying Hybrid Analysis (if key) and VirusTotal (basic)")
        hybrid_analysis_lookup(val, "url")
        try:
            url_id = base64.urlsafe_b64encode(val.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            r = requests.get(vt_url, headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                print("\n[VirusTotal] URL report")
                print(f"  Malicious : {stats.get('malicious', 0)}")
                print(f"  Suspicious: {stats.get('suspicious', 0)}")
                print(f"  Harmless  : {stats.get('harmless', 0)}")
            else:
                print(f"\n[VirusTotal] URL lookup error: {r.status_code}")
        except Exception as e:
            print(f"\n[VirusTotal] URL lookup failed: {e}")
    else:
        print("Unknown indicator type. Provide a hash, IPv4, or a URL.")
        sys.exit(1)

if __name__ == "__main__":
    main()