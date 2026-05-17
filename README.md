# Scaning — Multi-Platform Threat Intelligence Scanner

A small command-line Python tool to query multiple threat-intel platforms (VirusTotal, Hybrid Analysis, AbuseIPDB) for file hashes, IPs, and URLs.

## Features
- Query VirusTotal for file/hash and URL reports.
- Query VirusTotal for IP reputation.
- Query Hybrid Analysis for hashes, IPs, and URLs (requires API access).
- Query AbuseIPDB for detailed IP reports (verbose mode + recent reports).
- Simple indicator type detection (IPv4, SHA256-like hash, http/https URL).
- Command-line or interactive usage.

## Requirements
- Python 3.8+
- requests

Install dependencies:
```powershell
pip install requests

# VirusTotal file report: file name, type, last analysis stats (malicious/suspicious/harmless).
VirusTotal IP report: country, ASN, last analysis stats.
Hybrid Analysis: threat/verdict snippet (API response snippet shown).
AbuseIPDB: abuse confidence score, total reports, country, domain, last reported at, recent reports.
Configuration / API keys

Configuration / API keys
Set API keys using environment variables. Do NOT hard-code keys in source.

Required environment variables:

VIRUSTOTAL_API_KEY
HYBRID_API_KEY
ABUSEIPDB_API_KEY
PowerShell (persist for user):
