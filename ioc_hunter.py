#!/usr/bin/env python3
"""
FBI TACU IOC Hunter - OpenSearch/Wazuh/Sysmon
Searches for suspicious IPs and domains from FBI Amber Alert indicators.
Covers Sysmon Event ID 3 (Network Connections) and Event ID 22 (DNS Queries).
"""

import json
import sys
import urllib.request
import urllib.error
import ssl
import base64
import getpass
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# IOC LISTS (FBI TACU Amber Alert – March 2026)
# ─────────────────────────────────────────────
MALICIOUS_IPS = [
    "93.118.166.139",
    "93.118.166.141",
    "93.118.166.142",
    "93.118.166.143",
    "93.118.166.144",
    "93.118.166.145",
    "18.116.63.2",
    "18.223.24.218",
    "35.175.224.64",
    "62.106.66.112",
    "143.198.5.41",
    "159.65.227.190",
    "165.227.82.147",
    "185.128.139.4",
    "194.11.246.101",
    "195.20.17.189",
]

MALICIOUS_DOMAINS = [
    "bookairway.com",
    "facetalk.org",
    "netivtech.org",
    "pharmacynod.com",
    "pprocessplanet.org",
    "sso.facetalk.org",
    "sso.moodleuni.com",
    "lvshvma-01.ke.hawaii.czn.com",
]

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DEFAULT_HOST = "https://localhost:9200"
DEFAULT_INDEX = "wazuh-alerts-*"

# Historical search window (per client request)
SEARCH_START = "2026-01-01T00:00:00Z"
SEARCH_END   = "2026-03-03T23:59:59Z"

MAX_HITS = 500  # Max results to return per query


# ─────────────────────────────────────────────
# HTTP HELPER (no external dependencies)
# ─────────────────────────────────────────────
def make_request(url: str, auth_header: str, payload: dict) -> dict:
    """Send a POST request to OpenSearch and return parsed JSON."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": auth_header,
        },
    )
    # Skip TLS verification for self-signed certs (common in on-prem OpenSearch)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  [HTTP {e.code}] {e.reason}")
        print(f"  Response: {body[:500]}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"  [Connection Error] {e.reason}")
        print("  Check that OpenSearch is reachable and the host/port are correct.")
        sys.exit(1)


def build_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


# ─────────────────────────────────────────────
# QUERY BUILDERS
# ─────────────────────────────────────────────
def time_range_filter(start: str, end: str) -> dict:
    return {"range": {"@timestamp": {"gte": start, "lte": end}}}


def ip_query(start: str, end: str) -> dict:
    """
    Sysmon Event 3 – Network Connections.
    Checks src_ip, dst_ip, and the nested eventdata fields Wazuh maps.
    """
    ip_terms = [
        {"terms": {"data_win_eventdata_sourceIp.keyword": MALICIOUS_IPS}},
        {"terms": {"data_win_eventdata_destinationIp.keyword": MALICIOUS_IPS}},
        # Flat field aliases Wazuh/Graylog may create
        {"terms": {"src_ip.keyword": MALICIOUS_IPS}},
        {"terms": {"dst_ip.keyword": MALICIOUS_IPS}},
        # Wildcard catch across the raw message (fallback)
        *[
            {"match_phrase": {"data_win_system_message": ip}}
            for ip in MALICIOUS_IPS
        ],
    ]
    return {
        "size": MAX_HITS,
        "_source": [
            "@timestamp",
            "agent.name",
            "data_win_system_message",
            "data_win_eventdata_sourceIp",
            "data_win_eventdata_destinationIp",
            "data_win_eventdata_image",
            "data_win_eventdata_user",
            "data_win_eventdata_protocol",
            "data_win_eventdata_destinationPort",
            "src_ip", "dst_ip", "rule_id",
        ],
        "query": {
            "bool": {
                "must": [
                    time_range_filter(start, end),
                    {"terms": {"rule_group3.keyword": ["sysmon_event3"]}},
                ],
                "should": ip_terms,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }


def domain_query(start: str, end: str) -> dict:
    """
    Sysmon Event 22 – DNS Queries.
    Checks queryName and queryResults fields.
    """
    domain_should = []
    for domain in MALICIOUS_DOMAINS:
        domain_should += [
            {"match_phrase": {"data_win_eventdata_queryName": domain}},
            {"match_phrase": {"data_win_eventdata_queryResults": domain}},
            {"match_phrase": {"data_win_system_message": domain}},
            {"match_phrase": {"dns_answer": domain}},
        ]
    return {
        "size": MAX_HITS,
        "_source": [
            "@timestamp",
            "agent.name",
            "data_win_eventdata_queryName",
            "data_win_eventdata_queryResults",
            "data_win_eventdata_image",
            "data_win_eventdata_user",
            "dns_answer",
            "rule_id",
        ],
        "query": {
            "bool": {
                "must": [
                    time_range_filter(start, end),
                    {"terms": {"rule_group3.keyword": ["sysmon_event_22"]}},
                ],
                "should": domain_should,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }


def firewall_ip_query(start: str, end: str) -> dict:
    """
    Juniper firewall logs – catch IPs in any firewall-tagged event.
    Adjust rule_group1 / rule_group2 values to match your index mappings.
    """
    ip_terms = [
        {"terms": {"src_ip.keyword": MALICIOUS_IPS}},
        {"terms": {"dst_ip.keyword": MALICIOUS_IPS}},
        *[
            {"match_phrase": {"full_message": ip}}
            for ip in MALICIOUS_IPS
        ],
    ]
    return {
        "size": MAX_HITS,
        "_source": ["@timestamp", "src_ip", "dst_ip", "full_message", "rule_id"],
        "query": {
            "bool": {
                "must": [
                    time_range_filter(start, end),
                    # Adjust this filter to match how your Juniper logs are tagged
                    {"match": {"rule_group1": "juniper"}},
                ],
                "should": ip_terms,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }


# ─────────────────────────────────────────────
# RESULT FORMATTING
# ─────────────────────────────────────────────
def print_hit(hit: dict, hit_num: int):
    src = hit.get("_source", {})
    print(f"\n  ── Hit #{hit_num} ──────────────────────────────")
    print(f"  Timestamp : {src.get('@timestamp', 'N/A')}")
    print(f"  Agent     : {src.get('agent', {}).get('name', src.get('agent_name', 'N/A'))}")
    print(f"  Rule ID   : {src.get('rule_id', 'N/A')}")

    # IP-specific fields
    for field, label in [
        ("data_win_eventdata_sourceIp",      "Src IP (Sysmon)"),
        ("data_win_eventdata_destinationIp", "Dst IP (Sysmon)"),
        ("data_win_eventdata_destinationPort","Dst Port"),
        ("data_win_eventdata_protocol",       "Protocol"),
        ("src_ip",                            "Src IP (FW)"),
        ("dst_ip",                            "Dst IP (FW)"),
    ]:
        val = src.get(field)
        if val:
            print(f"  {label:22}: {val}")

    # DNS-specific fields
    for field, label in [
        ("data_win_eventdata_queryName",    "Query Name"),
        ("data_win_eventdata_queryResults", "Query Results"),
        ("dns_answer",                      "DNS Answer"),
    ]:
        val = src.get(field)
        if val:
            print(f"  {label:22}: {val[:120]}")

    for field, label in [
        ("data_win_eventdata_image", "Process"),
        ("data_win_eventdata_user",  "User"),
    ]:
        val = src.get(field)
        if val:
            print(f"  {label:22}: {val}")


def run_search(label: str, url: str, auth: str, query: dict) -> list:
    print(f"\n{'='*60}")
    print(f"  SEARCH: {label}")
    print(f"{'='*60}")
    result = make_request(url, auth, query)
    hits = result.get("hits", {}).get("hits", [])
    total = result.get("hits", {}).get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    print(f"  Total matches: {total_val}  (showing up to {MAX_HITS})")
    if hits:
        for i, hit in enumerate(hits, 1):
            print_hit(hit, i)
    else:
        print("  No matches found.")
    return hits


def export_results(all_results: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Results exported to: {filename}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  FBI TACU IOC Hunter – OpenSearch")
    print("  Covers: Sysmon Event 3 (Net), Event 22 (DNS), Juniper FW")
    print("=" * 60)

    # ── Connection setup ──
    host = input(f"\nOpenSearch host [{DEFAULT_HOST}]: ").strip() or DEFAULT_HOST
    index = input(f"Index pattern [{DEFAULT_INDEX}]: ").strip() or DEFAULT_INDEX
    username = input("Username [admin]: ").strip() or "admin"
    password = getpass.getpass("Password: ")

    # ── Time window ──
    print(f"\nDefault search window: {SEARCH_START}  →  {SEARCH_END}")
    custom = input("Use default window? [Y/n]: ").strip().lower()
    if custom == "n":
        start = input(f"  Start (ISO8601, e.g. {SEARCH_START}): ").strip() or SEARCH_START
        end   = input(f"  End   (ISO8601, e.g. {SEARCH_END}): ").strip() or SEARCH_END
    else:
        start, end = SEARCH_START, SEARCH_END

    search_url = f"{host}/{index}/_search"
    auth = build_auth_header(username, password)

    print(f"\n[*] Connecting to: {search_url}")
    print(f"[*] Window: {start}  →  {end}")
    print(f"[*] IOCs: {len(MALICIOUS_IPS)} IPs, {len(MALICIOUS_DOMAINS)} domains\n")

    all_results = {}

    # ── Run searches ──
    sysmon_ip_hits = run_search(
        "Sysmon Event 3 – Malicious IP Connections",
        search_url, auth, ip_query(start, end)
    )
    all_results["sysmon_ip_connections"] = [h["_source"] for h in sysmon_ip_hits]

    sysmon_dns_hits = run_search(
        "Sysmon Event 22 – Malicious Domain DNS Queries",
        search_url, auth, domain_query(start, end)
    )
    all_results["sysmon_dns_queries"] = [h["_source"] for h in sysmon_dns_hits]

    fw_hits = run_search(
        "Juniper Firewall – Malicious IP Traffic",
        search_url, auth, firewall_ip_query(start, end)
    )
    all_results["juniper_firewall"] = [h["_source"] for h in fw_hits]

    # ── Summary ──
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    total_hits = sum(len(v) for v in all_results.values())
    print(f"  Sysmon IP connections : {len(all_results['sysmon_ip_connections'])}")
    print(f"  Sysmon DNS queries    : {len(all_results['sysmon_dns_queries'])}")
    print(f"  Juniper FW hits       : {len(all_results['juniper_firewall'])}")
    print(f"  ──────────────────────")
    print(f"  TOTAL                 : {total_hits}")

    if total_hits > 0:
        print("\n  [!] POTENTIAL IOC ACTIVITY DETECTED – review results above.")
    else:
        print("\n  [✓] No matching activity found in the specified window.")

    # ── Export ──
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = f"ioc_hunt_results_{ts}.json"
    save = input(f"\nSave results to JSON? [{out_file}] (Y/n): ").strip().lower()
    if save != "n":
        export_results(all_results, out_file)

    print("\n[*] Hunt complete.\n")


if __name__ == "__main__":
    main()
