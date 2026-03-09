# FBI TACU IOC Hunter — Setup & Usage

## What this does

Queries your OpenSearch cluster (Wazuh/Sysmon/Juniper data) for indicators
from the FBI TACU Amber Alerts received March 4 & 6, 2026.

Searches three event types:
- **Sysmon Event ID 3** – Outbound/inbound network connections to malicious IPs
- **Sysmon Event ID 22** – DNS queries resolving malicious domains
- **Juniper Firewall** – Any firewall-logged traffic to/from malicious IPs

---

## Quick Start

```bash
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. No extra packages needed — uses only Python stdlib
#    (urllib, ssl, json, getpass are all built-in)

# 3. Run the hunter
python ioc_hunter.py
```

The script will prompt you for:
| Prompt | Default | Notes |
|---|---|---|
| OpenSearch host | `https://localhost:9200` | Change to your cluster URL |
| Index pattern | `wazuh-alerts-*` | Use your actual Wazuh index |
| Username | `admin` | |
| Password | *(hidden)* | |
| Time window | Jan 1 – Mar 3, 2026 | Per client request |

---

## Output

- Results print to the terminal with timestamps, agent names, IPs/domains, and process info
- You'll be prompted to save a timestamped JSON file: `ioc_hunt_results_YYYYMMDD_HHMMSS.json`

---

## Adjusting for your environment

**If your Juniper index is separate**, change the index pattern when prompted
(e.g. `juniper-*`) or run the script twice with different index patterns.

**If Wazuh field names differ**, the key fields to verify in your index mappings are:
```
data_win_eventdata_sourceIp
data_win_eventdata_destinationIp
data_win_eventdata_queryName
data_win_eventdata_queryResults
rule_group3   (values: sysmon_event3, sysmon_event_22)
```
You can check your actual field names in OpenSearch Dashboards → Index Management → your index → Mappings.

---

## Monitoring going forward (post-blocking)

To confirm your blocking rules are working after March 4/6:

1. Run the script with a **new date range** starting March 4, 2026 to present
2. Any hits that appear after the blocking date indicate the rule is NOT blocking
3. For ongoing alerting, import the same IP/domain lists into:
   - **Graylog**: Create a Lookup Table from a CSV of IOCs, then use it in a Stream rule
   - **Wazuh**: Add the IPs to `/var/ossec/etc/lists/` as a CDB list and create a custom rule referencing it

---

## IOC Reference

**IPs (16 total):**
93.118.166.139/141/142/143/144/145, 18.116.63.2, 18.223.24.218,
35.175.224.64, 62.106.66.112, 143.198.5.41, 159.65.227.190,
165.227.82.147, 185.128.139.4, 194.11.246.101, 195.20.17.189

**Domains (7 total):**
bookairway.com, facetalk.org, netivtech.org, pharmacynod.com,
pprocessplanet.org, sso.facetalk.org, sso.moodleuni.com
