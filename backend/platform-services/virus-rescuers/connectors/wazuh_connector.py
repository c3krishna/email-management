#!/usr/bin/env python3
"""
============================================================
Worktual Wazuh SIEM Connector
File: /opt/virus-rescuers/connectors/wazuh_connector.py

Pulls from TWO Wazuh components:

  1. Wazuh Manager API (port 55000)
     - Agent status/inventory
     - Vulnerability detector results
     - SCA (Security Configuration Assessment) — maps directly
       to PCI DSS, GDPR, HIPAA, NIST 800-53, CIS benchmarks

  2. Wazuh Indexer / OpenSearch (port 9200, or via dashboard proxy)
     - Real alerts, tagged with rule.groups containing
       'gdpr', 'pci_dss', 'hipaa', 'nist_800_53' etc.
     - This is the actual threat-hunting alert stream

Both feed into the same security_events-style tables so this
shows up alongside email threats on one unified dashboard.

Deploy: Dashboard server (82.113.72.52)
PM2: pm2 start wazuh_connector.py --interpreter python3 --name wazuh-connector
============================================================
"""

import os, json, time, logging, requests
import mysql.connector
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DB_HOST = os.getenv("DB_HOST", "10.180.0.84")
DB_USER = os.getenv("DB_USER", "mailmetrics")
DB_PASS = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")

# Wazuh Manager API (agents, vulnerabilities, SCA)
WAZUH_API_URL  = os.getenv("WAZUH_API_URL",  "https://10.180.1.221:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "")

# Wazuh Indexer (OpenSearch) — real-time alerts with compliance tags
WAZUH_INDEXER_URL  = os.getenv("WAZUH_INDEXER_URL",  "https://10.180.1.221:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
CUSTOMER_ID   = int(os.getenv("CUSTOMER_ID", "1"))  # which customer this Wazuh cluster belongs to

os.makedirs("/var/log/wazuh-connector", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/wazuh-connector/connector.log")]
)
log = logging.getLogger("wazuh-connector")

COMPLIANCE_FRAMEWORKS = ['gdpr', 'pci_dss', 'hipaa', 'nist_800_53', 'tsc', 'cis']


def get_conn():
    return mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
        database='threat_platform', autocommit=True, connection_timeout=15)


def ensure_schema():
    conn = get_conn(); cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS wazuh_agents (
      id             INT          NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      agent_id       VARCHAR(10)  NOT NULL,
      agent_name     VARCHAR(255) NOT NULL,
      ip_address     VARCHAR(50)  DEFAULT NULL,
      os_name        VARCHAR(100) DEFAULT NULL,
      status         VARCHAR(20)  DEFAULT NULL,
      last_seen      DATETIME     DEFAULT NULL,
      updated_at     DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_agent (customer_id, agent_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS wazuh_vulnerabilities (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      agent_id       VARCHAR(10)  NOT NULL,
      agent_name     VARCHAR(255) DEFAULT NULL,
      cve            VARCHAR(50)  NOT NULL,
      severity       VARCHAR(20)  DEFAULT NULL,
      cvss_score     DECIMAL(3,1) DEFAULT NULL,
      package_name   VARCHAR(255) DEFAULT NULL,
      package_version VARCHAR(100) DEFAULT NULL,
      title          VARCHAR(500) DEFAULT NULL,
      published_date DATE         DEFAULT NULL,
      status         VARCHAR(30)  DEFAULT 'active',
      detected_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_vuln (customer_id, agent_id, cve),
      KEY idx_severity (severity)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS wazuh_compliance (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      agent_id       VARCHAR(10)  NOT NULL,
      framework      VARCHAR(30)  NOT NULL COMMENT 'gdpr/pci_dss/hipaa/nist_800_53/tsc/cis',
      policy_name    VARCHAR(255) DEFAULT NULL,
      pass_count     INT          DEFAULT 0,
      fail_count     INT          DEFAULT 0,
      score_pct      DECIMAL(5,2) DEFAULT NULL,
      checked_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_framework (customer_id, framework)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS wazuh_alerts (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      wazuh_alert_id VARCHAR(100) DEFAULT NULL,
      agent_id       VARCHAR(10)  DEFAULT NULL,
      agent_name     VARCHAR(255) DEFAULT NULL,
      rule_id        INT          DEFAULT NULL,
      rule_level     TINYINT      DEFAULT NULL,
      rule_description VARCHAR(500) DEFAULT NULL,
      compliance_tags VARCHAR(200) DEFAULT NULL COMMENT 'comma-separated: gdpr,pci_dss,...',
      mitre_technique VARCHAR(100) DEFAULT NULL,
      full_log       TEXT         DEFAULT NULL,
      alert_datetime DATETIME     NOT NULL,
      created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_alert (wazuh_alert_id),
      KEY idx_customer_date (customer_id, alert_datetime),
      KEY idx_level (rule_level)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    conn.commit(); cur.close(); conn.close()
    log.info("Wazuh integration tables ready")


# ── Wazuh Manager API auth ──────────────────────────────────────
_token_cache = {'token': None, 'expires': 0}

def get_wazuh_token():
    if _token_cache['token'] and time.time() < _token_cache['expires']:
        return _token_cache['token']
    try:
        r = requests.post(f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False, timeout=15)
        r.raise_for_status()
        token = r.json()['data']['token']
        _token_cache['token'] = token
        _token_cache['expires'] = time.time() + 850  # tokens last ~900s
        return token
    except Exception as e:
        log.error(f"Wazuh auth error: {e}")
        return None


def wazuh_api_get(path, params=None):
    token = get_wazuh_token()
    if not token:
        return None
    try:
        r = requests.get(f"{WAZUH_API_URL}{path}",
            headers={'Authorization': f'Bearer {token}'},
            params=params, verify=False, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.error(f"Wazuh API error {path}: {e}")
        return None


# ── Sync agents ──────────────────────────────────────────────────
def sync_agents():
    data = wazuh_api_get('/agents', {'limit': 500})
    if not data:
        return 0

    agents = data.get('data', {}).get('affected_items', [])
    conn = get_conn(); cur = conn.cursor()
    count = 0
    for a in agents:
        try:
            cur.execute("""
                INSERT INTO wazuh_agents (customer_id, agent_id, agent_name, ip_address, os_name, status, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                  agent_name=VALUES(agent_name), ip_address=VALUES(ip_address),
                  os_name=VALUES(os_name), status=VALUES(status), last_seen=VALUES(last_seen)
            """, (
                CUSTOMER_ID, a.get('id'), a.get('name'),
                a.get('ip'), a.get('os', {}).get('name'),
                a.get('status'), a.get('lastKeepAlive', '').replace('T', ' ').replace('Z', '')[:19] or None,
            ))
            count += 1
        except Exception as e:
            log.error(f"Agent sync error: {e}")
    conn.commit(); cur.close(); conn.close()
    return count


# ── Sync vulnerabilities ─────────────────────────────────────────
def sync_vulnerabilities():
    """Query Wazuh Indexer for vulnerabilities, filtered to our agents only."""
    conn0 = get_conn(); cur0 = conn0.cursor()
    cur0.execute("SELECT agent_id FROM wazuh_agents WHERE customer_id=%s", (CUSTOMER_ID,))
    our_agent_ids = [row[0] for row in cur0.fetchall()]
    cur0.close(); conn0.close()

    if not our_agent_ids:
        log.warning("No agents found in wazuh_agents table yet")
        return 0

    query = {
        "size": 1000,
        "query": {"bool": {"filter": [{"terms": {"agent.id": our_agent_ids}}]}},
        "sort": [{"vulnerability.score.base": {"order": "desc", "missing": "_last"}}]
    }
    try:
        r = requests.post(
            f"{WAZUH_INDEXER_URL}/wazuh-states-vulnerabilities-*/_search",
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
            json=query, verify=False, timeout=30)
        r.raise_for_status()
        resp_json = r.json()
        hits = resp_json.get('hits', {}).get('hits', [])
        total_matched = resp_json.get('hits', {}).get('total', {}).get('value', '?')
        log.info(f"  Vulnerability query matched {total_matched} docs for {len(our_agent_ids)} agents, fetched {len(hits)}")
    except Exception as e:
        log.error(f"Vulnerability indexer query error: {e}")
        return 0

    conn = get_conn(); cur = conn.cursor()
    total = 0
    for hit in hits:
        src = hit.get('_source', {})
        vuln = src.get('vulnerability', {})
        agent = src.get('agent', {})
        package = src.get('package', {})

        cve = vuln.get('id')
        if not cve:
            continue

        try:
            cur.execute("""
                INSERT INTO wazuh_vulnerabilities
                  (customer_id, agent_id, agent_name, cve, severity, cvss_score,
                   package_name, package_version, title, published_date, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                  severity=VALUES(severity), cvss_score=VALUES(cvss_score),
                  status=VALUES(status), detected_at=NOW()
            """, (
                CUSTOMER_ID, agent.get('id'), agent.get('name'),
                cve,
                vuln.get('severity'),
                vuln.get('score', {}).get('base'),
                package.get('name'),
                package.get('version'),
                (vuln.get('description') or '')[:500],
                (vuln.get('published_at') or '')[:10] or None,
                'active' if vuln.get('status', '').lower() != 'fixed' else 'fixed',
            ))
            total += 1
        except Exception as e:
            log.debug(f"Vuln insert error: {e}")

    conn.commit(); cur.close(); conn.close()
    return total

def sync_compliance():
    agents_data = wazuh_api_get('/agents', {'limit': 500, 'status': 'active'})
    if not agents_data:
        return 0
    agents = agents_data.get('data', {}).get('affected_items', [])

    conn = get_conn(); cur = conn.cursor()
    total = 0
    for agent in agents:
        agent_id = agent.get('id')
        if agent_id == '000':
            continue
        sca_data = wazuh_api_get(f'/sca/{agent_id}')
        if not sca_data:
            continue
        policies = sca_data.get('data', {}).get('affected_items', [])
        for p in policies:
            name = (p.get('name') or '').lower()
            # Map policy name to a compliance framework
            framework = next((f for f in COMPLIANCE_FRAMEWORKS if f.replace('_', '') in name.replace('-', '').replace(' ', '')), None)
            if not framework:
                continue  # skip generic CIS/OS-hardening policies not tied to a named framework
            try:
                pass_count = p.get('pass', 0)
                fail_count = p.get('fail', 0)
                score = p.get('score', 0)
                cur.execute("""
                    INSERT INTO wazuh_compliance
                      (customer_id, agent_id, framework, policy_name, pass_count, fail_count, score_pct)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      pass_count=VALUES(pass_count),
                      fail_count=VALUES(fail_count),
                      score_pct=VALUES(score_pct),
                      checked_at=NOW()
                """, (CUSTOMER_ID, agent_id, framework, p.get('name'), pass_count, fail_count, score))
                total += 1
            except Exception as e:
                log.debug(f"Compliance insert error: {e}")
    conn.commit(); cur.close(); conn.close()
    return total


# ── Sync alerts from Wazuh Indexer (OpenSearch) with compliance tags ──
def sync_alerts():
    since = (datetime.utcnow() - timedelta(minutes=POLL_INTERVAL//60 + 10)).strftime('%Y-%m-%dT%H:%M:%S')
    query = {
        "size": 200,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": since}}}],
                "should": [{"exists": {"field": f"rule.groups"}}],
            }
        }
    }
    try:
        r = requests.post(f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
            json=query, verify=False, timeout=20)
        r.raise_for_status()
        hits = r.json().get('hits', {}).get('hits', [])
    except Exception as e:
        log.error(f"Wazuh indexer query error: {e}")
        return 0

    conn = get_conn(); cur = conn.cursor()
    count = 0
    for hit in hits:
        src = hit.get('_source', {})
        rule = src.get('rule', {})
        # Wazuh stores compliance frameworks as separate top-level fields
        # on 'rule' (rule.pci_dss, rule.gdpr, rule.hipaa, etc.) — NOT inside
        # rule.groups. Each framework field is a list of specific control IDs.
        compliance_tags = [fw for fw in COMPLIANCE_FRAMEWORKS if rule.get(fw)]

        try:
            cur.execute("""
                INSERT IGNORE INTO wazuh_alerts
                  (customer_id, wazuh_alert_id, agent_id, agent_name,
                   rule_id, rule_level, rule_description, compliance_tags,
                   mitre_technique, full_log, alert_datetime)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                CUSTOMER_ID, hit.get('_id'),
                src.get('agent', {}).get('id'), src.get('agent', {}).get('name'),
                rule.get('id'), rule.get('level'), rule.get('description'),
                ','.join(compliance_tags) if compliance_tags else None,
                ','.join(rule.get('mitre', {}).get('id', [])) if rule.get('mitre') else None,
                (src.get('full_log') or '')[:2000],
                (src.get('@timestamp') or '').replace('T', ' ').replace('Z', '')[:19],
            ))
            if cur.rowcount:
                count += 1
        except Exception as e:
            log.debug(f"Alert insert error: {e}")

    conn.commit(); cur.close(); conn.close()
    return count


def main_loop():
    while True:
        try:
            log.info("Syncing Wazuh agents...")
            n_agents = sync_agents()
            log.info(f"  {n_agents} agents synced")

            log.info("Syncing vulnerabilities...")
            n_vulns = sync_vulnerabilities()
            log.info(f"  {n_vulns} vulnerabilities synced")

            log.info("Syncing compliance (SCA)...")
            n_comp = sync_compliance()
            log.info(f"  {n_comp} compliance results synced")

            log.info("Syncing threat-hunting alerts...")
            n_alerts = sync_alerts()
            log.info(f"  {n_alerts} new alerts synced")

        except Exception as e:
            log.error(f"Main loop error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    log.info("=" * 60)
    log.info("Worktual Wazuh SIEM Connector")
    log.info(f"Manager API: {WAZUH_API_URL}")
    log.info(f"Indexer:     {WAZUH_INDEXER_URL}")
    log.info(f"Customer ID: {CUSTOMER_ID} | Poll: {POLL_INTERVAL}s")
    log.info("=" * 60)
    ensure_schema()
    main_loop()
