#!/usr/bin/env python3
"""
============================================================
Worktual Universal Email Security Connector
File: /opt/virus-rescuers/connectors/universal_connector.py

Supports:
  - Proofpoint TAP API
  - Microsoft Defender / Office 365
  - Google Workspace (Gmail API)
  - Mimecast
  - Barracuda Email Security
  - Generic IMAP
  - Webhook (push-based, any platform)
  - Postfix (log agent, already built)

Each customer has a connector_type + credentials stored in DB.
The engine polls each customer's platform every N minutes,
normalizes data into a unified schema, and stores centrally.

Deploy: Dashboard server (82.113.72.52)
PM2: pm2 start universal_connector.py
       --interpreter python3 --name vr-connector
============================================================
"""

import os, re, json, time, logging, hashlib, base64
import requests, mysql.connector
from datetime import datetime, timedelta, timezone
from abc import ABC, abstractmethod

# ── CONFIG ────────────────────────────────────────────────────
DB_HOST       = os.getenv("DB_HOST",       "10.180.0.84")
DB_USER       = os.getenv("DB_USER",       "mailmetrics")
DB_PASS       = os.getenv("DB_PASSWORD",   "WorktualMailMetrics@123")
OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://miniai.worktual.tech:11434")
AI_MODEL      = os.getenv("AI_MODEL",      "qwen2.5:14b-instruct-q4_K_M")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))  # 5 minutes
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "WorktualAgent@2026")

# ── LOGGING ───────────────────────────────────────────────────
os.makedirs("/var/log/vr-connector", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/vr-connector/connector.log"),
    ]
)
log = logging.getLogger("vr-connector")

# ── UNIFIED EVENT SCHEMA ─────────────────────────────────────
# Every connector normalizes to this structure
def make_event(
    customer_id,
    platform,           # proofpoint/microsoft/google/mimecast/barracuda/generic
    event_type,         # blocked/delivered/quarantined/threat/spam/phishing/malware
    mail_from,
    mail_to,
    subject,
    event_datetime,
    threat_category=None,   # spam/phishing/malware/bec/url_threat/none
    threat_score=None,      # 0-100
    sender_domain=None,
    recipient_domain=None,
    sender_ip=None,
    urls=None,              # list of URLs
    attachment_hashes=None, # list of hashes
    message_id=None,
    platform_guid=None,     # original platform event ID
    headers=None,           # dict of headers
    raw=None,               # original raw event (JSON)
):
    return {
        "customer_id":        customer_id,
        "platform":           platform,
        "event_type":         event_type,
        "mail_from":          (mail_from or "")[:255],
        "mail_to":            (mail_to   or "")[:255] if isinstance(mail_to, str)
                              else ", ".join(mail_to or [])[:255],
        "subject":            (subject   or "")[:500],
        "event_datetime":     event_datetime,
        "threat_category":    threat_category,
        "threat_score":       threat_score,
        "sender_domain":      sender_domain or (mail_from.split("@")[-1]
                              if mail_from and "@" in mail_from else None),
        "recipient_domain":   recipient_domain,
        "sender_ip":          sender_ip,
        "urls":               json.dumps(urls or [])[:2000],
        "attachment_hashes":  json.dumps(attachment_hashes or [])[:1000],
        "message_id":         (message_id   or "")[:255],
        "platform_guid":      (platform_guid or "")[:255],
        "headers_json":       json.dumps(headers or {})[:4000],
        "raw_json":           json.dumps(raw or {})[:8000],
        "dedup_hash":         hashlib.md5(
            f"{mail_from}{mail_to}{subject}{event_datetime}".encode()
        ).hexdigest(),
    }

# ── DB HELPERS ────────────────────────────────────────────────
def get_conn(database="threat_platform"):
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=database, autocommit=False, connection_timeout=30
    )

def ensure_schema():
    """Create all required tables."""
    conn = get_conn()
    cur  = conn.cursor()

    # Platform connectors config
    cur.execute("""
    CREATE TABLE IF NOT EXISTS platform_connectors (
      id               INT          NOT NULL AUTO_INCREMENT,
      customer_id      INT          NOT NULL,
      platform         VARCHAR(50)  NOT NULL,
      display_name     VARCHAR(100) DEFAULT NULL,
      connector_type   ENUM(
        'proofpoint','microsoft_defender','google_workspace',
        'mimecast','barracuda','postfix_agent','imap','webhook','generic_api'
      ) NOT NULL,
      credentials      JSON         NOT NULL COMMENT 'Encrypted credentials',
      config           JSON         DEFAULT NULL COMMENT 'Extra config (poll_interval, etc)',
      active           TINYINT(1)   DEFAULT 1,
      last_sync_at     DATETIME     DEFAULT NULL,
      last_sync_status VARCHAR(20)  DEFAULT NULL,
      last_error       TEXT         DEFAULT NULL,
      total_events     BIGINT       DEFAULT 0,
      created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_customer (customer_id),
      KEY idx_active   (active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # Unified security events table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
      id                BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id       INT          NOT NULL,
      connector_id      INT          DEFAULT NULL,
      platform          VARCHAR(50)  NOT NULL,
      event_type        VARCHAR(50)  NOT NULL,
      mail_from         VARCHAR(255) DEFAULT NULL,
      mail_to           VARCHAR(255) DEFAULT NULL,
      subject           VARCHAR(500) DEFAULT NULL,
      event_datetime    DATETIME     NOT NULL,
      threat_category   VARCHAR(50)  DEFAULT NULL,
      threat_score      TINYINT      DEFAULT NULL,
      sender_domain     VARCHAR(255) DEFAULT NULL,
      recipient_domain  VARCHAR(255) DEFAULT NULL,
      sender_ip         VARCHAR(50)  DEFAULT NULL,
      urls              TEXT         DEFAULT NULL,
      attachment_hashes VARCHAR(1000)DEFAULT NULL,
      message_id        VARCHAR(255) DEFAULT NULL,
      platform_guid     VARCHAR(255) DEFAULT NULL,
      headers_json      TEXT         DEFAULT NULL,
      raw_json          TEXT         DEFAULT NULL,
      dedup_hash        VARCHAR(32)  DEFAULT NULL,
      ai_processed      TINYINT(1)   DEFAULT 0,
      ai_threat_type    VARCHAR(50)  DEFAULT NULL,
      ai_confidence     TINYINT      DEFAULT NULL,
      ai_explanation    TEXT         DEFAULT NULL,
      notification_sent TINYINT(1)   DEFAULT 0,
      created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_dedup  (customer_id, dedup_hash),
      KEY idx_customer_date (customer_id, event_datetime),
      KEY idx_threat        (threat_category),
      KEY idx_platform      (platform),
      KEY idx_ai_processed  (ai_processed)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # Sync state per connector
    cur.execute("""
    CREATE TABLE IF NOT EXISTS connector_sync_state (
      connector_id     INT          NOT NULL,
      last_event_time  DATETIME     DEFAULT NULL,
      last_cursor      VARCHAR(500) DEFAULT NULL,
      events_today     INT          DEFAULT 0,
      events_total     BIGINT       DEFAULT 0,
      PRIMARY KEY (connector_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    conn.commit()
    cur.close()
    conn.close()
    log.info("Schema ready")

# ── BASE CONNECTOR ────────────────────────────────────────────
class BaseConnector(ABC):
    """
    Abstract base — all platform connectors inherit this.
    Implement fetch_events() to return list of normalized events.
    """

    def __init__(self, connector_row):
        self.id           = connector_row["id"]
        self.customer_id  = connector_row["customer_id"]
        self.platform     = connector_row["platform"]
        self.display_name = connector_row.get("display_name", "")
        self.credentials  = connector_row["credentials"] \
                            if isinstance(connector_row["credentials"], dict) \
                            else json.loads(connector_row["credentials"] or "{}")
        self.config       = connector_row.get("config") or {}
        if isinstance(self.config, str):
            self.config = json.loads(self.config or "{}")
        self.log = logging.getLogger(f"connector.{self.platform}.{self.id}")

    @abstractmethod
    def fetch_events(self, since: datetime) -> list:
        """Fetch and normalize events since given datetime."""
        pass

    def test_connection(self) -> dict:
        """Test if credentials are valid."""
        try:
            events = self.fetch_events(datetime.utcnow() - timedelta(hours=1))
            return {"success": True, "message": f"Connected — {len(events)} events in last 1h"}
        except Exception as e:
            return {"success": False, "message": str(e)}


# ══════════════════════════════════════════════════════════════
# PROOFPOINT TAP CONNECTOR
# Docs: https://tap-api-v2.proofpoint.com/v2/
# ══════════════════════════════════════════════════════════════
class ProofpointConnector(BaseConnector):
    """
    Proofpoint Targeted Attack Protection (TAP) API
    Credentials needed:
      service_principal: <string>
      secret_key:        <string>
      tenant_id:         <optional>
    """

    BASE_URL = "https://tap-api-v2.proofpoint.com/v2"

    def _headers(self):
        sp  = self.credentials["service_principal"]
        key = self.credentials["secret_key"]
        token = base64.b64encode(f"{sp}:{key}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Content-Type":  "application/json",
        }

    def fetch_events(self, since: datetime) -> list:
        events = []
        # Proofpoint max window = 1 hour per request
        now    = datetime.utcnow()
        window = min((now - since).total_seconds(), 3600)
        since  = now - timedelta(seconds=window)

        # Format: ISO 8601
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        now_str   = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Fetch all SIEM events (blocked + delivered threats)
        endpoints = [
            f"{self.BASE_URL}/siem/all?format=json&sinceTime={since_str}&toTime={now_str}",
        ]

        for url in endpoints:
            try:
                r = requests.get(url, headers=self._headers(), timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    events += self._parse_proofpoint(data)
                elif r.status_code == 401:
                    raise Exception("Proofpoint auth failed — check service_principal/secret_key")
                else:
                    self.log.warning(f"Proofpoint {url}: {r.status_code}")
            except Exception as e:
                self.log.error(f"Proofpoint fetch error: {e}")

        return events

    def _parse_proofpoint(self, data: dict) -> list:
        events = []
        # messagesBlocked, messagesDelivered, clicksBlocked, clicksPermitted
        for category, event_list in data.items():
            if not isinstance(event_list, list):
                continue
            for item in event_list:
                # Get recipients
                recipients = item.get("recipients", [])
                if not recipients:
                    recipients = [item.get("recipient", "")]

                # Threat info
                threats    = item.get("threatsInfoMap", [{}])
                threat     = threats[0] if threats else {}
                threat_cat = threat.get("classification", "").lower()
                threat_score = None
                if "scoreScore" in threat:
                    threat_score = int(float(threat.get("scoreScore", 0)) * 100)

                # URLs
                urls = [u.get("url","") for u in item.get("url", []) if u.get("url")]

                # Attachment hashes
                hashes = []
                for att in item.get("messageParts", []):
                    if att.get("md5"):
                        hashes.append(att["md5"])
                    if att.get("sha256"):
                        hashes.append(att["sha256"])

                # Event type
                if "blocked" in category.lower():
                    event_type = "blocked"
                elif "delivered" in category.lower():
                    event_type = "delivered"
                elif "click" in category.lower():
                    event_type = "url_click"
                else:
                    event_type = "threat"

                for recipient in recipients:
                    evt = make_event(
                        customer_id      = self.customer_id,
                        platform         = "proofpoint",
                        event_type       = event_type,
                        mail_from        = item.get("sender", ""),
                        mail_to          = recipient,
                        subject          = item.get("subject", ""),
                        event_datetime   = item.get("messageTime",
                                           datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
                        threat_category  = threat_cat or None,
                        threat_score     = threat_score,
                        sender_ip        = item.get("senderIP"),
                        urls             = urls,
                        attachment_hashes= hashes,
                        message_id       = item.get("messageID", ""),
                        platform_guid    = item.get("GUID", ""),
                        raw              = item,
                    )
                    events.append(evt)
        return events


# ══════════════════════════════════════════════════════════════
# MICROSOFT DEFENDER / OFFICE 365 CONNECTOR
# Uses Microsoft Graph API
# ══════════════════════════════════════════════════════════════
class MicrosoftDefenderConnector(BaseConnector):
    """
    Microsoft Defender for Office 365 via Graph API
    Credentials needed:
      tenant_id:     <Azure AD tenant ID>
      client_id:     <App registration client ID>
      client_secret: <App registration secret>
    Permissions needed: ThreatAssessment.Read.All, Mail.Read
    """

    def _get_token(self):
        tenant_id = self.credentials["tenant_id"]
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        r = requests.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     self.credentials["client_id"],
            "client_secret": self.credentials["client_secret"],
            "scope":         "https://graph.microsoft.com/.default",
        }, timeout=15)
        if r.status_code == 200:
            return r.json()["access_token"]
        raise Exception(f"Microsoft auth failed: {r.status_code} {r.text[:200]}")

    def fetch_events(self, since: datetime) -> list:
        events = []
        try:
            token   = self._get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/json",
            }
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Get threat intelligence email events
            # Using Security API — email threats
            urls_to_fetch = [
                f"https://graph.microsoft.com/v1.0/security/alerts?"
                f"$filter=createdDateTime ge {since_str} and category eq 'maliciousEmail'"
                f"&$top=100&$orderby=createdDateTime desc",
            ]

            for url in urls_to_fetch:
                while url:
                    r = requests.get(url, headers=headers, timeout=30)
                    if r.status_code == 200:
                        data = r.json()
                        for alert in data.get("value", []):
                            evt = self._parse_ms_alert(alert)
                            if evt:
                                events.append(evt)
                        # Pagination
                        url = data.get("@odata.nextLink")
                    else:
                        self.log.warning(f"MS Graph: {r.status_code}")
                        break
        except Exception as e:
            self.log.error(f"Microsoft fetch error: {e}")
        return events

    def _parse_ms_alert(self, alert: dict) -> dict:
        # Extract email info from alert
        email_roles = alert.get("emailRoles", [])
        mail_from   = next((e.get("sender") for e in email_roles
                           if e.get("role") == "sender"), "")
        mail_to     = next((e.get("recipient") for e in email_roles
                           if e.get("role") == "recipient"), "")

        # Threat category mapping
        category_map = {
            "malware":  "malware",
            "phishing": "phishing",
            "spam":     "spam",
            "backdoor": "malware",
        }
        cat = category_map.get(alert.get("category","").lower(), "threat")

        return make_event(
            customer_id    = self.customer_id,
            platform       = "microsoft_defender",
            event_type     = "blocked" if alert.get("status") == "resolved" else "threat",
            mail_from      = mail_from,
            mail_to        = mail_to,
            subject        = alert.get("title", ""),
            event_datetime = alert.get("createdDateTime",
                             datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            threat_category= cat,
            threat_score   = int(alert.get("severity","low") == "high") * 80 +
                             int(alert.get("severity","low") == "medium") * 50,
            urls           = [u.get("url","") for u in alert.get("malwareStates",[])],
            platform_guid  = alert.get("id",""),
            raw            = alert,
        )


# ══════════════════════════════════════════════════════════════
# GOOGLE WORKSPACE CONNECTOR
# Uses Gmail API + Admin SDK
# ══════════════════════════════════════════════════════════════
class GoogleWorkspaceConnector(BaseConnector):
    """
    Google Workspace via Admin SDK Reports API
    Credentials needed:
      service_account_json: <contents of service account JSON>
      admin_email:          <admin@yourdomain.com> (delegated access)
      customer_domain:      <yourdomain.com>
    """

    def _get_token(self):
        try:
            from google.oauth2 import service_account
            from google.auth.transport.requests import Request

            sa_info = self.credentials.get("service_account_json", {})
            if isinstance(sa_info, str):
                sa_info = json.loads(sa_info)

            creds = service_account.Credentials.from_service_account_info(
                sa_info,
                scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
                subject=self.credentials.get("admin_email"),
            )
            creds.refresh(Request())
            return creds.token
        except ImportError:
            raise Exception("Install: pip3 install google-auth google-auth-httplib2")

    def fetch_events(self, since: datetime) -> list:
        events = []
        try:
            token = self._get_token()
            headers = {"Authorization": f"Bearer {token}"}
            since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            domain    = self.credentials.get("customer_domain", "")

            url = (
                f"https://admin.googleapis.com/admin/reports/v1/activity/users/all"
                f"/applications/token?startTime={since_str}&domain={domain}&maxResults=500"
            )

            # Gmail log events
            gmail_url = (
                f"https://admin.googleapis.com/admin/reports/v1/activity/users/all"
                f"/applications/gmail?startTime={since_str}&maxResults=500"
                f"&eventName=email_spam,message_spam_found,phishing_identified"
            )

            r = requests.get(gmail_url, headers=headers, timeout=30)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    evt = self._parse_google_event(item)
                    if evt:
                        events.append(evt)
            else:
                self.log.warning(f"Google API: {r.status_code}")
        except Exception as e:
            self.log.error(f"Google fetch error: {e}")
        return events

    def _parse_google_event(self, item: dict) -> dict:
        params  = {p["name"]: p.get("value","")
                   for event in item.get("events",[])
                   for p in event.get("parameters",[])}
        return make_event(
            customer_id    = self.customer_id,
            platform       = "google_workspace",
            event_type     = "spam" if "spam" in item.get("events",[{}])[0]
                             .get("name","").lower() else "threat",
            mail_from      = params.get("message_id",""),
            mail_to        = item.get("actor",{}).get("email",""),
            subject        = params.get("subject",""),
            event_datetime = item.get("id",{}).get("time",
                             datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            threat_category= "spam",
            platform_guid  = item.get("id",{}).get("uniqueQualifier",""),
            raw            = item,
        )


# ══════════════════════════════════════════════════════════════
# MIMECAST CONNECTOR
# ══════════════════════════════════════════════════════════════
class MimecastConnector(BaseConnector):
    """
    Mimecast Email Security REST API
    Credentials needed:
      base_url:    https://eu-api.mimecast.com (region specific)
      app_id:      <Application ID>
      app_key:     <Application Key>
      access_key:  <Access Key>
      secret_key:  <Secret Key>
    """

    def _auth_headers(self, uri):
        import hmac, hashlib, uuid
        request_id = str(uuid.uuid4())
        date_str   = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")
        data_to_sign = f"{date_str}:{request_id}:{uri}:{self.credentials['app_key']}"
        hmac_sha1  = hmac.new(
            base64.b64decode(self.credentials["secret_key"]),
            data_to_sign.encode(), hashlib.sha1
        ).digest()
        sig = base64.b64encode(hmac_sha1).decode()

        return {
            "Authorization": f"MC {self.credentials['access_key']}:{sig}",
            "x-mc-app-id":   self.credentials["app_id"],
            "x-mc-date":     date_str,
            "x-mc-req-id":   request_id,
            "Content-Type":  "application/json",
        }

    def fetch_events(self, since: datetime) -> list:
        events = []
        base   = self.credentials.get("base_url", "https://eu-api.mimecast.com")
        uri    = "/api/ttp/url/get-logs"
        try:
            r = requests.post(
                f"{base}{uri}",
                headers=self._auth_headers(uri),
                json={"data": [{"from": since.strftime("%Y-%m-%dT%H:%M:%S+0000")}]},
                timeout=30,
            )
            if r.status_code == 200:
                for item in r.json().get("data", [{}])[0].get("clickLogs", []):
                    events.append(make_event(
                        customer_id    = self.customer_id,
                        platform       = "mimecast",
                        event_type     = "url_click",
                        mail_from      = item.get("from",""),
                        mail_to        = item.get("to",""),
                        subject        = item.get("subject",""),
                        event_datetime = item.get("date",""),
                        threat_category= item.get("category","").lower() or None,
                        urls           = [item.get("url","")],
                        platform_guid  = item.get("id",""),
                        raw            = item,
                    ))
        except Exception as e:
            self.log.error(f"Mimecast fetch error: {e}")
        return events


# ══════════════════════════════════════════════════════════════
# BARRACUDA CONNECTOR
# ══════════════════════════════════════════════════════════════
class BarracudaConnector(BaseConnector):
    """
    Barracuda Email Security Gateway REST API
    Credentials needed:
      base_url:  https://your-barracuda.example.com
      username:  <admin username>
      password:  <admin password>
      domain:    <your domain>
    """

    def _get_token(self):
        r = requests.post(
            f"{self.credentials['base_url']}/restapi/v1/login",
            json={
                "username": self.credentials["username"],
                "password": self.credentials["password"],
            },
            timeout=15, verify=False,
        )
        if r.status_code == 200:
            return r.json().get("token","")
        raise Exception(f"Barracuda auth failed: {r.status_code}")

    def fetch_events(self, since: datetime) -> list:
        events = []
        try:
            token = self._get_token()
            base  = self.credentials["base_url"]
            since_str = since.strftime("%Y-%m-%d %H:%M:%S")

            r = requests.get(
                f"{base}/restapi/v1/email/logs",
                headers={"Authorization": f"Token {token}"},
                params={"start": since_str, "limit": 500,
                        "filter": "blocked,spam,virus"},
                timeout=30, verify=False,
            )
            if r.status_code == 200:
                for item in r.json().get("results", []):
                    cat = "spam" if item.get("reason","").lower() == "spam" \
                          else "malware" if item.get("reason","").lower() == "virus" \
                          else "threat"
                    events.append(make_event(
                        customer_id    = self.customer_id,
                        platform       = "barracuda",
                        event_type     = "blocked",
                        mail_from      = item.get("from",""),
                        mail_to        = item.get("to",""),
                        subject        = item.get("subject",""),
                        event_datetime = item.get("date",""),
                        threat_category= cat,
                        platform_guid  = str(item.get("id","")),
                        raw            = item,
                    ))
        except Exception as e:
            self.log.error(f"Barracuda fetch error: {e}")
        return events


# ══════════════════════════════════════════════════════════════
# GENERIC IMAP CONNECTOR
# Any mail server with IMAP access
# ══════════════════════════════════════════════════════════════
class IMAPConnector(BaseConnector):
    """
    Generic IMAP connector — works with any mail server
    Credentials needed:
      host:     mail.example.com
      port:     993
      username: security@example.com
      password: <password>
      folder:   Spam (or Junk, or INBOX.Spam)
      use_ssl:  true
    """

    def fetch_events(self, since: datetime) -> list:
        import imaplib
        import email as email_lib
        import email.header

        events = []
        try:
            host = self.credentials["host"]
            port = int(self.credentials.get("port", 993))
            ssl  = self.credentials.get("use_ssl", True)

            M = imaplib.IMAP4_SSL(host, port) if ssl else imaplib.IMAP4(host, port)
            M.login(self.credentials["username"], self.credentials["password"])

            folder = self.credentials.get("folder", "INBOX")
            M.select(folder)

            # Search for emails since date
            date_str = since.strftime("%d-%b-%Y")
            _, msg_ids = M.search(None, f'SINCE {date_str}')

            for mid in (msg_ids[0].split() or [])[:200]:  # max 200
                try:
                    _, data = M.fetch(mid, "(RFC822)")
                    msg     = email_lib.message_from_bytes(data[0][1])

                    # Decode subject
                    subject_raw = msg.get("Subject", "")
                    subject_parts = email.header.decode_header(subject_raw)
                    subject = " ".join(
                        (part.decode(charset or "utf-8", errors="replace")
                         if isinstance(part, bytes) else str(part))
                        for part, charset in subject_parts
                    )

                    # Extract URLs from body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                                break
                    else:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="replace") \
                               if isinstance(msg.get_payload(), bytes) else str(msg.get_payload())

                    urls = re.findall(r'https?://[^\s<>"\']+', body)

                    events.append(make_event(
                        customer_id    = self.customer_id,
                        platform       = "imap",
                        event_type     = "spam",
                        mail_from      = msg.get("From",""),
                        mail_to        = msg.get("To",""),
                        subject        = subject,
                        event_datetime = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        urls           = urls[:10],
                        message_id     = msg.get("Message-ID",""),
                        headers        = dict(msg.items()),
                    ))
                except Exception as e:
                    self.log.debug(f"IMAP parse error mid={mid}: {e}")

            M.logout()
        except Exception as e:
            self.log.error(f"IMAP fetch error: {e}")
        return events


# ══════════════════════════════════════════════════════════════
# WEBHOOK CONNECTOR (push-based)
# Platform pushes events to YOUR endpoint
# ══════════════════════════════════════════════════════════════
class WebhookConnector(BaseConnector):
    """
    Webhook-based connector — platform pushes to:
    POST https://email-management.worktual.tech/api/connectors/webhook/{customer_id}

    No polling needed — events arrive in real-time.
    fetch_events() just returns buffered events from DB.
    """

    def fetch_events(self, since: datetime) -> list:
        # Events already stored by webhook endpoint
        # Just return empty — webhook handler saves directly
        return []


# ══════════════════════════════════════════════════════════════
# CONNECTOR FACTORY
# ══════════════════════════════════════════════════════════════
CONNECTOR_MAP = {
    "proofpoint":          ProofpointConnector,
    "microsoft_defender":  MicrosoftDefenderConnector,
    "google_workspace":    GoogleWorkspaceConnector,
    "mimecast":            MimecastConnector,
    "barracuda":           BarracudaConnector,
    "imap":                IMAPConnector,
    "webhook":             WebhookConnector,
    "postfix_agent":       None,  # Uses existing log-agent.mjs
    "generic_api":         None,  # Custom implementation per customer
}

def get_connector(row: dict) -> BaseConnector:
    cls = CONNECTOR_MAP.get(row["connector_type"])
    if cls is None:
        raise Exception(f"No connector class for type: {row['connector_type']}")
    return cls(row)


# ── EVENT STORAGE ─────────────────────────────────────────────
def save_events(events: list, connector_id: int) -> int:
    """Save normalized events to DB, skip duplicates."""
    if not events:
        return 0
    conn = get_conn()
    cur  = conn.cursor()
    saved = 0
    for e in events:
        try:
            cur.execute("""
                INSERT IGNORE INTO security_events
                  (customer_id, connector_id, platform, event_type,
                   mail_from, mail_to, subject, event_datetime,
                   threat_category, threat_score, sender_domain,
                   recipient_domain, sender_ip, urls, attachment_hashes,
                   message_id, platform_guid, headers_json, raw_json, dedup_hash)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                e["customer_id"], connector_id, e["platform"], e["event_type"],
                e["mail_from"], e["mail_to"], e["subject"], e["event_datetime"],
                e["threat_category"], e["threat_score"], e["sender_domain"],
                e["recipient_domain"], e["sender_ip"], e["urls"],
                e["attachment_hashes"], e["message_id"], e["platform_guid"],
                e["headers_json"], e["raw_json"], e["dedup_hash"],
            ))
            if cur.rowcount > 0:
                saved += 1
        except Exception as ex:
            log.debug(f"Save event error: {ex}")
    conn.commit()
    cur.close()
    conn.close()
    return saved


# ── SYNC STATE ────────────────────────────────────────────────
def get_last_sync(connector_id: int) -> datetime:
    try:
        conn = get_conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT last_event_time FROM connector_sync_state WHERE connector_id=%s",
            (connector_id,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and row["last_event_time"]:
            return row["last_event_time"]
    except Exception:
        pass
    return datetime.utcnow() - timedelta(hours=1)

def update_sync_state(connector_id: int, event_count: int):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO connector_sync_state
              (connector_id, last_event_time, events_today, events_total)
            VALUES (%s, NOW(), %s, %s)
            ON DUPLICATE KEY UPDATE
              last_event_time = NOW(),
              events_today    = events_today + VALUES(events_today),
              events_total    = events_total + VALUES(events_total)
        """, (connector_id, event_count, event_count))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Sync state update error: {e}")

def update_connector_status(connector_id: int, status: str, error=None):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("""
            UPDATE platform_connectors
            SET last_sync_at=NOW(), last_sync_status=%s, last_error=%s
            WHERE id=%s
        """, (status, error, connector_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Connector status update error: {e}")


# ── MAIN SYNC LOOP ────────────────────────────────────────────
def sync_all_connectors():
    """Fetch all active connectors and sync each one."""
    try:
        conn = get_conn()
        cur  = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT pc.*, c.name AS customer_name
            FROM platform_connectors pc
            JOIN customers c ON c.id = pc.customer_id
            WHERE pc.active = 1
            ORDER BY pc.customer_id
        """)
        connectors = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Failed to load connectors: {e}")
        return

    if not connectors:
        log.info("No active connectors found")
        return

    log.info(f"Syncing {len(connectors)} connectors...")

    for row in connectors:
        ctype = row["connector_type"]
        cname = row.get("customer_name","")
        cid   = row["id"]

        if ctype in ("postfix_agent", "webhook", "generic_api"):
            log.info(f"Skipping {ctype} connector {cid} (push-based)")
            continue

        log.info(f"Syncing [{ctype}] customer={cname} connector_id={cid}")

        try:
            connector = get_connector(row)
            since     = get_last_sync(cid)
            events    = connector.fetch_events(since)
            saved     = save_events(events, cid)

            update_sync_state(cid, saved)
            update_connector_status(cid, "ok")

            log.info(f"  ✅ {ctype}/{cname}: {len(events)} fetched, {saved} saved")

            # Push to AI processing queue
            if saved > 0:
                trigger_ai_processing(row["customer_id"])

        except Exception as e:
            log.error(f"  ❌ {ctype}/{cname}: {e}")
            update_connector_status(cid, "error", str(e)[:500])


def trigger_ai_processing(customer_id: int):
    """Notify dashboard to process new events through AI."""
    try:
        requests.post(
            f"{DASHBOARD_URL}/api/connectors/process",
            json={"customer_id": customer_id},
            headers={"X-Agent-Secret": AGENT_SECRET},
            timeout=3,
        )
    except Exception:
        pass


# ── ENTRY POINT ───────────────────────────────────────────────
if __name__ == "__main__":
    log.info("=" * 60)
    log.info("Worktual Universal Email Security Connector")
    log.info(f"Supported platforms: {list(CONNECTOR_MAP.keys())}")
    log.info(f"Poll interval: {POLL_INTERVAL}s")
    log.info("=" * 60)

    ensure_schema()

    while True:
        try:
            sync_all_connectors()
        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.error(f"Sync loop error: {e}")

        log.info(f"Sleeping {POLL_INTERVAL}s...")
        time.sleep(POLL_INTERVAL)
