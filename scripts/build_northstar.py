"""從快照重建 Northstar 模擬資料集。

資料集是人工設計的（哪台機器有哪個漏洞、控制措施放在哪裡），但**每個 CVSS 都取自
`data/snapshots/` 的真實快照**，不手填。重跑本腳本不打網路，輸出必須逐位元組相同。

執行：uv run python scripts/build_northstar.py
"""

from __future__ import annotations

import csv
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cve2action.collectors.nvd import load_snapshots  # noqa: E402
from cve2action.normalization.business import derive_business_context  # noqa: E402
from cve2action.normalization.exposure import derive_asset_context  # noqa: E402
from cve2action.rules import load_rules  # noqa: E402

# 預設寫進版控目錄；測試用 NORTHSTAR_OUT 導到暫存目錄，
# 才不會在跑測試時改寫其他測試正在讀的檔案。
OUT = Path(os.environ.get("NORTHSTAR_OUT") or ROOT / "data" / "synthetic" / "northstar")

ASSET_HEADER = ["asset_id", "hostname", "zone", "environment", "business_role",
                "declared_criticality", "crown_jewel", "owner_team"]
BUSINESS_HEADER = ["asset_id", "data_class", "rto_hours", "customer_facing", "notes"]
CONTROL_HEADER = ["asset_id", "control_type", "effectiveness", "evidence", "verified_at"]
NETWORK_HEADER = ["source", "target", "port", "protocol", "allowed"]
IDENTITY_HEADER = ["account", "source", "target", "privilege",
                   "credential_source", "requires_privilege"]
REMEDIATION_HEADER = ["remediation_id", "asset", "cve", "action", "effort_hours",
                      "downtime_minutes", "compatibility", "notes"]
INTERFACE_HEADER = ["interface_id", "asset_id", "ip", "hostname", "mac", "interface_type"]
SERVICE_HEADER = ["asset_id", "port", "protocol", "service", "version", "state",
                  "runs_as"]
POLICY_HEADER = ["policy_id", "source_scope", "destination", "port", "action", "verified_at"]
# Day 25 的適用性閘門：裝的到底是哪一版，以及我們憑什麼這樣說。
# 刻意**以 (asset_id, cve) 為鍵**，不靠服務名 join——Day 21 已經證明名字對不起來
# （服務名只對得上 15/40）。「這個 CVE 該看哪個產品的版本」是人的判斷，
# 寫進資料裡看得見、審得到，比埋在比對規則裡安全。
VERSION_EVIDENCE_HEADER = ["asset_id", "cve", "product", "cpe_product", "version",
                           "source", "verified_at", "notes"]
# Day 25／藍圖 §9.6：「任何 P0/P1 降級都必須留下原因、核准人與有效期限。」
# 這是那句話的載體。沒有這一列，就沒有人可以把一筆 finding 降下來。
RISK_ACCEPTANCE_HEADER = ["acceptance_id", "asset", "cve", "status", "reason",
                          "approver", "valid_until", "ref"]
CONTEXT_HEADER = ["asset", "environment", "reachability", "control_effectiveness",
                  "business_criticality", "reachability_source", "control_source",
                  "business_source"]

# 虛構公司 Northstar Digital Services：20 項資產、4 項 Crown Jewel。
# asset_id, hostname, zone, environment, business_role, criticality, crown_jewel, owner_team
ASSETS = [
    ("NS-WEB-PORTAL-01", "web-portal-01", "DMZ", "PROD", "customer_portal", "CRITICAL", "no", "platform-team"),
    ("NS-WEB-PORTAL-02", "web-portal-02", "DMZ", "PROD", "customer_portal", "CRITICAL", "no", "platform-team"),
    ("NS-API-GW-01", "api-gw-01", "DMZ", "PROD", "api_gateway", "CRITICAL", "no", "platform-team"),
    ("NS-MAIL-GW-01", "mail-gw-01", "DMZ", "PROD", "mail_gateway", "CRITICAL", "no", "it-ops"),
    ("NS-VPN-GW-01", "vpn-gw-01", "DMZ", "PROD", "remote_access", "CRITICAL", "no", "network-team"),
    ("NS-EDGE-RTR-01", "edge-rtr-01", "DMZ", "PROD", "edge_router", "CRITICAL", "no", "network-team"),
    ("NS-APP-ORDER-01", "app-order-01", "APP", "PROD", "order_service", "CRITICAL", "no", "order-team"),
    ("NS-APP-BILLING-01", "app-billing-01", "APP", "PROD", "billing_service", "CRITICAL", "no", "billing-team"),
    ("NS-APP-INTRANET-01", "app-intranet-01", "APP", "PROD", "intranet_app", "IMPORTANT", "no", "it-ops"),
    ("NS-APP-REPORT-01", "app-report-01", "APP", "PROD", "reporting", "NORMAL", "no", "data-team"),
    ("NS-DB-CUSTOMER-01", "db-customer-01", "DATA", "PROD", "customer_database", "CRITICAL", "yes", "dba-team"),
    ("NS-DB-BILLING-01", "db-billing-01", "DATA", "PROD", "billing_database", "CRITICAL", "yes", "dba-team"),
    ("NS-BACKUP-01", "backup-01", "DATA", "PROD", "backup_vault", "CRITICAL", "yes", "it-ops"),
    ("NS-FILE-SRV-01", "file-srv-01", "CORP", "PROD", "file_server", "NORMAL", "no", "it-ops"),
    ("NS-AD-DC-01", "ad-dc-01", "MGMT", "PROD", "domain_controller", "CRITICAL", "yes", "identity-team"),
    ("NS-JUMP-01", "jump-01", "MGMT", "PROD", "admin_jump_host", "CRITICAL", "no", "infra-sec"),
    ("NS-MON-01", "mon-01", "MGMT", "PROD", "monitoring", "IMPORTANT", "no", "sre-team"),
    ("NS-OPS-WS-07", "ops-ws-07", "CORP", "PROD", "ops_workstation", "IMPORTANT", "no", "it-ops"),
    ("NS-PLC-DC-ENV", "plc-dc-env", "OT", "PROD", "datacenter_hvac", "IMPORTANT", "no", "facility-team"),
    ("NS-LAB-CONFLUENCE-01", "lab-confluence-01", "LAB", "NON_PROD", "lab_wiki", "NORMAL", "no", "platform-team"),
]

# 業務事實（Day 13）。criticality 不再手標，由這三欄推導。
# asset_id, data_class, rto_hours, customer_facing, notes
BUSINESS = [
    ("NS-WEB-PORTAL-01", "INTERNAL", "2", "yes", "customer sign-in and self-service"),
    ("NS-WEB-PORTAL-02", "INTERNAL", "2", "yes", "same service behind the load balancer"),
    ("NS-API-GW-01", "INTERNAL", "2", "yes", "partner and mobile API entry point"),
    ("NS-MAIL-GW-01", "CONFIDENTIAL", "8", "no", "internal mail; queues survive a short outage"),
    ("NS-VPN-GW-01", "INTERNAL", "4", "no", "staff remote access; no customer traffic"),
    ("NS-EDGE-RTR-01", "NONE", "1", "no", "all north-south traffic; nothing works without it"),
    ("NS-APP-ORDER-01", "CONFIDENTIAL", "2", "yes", "order capture; downtime loses transactions"),
    ("NS-APP-BILLING-01", "RESTRICTED", "4", "no", "handles cardholder and tax data"),
    ("NS-APP-INTRANET-01", "INTERNAL", "48", "no", "staff wiki and forms; tolerable for two days"),
    ("NS-APP-REPORT-01", "INTERNAL", "72", "no", "nightly management reports"),
    ("NS-DB-CUSTOMER-01", "RESTRICTED", "2", "no", "personal data under contract and law"),
    ("NS-DB-BILLING-01", "RESTRICTED", "4", "no", "billing records under audit scope"),
    ("NS-BACKUP-01", "RESTRICTED", "24", "no", "holds copies of everything above"),
    ("NS-FILE-SRV-01", "INTERNAL", "24", "no", "shared drives; a day offline stops several teams"),
    ("NS-AD-DC-01", "CONFIDENTIAL", "1", "no", "authentication for every other system"),
    ("NS-JUMP-01", "NONE", "4", "no", "no data of its own; without it nothing can be administered"),
    ("NS-MON-01", "INTERNAL", "8", "no", "alerting; blind spot grows with every hour down"),
    ("NS-OPS-WS-07", "INTERNAL", "24", "no", "one operator's endpoint; work can move to a spare"),
    ("NS-PLC-DC-ENV", "NONE", "2", "no", "server room cooling; overheats within hours"),
    ("NS-LAB-CONFLUENCE-01", "NONE", "168", "no", "throwaway lab wiki"),
]

# 8 項已部署的控制措施；effectiveness 需要證據支撐，證明不了就是 UNKNOWN。
CONTROLS = [
    ("NS-WEB-PORTAL-01", "waf", "STRONG", "blocking rules tuned for this app; quarterly bypass test", "2026-08-14"),
    ("NS-API-GW-01", "waf", "PARTIAL", "shared ruleset, not tuned for API schemas", "2026-08-14"),
    ("NS-MAIL-GW-01", "edr", "PARTIAL", "detects post-exploitation, no pre-auth blocking evidence", "2026-09-02"),
    ("NS-APP-INTRANET-01", "edr", "UNKNOWN", "agent installed; no test covering this exploit class", "2026-05-30"),
    ("NS-DB-CUSTOMER-01", "network_segmentation", "STRONG", "allowlist verified by negative test", "2026-09-10"),
    ("NS-DB-BILLING-01", "network_segmentation", "STRONG", "allowlist verified by negative test", "2026-09-10"),
    ("NS-AD-DC-01", "mfa_admin_tiering", "STRONG", "tier-0 accounts enforce phishing-resistant MFA", "2026-08-28"),
    ("NS-JUMP-01", "mfa", "PARTIAL", "MFA enforced; session recording gaps on break-glass account", "2026-09-05"),
]

# 情境時點。必須固定，不能用今天的日期——否則控制證據的年齡每天都變，資料集就不可重現。

# 藍圖 §8.2：25 條網路連線。INTERNET 是外部來源的虛擬節點。
# allowed=no 的那一條是刻意留的：未允許的連線不得被當成可達路徑（§16 Day 24 門檻）。
# NS-PLC-DC-ENV 一條邊都沒有——「沒有已知路徑」不等於「證明不可達」，Day 22 不得混用。
NETWORK_EDGES = [
    ("INTERNET", "NS-EDGE-RTR-01", 443, "tcp", "yes"),
    ("INTERNET", "NS-WEB-PORTAL-01", 443, "tcp", "yes"),
    ("INTERNET", "NS-WEB-PORTAL-02", 443, "tcp", "yes"),
    ("INTERNET", "NS-API-GW-01", 443, "tcp", "yes"),
    ("INTERNET", "NS-MAIL-GW-01", 443, "tcp", "yes"),
    ("INTERNET", "NS-VPN-GW-01", 443, "tcp", "yes"),
    ("NS-WEB-PORTAL-01", "NS-APP-ORDER-01", 8080, "tcp", "yes"),
    ("NS-WEB-PORTAL-02", "NS-APP-ORDER-01", 8080, "tcp", "yes"),
    ("NS-API-GW-01", "NS-APP-ORDER-01", 8080, "tcp", "yes"),
    ("NS-API-GW-01", "NS-APP-BILLING-01", 8443, "tcp", "yes"),
    ("NS-VPN-GW-01", "NS-JUMP-01", 3389, "tcp", "yes"),
    ("NS-MAIL-GW-01", "NS-AD-DC-01", 389, "tcp", "yes"),
    ("NS-APP-ORDER-01", "NS-DB-CUSTOMER-01", 5432, "tcp", "yes"),
    ("NS-APP-BILLING-01", "NS-DB-BILLING-01", 5432, "tcp", "yes"),
    ("NS-APP-REPORT-01", "NS-DB-CUSTOMER-01", 5432, "tcp", "yes"),
    ("NS-APP-INTRANET-01", "NS-FILE-SRV-01", 445, "tcp", "yes"),
    ("NS-JUMP-01", "NS-DB-CUSTOMER-01", 5432, "tcp", "yes"),
    ("NS-JUMP-01", "NS-DB-BILLING-01", 5432, "tcp", "yes"),
    ("NS-JUMP-01", "NS-AD-DC-01", 3389, "tcp", "yes"),
    ("NS-JUMP-01", "NS-APP-ORDER-01", 22, "tcp", "yes"),
    ("NS-MON-01", "NS-APP-ORDER-01", 9100, "tcp", "yes"),
    ("NS-AD-DC-01", "NS-FILE-SRV-01", 445, "tcp", "yes"),
    ("NS-OPS-WS-07", "NS-JUMP-01", 3389, "tcp", "yes"),
    ("NS-DB-CUSTOMER-01", "NS-BACKUP-01", 873, "tcp", "yes"),
    ("NS-LAB-CONFLUENCE-01", "NS-FILE-SRV-01", 445, "tcp", "no"),
]

# 藍圖 §8.2：10 條帳號或權限關係。break_glass 那一條對應 controls.csv 裡
# NS-JUMP-01 的 mfa/PARTIAL 證據「session recording gaps on break-glass account」。
IDENTITY_EDGES = [
    ("svc_order", "NS-APP-ORDER-01", "NS-DB-CUSTOMER-01", "db_read_write", "config_file", "local_service"),
    ("svc_billing", "NS-APP-BILLING-01", "NS-DB-BILLING-01", "db_read_write", "config_file", "local_service"),
    ("svc_report", "NS-APP-REPORT-01", "NS-DB-CUSTOMER-01", "db_read_only", "config_file", "local_service"),
    ("svc_backup", "NS-BACKUP-01", "NS-DB-CUSTOMER-01", "db_read_only", "agent_token", "local_admin"),
    ("svc_monitor", "NS-MON-01", "NS-APP-ORDER-01", "local_service", "config_file", "local_service"),
    ("adm_platform", "NS-JUMP-01", "NS-DB-CUSTOMER-01", "local_admin", "memory", "local_admin"),
    ("adm_platform", "NS-JUMP-01", "NS-DB-BILLING-01", "local_admin", "memory", "local_admin"),
    ("adm_domain", "NS-JUMP-01", "NS-AD-DC-01", "domain_admin", "memory", "local_admin"),
    ("break_glass", "NS-JUMP-01", "NS-AD-DC-01", "domain_admin", "sealed_credential", "interactive_logon"),
    ("ops_desktop", "NS-OPS-WS-07", "NS-JUMP-01", "interactive_logon", "interactive_only", "interactive_logon"),
]

# 藍圖 §8.2：15 種候選修補措施。以 (asset, cve) 為鍵——scanner.csv 沒有 finding_id，
# 而 (資產, 漏洞) 本來就是全專案一致的自然鍵（見 scoring/calibration.key_of）。
# effort_hours／downtime_minutes 是虛構估計；Day 26 的成本比較會用到，Day 19 還不會。
REMEDIATIONS = [
    ("REM-001", "NS-EDGE-RTR-01", "CVE-2023-20198", "patch", 2, 15, "none", "廠商已釋出修補；需重啟"),
    ("REM-002", "NS-EDGE-RTR-01", "CVE-2023-20198", "disable_service", 1, 0, "none", "關閉 WebUI 管理介面，改用 CLI"),
    ("REM-003", "NS-APP-BILLING-01", "CVE-2023-34362", "patch", 4, 30, "none", "MOVEit 升級至修補版本"),
    ("REM-004", "NS-APP-BILLING-01", "CVE-2023-34362", "isolate", 2, 0, "breaks_partner_upload", "暫時移除對外傳輸介面"),
    ("REM-005", "NS-API-GW-01", "CVE-2021-44228", "patch", 3, 20, "none", "log4j2 升級"),
    ("REM-006", "NS-API-GW-01", "CVE-2021-44228", "compensating_control", 1, 0, "none", "WAF 規則比對 JNDI 字串；擋得住已知樣態，不是根治"),
    ("REM-007", "NS-APP-ORDER-01", "CVE-2021-44228", "patch", 3, 20, "none", "同一個 CVE，三台機器各自要排"),
    ("REM-008", "NS-APP-ORDER-01", "CVE-2021-44228", "config_change", 1, 10, "none", "移除 JndiLookup class，不動版本"),
    ("REM-009", "NS-MON-01", "CVE-2021-44228", "compensating_control", 1, 0, "vendor_appliance", "監控套件不可自行升版，只能移除 JndiLookup"),
    ("REM-010", "NS-DB-CUSTOMER-01", "CVE-2021-3156", "patch", 1, 5, "none", "sudo 套件更新"),
    ("REM-011", "NS-DB-BILLING-01", "CVE-2022-0847", "patch", 2, 45, "requires_kernel_reboot", "核心更新，需安排維護窗口"),
    ("REM-012", "NS-AD-DC-01", "CVE-2020-1472", "patch", 3, 60, "legacy_client_risk", "Netlogon 強制安全通道，舊用戶端可能失效"),
    ("REM-013", "NS-JUMP-01", "CVE-2019-0708", "config_change", 1, 0, "none", "啟用 NLA，把免驗證利用擋在驗證之前"),
    ("REM-014", "NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "isolate", 1, 0, "none", "實驗室系統，直接從網路移除比排修補快"),
    ("REM-015", "NS-WEB-PORTAL-01", "CVE-2013-2566", "config_change", 1, 0, "breaks_legacy_clients", "停用 RC4 密碼套件"),
]


# 藍圖 §8.3：多介面資產歸併的證據（Day 19）。
# 20 台資產、30 個介面——同一台機器的 service／management／backup／vip 介面各有 IP，
# 弱掃若按 IP 回報就會把一台機器算成好幾台。歸併依據是 MAC 與 hostname，不是 IP。
# NS-SHADOW-NAS-02 刻意不在這裡：掃描掃到它、清冊沒有它，那正是它 NEEDS_CONTEXT 的原因。
ASSET_INTERFACES = [
    ("IF-001", "NS-WEB-PORTAL-01", "203.0.113.11", "portal-a.northstar.example", "02:1a:00:00:11:01", "service"),
    ("IF-002", "NS-WEB-PORTAL-01", "10.20.0.11", "portal-a-mgmt.northstar.example", "02:1a:00:00:11:02", "management"),
    ("IF-003", "NS-WEB-PORTAL-01", "203.0.113.10", "www.northstar.example", "02:1a:00:00:11:01", "vip"),
    ("IF-004", "NS-WEB-PORTAL-02", "203.0.113.12", "portal-b.northstar.example", "02:1a:00:00:12:01", "service"),
    ("IF-005", "NS-WEB-PORTAL-02", "203.0.113.10", "www.northstar.example", "02:1a:00:00:12:01", "vip"),
    ("IF-006", "NS-API-GW-01", "203.0.113.21", "api.northstar.example", "02:1a:00:00:21:01", "service"),
    ("IF-007", "NS-API-GW-01", "10.20.0.21", "api-mgmt.northstar.example", "02:1a:00:00:21:02", "management"),
    ("IF-008", "NS-MAIL-GW-01", "203.0.113.31", "mail.northstar.example", "02:1a:00:00:31:01", "service"),
    ("IF-009", "NS-VPN-GW-01", "203.0.113.41", "vpn.northstar.example", "02:1a:00:00:41:01", "service"),
    ("IF-010", "NS-EDGE-RTR-01", "203.0.113.1", "edge-rtr.northstar.example", "02:1a:00:00:01:01", "service"),
    ("IF-011", "NS-EDGE-RTR-01", "10.20.0.1", "edge-rtr-mgmt.northstar.example", "02:1a:00:00:01:02", "management"),
    ("IF-012", "NS-APP-ORDER-01", "10.30.1.11", "app-order-01.northstar.example", "02:1a:00:01:11:01", "service"),
    ("IF-013", "NS-APP-ORDER-01", "10.20.1.11", "app-order-01-mgmt.northstar.example", "02:1a:00:01:11:02", "management"),
    ("IF-014", "NS-APP-BILLING-01", "10.30.1.12", "app-billing-01.northstar.example", "02:1a:00:01:12:01", "service"),
    ("IF-015", "NS-APP-INTRANET-01", "10.30.1.13", "intranet.northstar.example", "02:1a:00:01:13:01", "service"),
    ("IF-016", "NS-APP-REPORT-01", "10.30.1.14", "report.northstar.example", "02:1a:00:01:14:01", "service"),
    ("IF-017", "NS-DB-CUSTOMER-01", "10.40.1.11", "db-cust-01.northstar.example", "02:1a:00:02:11:01", "service"),
    ("IF-018", "NS-DB-CUSTOMER-01", "10.41.1.11", "db-cust-01-bkp.northstar.example", "02:1a:00:02:11:02", "backup"),
    ("IF-019", "NS-DB-BILLING-01", "10.40.1.12", "db-bill-01.northstar.example", "02:1a:00:02:12:01", "service"),
    ("IF-020", "NS-DB-BILLING-01", "10.41.1.12", "db-bill-01-bkp.northstar.example", "02:1a:00:02:12:02", "backup"),
    ("IF-021", "NS-BACKUP-01", "10.41.1.20", "backup-vault.northstar.example", "02:1a:00:02:20:01", "service"),
    ("IF-022", "NS-FILE-SRV-01", "10.50.1.30", "files.northstar.example", "02:1a:00:03:30:01", "service"),
    ("IF-023", "NS-AD-DC-01", "10.60.1.10", "dc01.northstar.example", "02:1a:00:04:10:01", "service"),
    ("IF-024", "NS-AD-DC-01", "10.20.1.10", "dc01-mgmt.northstar.example", "02:1a:00:04:10:02", "management"),
    ("IF-025", "NS-JUMP-01", "10.60.1.20", "jump01.northstar.example", "02:1a:00:04:20:01", "service"),
    ("IF-026", "NS-MON-01", "10.60.1.30", "mon01.northstar.example", "02:1a:00:04:30:01", "service"),
    ("IF-027", "NS-OPS-WS-07", "10.50.2.7", "ws-ops-07.northstar.example", "02:1a:00:03:07:01", "service"),
    ("IF-028", "NS-PLC-DC-ENV", "10.70.1.5", "plc-hvac-01.northstar.example", "02:1a:00:05:05:01", "service"),
    ("IF-029", "NS-LAB-CONFLUENCE-01", "10.80.1.9", "lab-wiki.northstar.example", "02:1a:00:06:09:01", "service"),
    ("IF-030", "NS-LAB-CONFLUENCE-01", "10.80.1.10", "wiki-old.northstar.example", "02:1a:00:06:09:01", "service"),
]

# 有效攻擊面（Day 20）。每一條「允許」的連線，目的端都必須真的有服務在聽，
# 否則那條邊通往空氣——有測試強制這件事。
# state=filtered 代表服務在、但被主機防火牆擋住；路徑分析不得把它當成走得通。
SERVICES = [
    ("NS-EDGE-RTR-01", 443, "tcp", "ios-xe-webui", "17.6.1", "listening", "local_admin"),
    ("NS-WEB-PORTAL-01", 443, "tcp", "apache-httpd", "2.4.49", "listening", "local_service"),
    ("NS-WEB-PORTAL-01", 80, "tcp", "apache-httpd", "2.4.49", "closed", "local_service"),
    ("NS-WEB-PORTAL-02", 443, "tcp", "apache-httpd", "2.4.49", "listening", "local_service"),
    ("NS-WEB-PORTAL-02", 80, "tcp", "apache-httpd", "2.4.49", "closed", "local_service"),
    ("NS-API-GW-01", 443, "tcp", "nginx", "1.20.1", "listening", "local_service"),
    ("NS-MAIL-GW-01", 443, "tcp", "exchange-owa", "15.2.792", "listening", "local_service"),
    ("NS-VPN-GW-01", 443, "tcp", "fortios-ssl-vpn", "6.0.4", "listening", "local_admin"),
    ("NS-APP-ORDER-01", 8080, "tcp", "tomcat", "9.0.30", "listening", "local_service"),
    ("NS-APP-ORDER-01", 22, "tcp", "openssh", "8.2p1", "listening", "interactive_logon"),
    ("NS-APP-ORDER-01", 9100, "tcp", "node-exporter", "1.3.1", "listening", "local_service"),
    ("NS-APP-BILLING-01", 8443, "tcp", "moveit-transfer", "15.0.1", "listening", "local_service"),
    ("NS-APP-INTRANET-01", 8090, "tcp", "confluence", "8.5.1", "listening", "local_service"),
    ("NS-APP-REPORT-01", 8009, "tcp", "tomcat-ajp", "9.0.30", "listening", "local_service"),
    ("NS-DB-CUSTOMER-01", 5432, "tcp", "postgresql", "14.5", "listening", "local_service"),
    ("NS-DB-BILLING-01", 5432, "tcp", "postgresql", "14.5", "listening", "local_service"),
    ("NS-BACKUP-01", 873, "tcp", "rsync", "3.2.3", "listening", "local_service"),
    ("NS-BACKUP-01", 445, "tcp", "smb", "1.0", "filtered", "local_service"),
    ("NS-FILE-SRV-01", 445, "tcp", "smb", "1.0", "listening", "local_service"),
    ("NS-FILE-SRV-01", 22, "tcp", "openssh", "7.4p1", "listening", "interactive_logon"),
    ("NS-AD-DC-01", 389, "tcp", "ldap", "2019", "listening", "local_service"),
    ("NS-AD-DC-01", 3389, "tcp", "rdp", "10.0", "listening", "local_admin"),
    ("NS-AD-DC-01", 445, "tcp", "netlogon", "2019", "listening", "local_service"),
    ("NS-JUMP-01", 3389, "tcp", "rdp", "10.0", "listening", "local_admin"),
    ("NS-MON-01", 3000, "tcp", "grafana", "9.1.0", "listening", "local_service"),
    ("NS-OPS-WS-07", 445, "tcp", "smb", "3.1.1", "filtered", "local_service"),
    ("NS-PLC-DC-ENV", 44818, "tcp", "controllogix", "32.011", "listening", "local_admin"),
    ("NS-LAB-CONFLUENCE-01", 8090, "tcp", "confluence", "7.13.0", "listening", "local_service"),
]

# ACL 與正向列表（Day 20）。policy 以 zone 為範圍，network_edges 是實際觀測到的連線。
# port=0 代表整段範圍。兩者不一致時以觀測為準，但差異必須被指出來——
# 政策說不行卻連得通，就是設定漂移，不是把觀測刪掉了事。
NETWORK_POLICIES = [
    ("POL-01", "INTERNET", "DMZ", 443, "allow", "2026-09-12"),
    ("POL-02", "INTERNET", "APP", 0, "deny", "2026-09-12"),
    ("POL-03", "INTERNET", "DATA", 0, "deny", "2026-09-12"),
    ("POL-04", "DMZ", "APP", 8080, "allow", "2026-09-12"),
    ("POL-05", "DMZ", "APP", 8443, "allow", "2026-09-12"),
    ("POL-06", "DMZ", "MGMT", 3389, "allow", "2026-08-30"),
    ("POL-07", "DMZ", "DATA", 0, "deny", "2026-09-12"),
    ("POL-08", "APP", "DATA", 5432, "allow", "2026-09-10"),
    ("POL-09", "MGMT", "DATA", 5432, "allow", "2026-09-10"),
    ("POL-10", "MGMT", "APP", 0, "allow", "2026-08-30"),
    ("POL-11", "CORP", "MGMT", 3389, "allow", "2026-09-05"),
    ("POL-12", "CORP", "DATA", 0, "deny", "2026-09-12"),
    ("POL-13", "APP", "CORP", 445, "allow", "2026-09-10"),
    ("POL-14", "MGMT", "CORP", 445, "allow", "2026-08-30"),
    ("POL-15", "LAB", "CORP", 0, "deny", "2026-09-12"),
    ("POL-16", "OT", "CORP", 0, "deny", "2026-09-12"),
]

SCENARIO_AS_OF = date(2026, 9, 24)

# 40 筆掃描發現。真實弱掃報告是金字塔：少數 RCE、大量弱加密與資訊洩漏。
# asset, cve, service
FINDINGS = [
    ("NS-WEB-PORTAL-01", "CVE-2021-41773", "apache-httpd"),
    ("NS-WEB-PORTAL-01", "CVE-2023-44487", "nginx-http2"),
    ("NS-WEB-PORTAL-01", "CVE-2013-2566", "tls-rc4"),
    ("NS-WEB-PORTAL-02", "CVE-2021-41773", "apache-httpd"),
    ("NS-WEB-PORTAL-02", "CVE-2023-44487", "nginx-http2"),
    ("NS-WEB-PORTAL-02", "CVE-2015-4000", "tls-dhe"),
    ("NS-API-GW-01", "CVE-2021-44228", "log4j2"),
    ("NS-API-GW-01", "CVE-2022-22965", "spring-boot"),
    ("NS-API-GW-01", "CVE-2016-2107", "openssl"),
    ("NS-MAIL-GW-01", "CVE-2021-26855", "exchange-owa"),
    ("NS-MAIL-GW-01", "CVE-2022-41082", "exchange-owa"),
    ("NS-MAIL-GW-01", "CVE-2011-3389", "tls-cbc"),
    ("NS-VPN-GW-01", "CVE-2024-21762", "fortios-ssl-vpn"),
    ("NS-VPN-GW-01", "CVE-2018-13379", "fortios-ssl-vpn"),
    ("NS-EDGE-RTR-01", "CVE-2023-20198", "ios-xe-webui"),
    ("NS-EDGE-RTR-01", "CVE-2025-21590", "junos-cli"),
    ("NS-APP-ORDER-01", "CVE-2021-44228", "log4j2"),
    ("NS-APP-ORDER-01", "CVE-2020-1938", "tomcat-ajp"),
    ("NS-APP-BILLING-01", "CVE-2023-34362", "moveit-transfer"),
    ("NS-APP-BILLING-01", "CVE-2021-3156", "sudo"),
    ("NS-APP-INTRANET-01", "CVE-2021-44228", "java-app"),
    ("NS-APP-INTRANET-01", "CVE-2023-22515", "confluence"),
    ("NS-APP-INTRANET-01", "CVE-2021-23017", "nginx-resolver"),
    ("NS-APP-REPORT-01", "CVE-2020-1938", "tomcat-ajp"),
    ("NS-APP-REPORT-01", "CVE-2016-2107", "openssl"),
    ("NS-DB-CUSTOMER-01", "CVE-2016-5195", "linux-kernel"),
    ("NS-DB-CUSTOMER-01", "CVE-2021-3156", "sudo"),
    ("NS-DB-BILLING-01", "CVE-2022-0847", "linux-kernel"),
    ("NS-BACKUP-01", "CVE-2017-0144", "smb-v1"),
    ("NS-BACKUP-01", "CVE-2014-0160", "openssl"),
    ("NS-FILE-SRV-01", "CVE-2017-0144", "smb-v1"),
    ("NS-FILE-SRV-01", "CVE-2018-15919", "openssh"),
    ("NS-AD-DC-01", "CVE-2020-1472", "netlogon"),
    ("NS-AD-DC-01", "CVE-2021-34527", "print-spooler"),
    ("NS-JUMP-01", "CVE-2019-0708", "rdp"),
    ("NS-MON-01", "CVE-2021-44228", "log4j2"),
    ("NS-OPS-WS-07", "CVE-2023-4863", "chromium-webp"),
    ("NS-PLC-DC-ENV", "CVE-2024-6242", "controllogix"),
    ("NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "confluence"),
    # 掃描器掃到、資產清冊裡沒有的機器：這是現實，也是 NEEDS_CONTEXT 的來源
    ("NS-SHADOW-NAS-02", "CVE-2017-0144", "smb-v1"),
]

# 掃描器認不出版本（留白），交給 NVD 快照補
SCANNER_BLANK = {("NS-PLC-DC-ENV", "CVE-2024-6242"), ("NS-MON-01", "CVE-2021-44228"),
                 ("NS-MAIL-GW-01", "CVE-2011-3389")}
# 掃描器回報的舊值，與 NVD 不一致；引擎會採快照並在 reason 註明
SCANNER_STALE = {("NS-JUMP-01", "CVE-2019-0708"): "9.9"}



# 版本證據（Day 25）。每一列的版本與範圍都對照過 data/snapshots/nvd 裡的真實 CPE，
# 不是編出來的——否則文章的數字就是在虛構上再疊一層虛構。
#
# source 的強弱是有差別的，這正是今天的重點：
#   package_manager／agent_inventory／vendor_portal —— 查得到安裝紀錄，可以定案
#   banner                                        —— 服務自己報的，**不能定案**
#                                                    （發行版回溯修補時 banner 不會變）
#   manual                                        —— 人工確認，要看 verified_at 新不新
#
# `cpe_product` 是**我們認定這台裝的東西在 NVD 裡叫什麼**。它必須寫出來，不能靠
# 名字比對猜：apache-httpd 在 CPE 裡叫 http_server、Confluence 分 confluence_server
# 與 confluence_data_center 兩個產品、windows-server 要連版號一起變成
# windows_server_2019。猜錯的後果不是漏判，是**誤判成不必修**。
VERSION_EVIDENCE = [
    # --- 版本落在受影響範圍內：APPLICABLE，該修 -----------------------------
    ("NS-WEB-PORTAL-01", "CVE-2021-41773", "apache-httpd", "http_server", "2.4.49", "package_manager",
     "2026-09-18", "CPE 只列 2.4.49 這一版，剛好命中"),
    ("NS-WEB-PORTAL-02", "CVE-2021-41773", "apache-httpd", "http_server", "2.4.49", "package_manager",
     "2026-09-18", "與 PORTAL-01 同一個映像檔"),
    ("NS-VPN-GW-01", "CVE-2024-21762", "fortios", "fortios", "6.0.4", "vendor_portal",
     "2026-09-20", "受影響 6.0.0–6.0.18"),
    ("NS-VPN-GW-01", "CVE-2018-13379", "fortios", "fortios", "6.0.4", "vendor_portal",
     "2026-09-20", "受影響 6.0.0–6.0.5；同一台同時中兩個"),
    ("NS-EDGE-RTR-01", "CVE-2023-20198", "ios-xe", "ios_xe", "17.6.1", "vendor_portal",
     "2026-09-20", "受影響 17.6–17.6.6a"),
    ("NS-APP-INTRANET-01", "CVE-2023-22515", "confluence", "confluence_server", "8.5.1", "agent_inventory",
     "2026-09-19", "受影響 8.5.0–8.5.2"),
    ("NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "confluence", "confluence_server", "7.13.0", "agent_inventory",
     "2026-09-19", "受影響 7.13.0–7.13.7"),
    ("NS-APP-REPORT-01", "CVE-2020-1938", "tomcat", "tomcat", "9.0.30", "package_manager",
     "2026-09-18", "受影響 9.0.0–9.0.31"),
    ("NS-AD-DC-01", "CVE-2020-1472", "windows-server", "windows_server_2019", "2019", "agent_inventory",
     "2026-09-17", "CPE 列 windows_server_2019"),

    # --- 版本落在範圍外：NOT_APPLICABLE，不必修 ------------------------------
    # 這是今天唯一「最便宜的處置」真的成立的一筆。注意量的是**作業系統**版本，
    # 不是 services.csv 裡那個 rdp 10.0——協定版本答不了這個 CVE 的問題。
    ("NS-JUMP-01", "CVE-2019-0708", "windows-server", "windows_server_2019", "2019", "agent_inventory",
     "2026-09-17", "CPE 只列 windows_7／windows_server_2008／2008_r2；2019 不在其中"),

    # --- 證據拿得出來，但定不了案：REVIEW_REQUIRED ---------------------------
    ("NS-FILE-SRV-01", "CVE-2018-15919", "openssh", "openssh", "7.4p1", "banner",
     "2026-09-21", "受影響 5.9–7.8，看起來命中——但這是 banner，發行版回溯修補後它不會變"),
    ("NS-APP-BILLING-01", "CVE-2023-34362", "moveit-transfer", "moveit_transfer", "15.0.1", "manual",
     "2026-09-15", "15.0.x 是 moveit_cloud 的編號；CPE 的 moveit_transfer 用 2021.x／2022.x，兩套編號對不起來"),
    ("NS-MAIL-GW-01", "CVE-2021-26855", "exchange-server", "exchange_server", "15.2.792", "agent_inventory",
     "2026-09-16", "15.2.x 是 Exchange 2019；CPE 以 2013／2016／2019 加 CU 編號表示，數字版本對不上去"),
    ("NS-PLC-DC-ENV", "CVE-2024-6242", "controllogix", "controllogix", "32.011", "manual",
     "2026-08-02", "NVD 這筆 configurations 是空的——沒有範圍可比，而且這份人工紀錄也過期了"),
]

# 風險接受（Day 25，藍圖 §9.6）。一列＝一次有紀錄的降級。
# status 為 APPROVED 且 valid_until 未過期才算數；過期的接受不是接受
# （與 Day 23 的豁免到期同一條紀律）。
RISK_ACCEPTANCES = [
    ("ACC-001", "NS-LAB-CONFLUENCE-01", "CVE-2022-26134", "APPROVED",
     "實驗室網段、不存業務資料、RTO 168 小時；下一個維護窗口隨版本升級一併處理",
     "林思妤（資安經理）", "2026-12-31", "RISK-2026-0418"),
    ("ACC-002", "NS-APP-REPORT-01", "CVE-2020-1938", "APPROVED",
     "AJP 連接埠僅綁定 127.0.0.1，前端不轉發；升級 Tomcat 需同步改報表排程",
     "陳柏翰（應用維運主管）", "2026-11-30", "RISK-2026-0392"),
    # 過期：日期已過 scenario 基準日，必須失效並重新送審
    ("ACC-003", "NS-WEB-PORTAL-02", "CVE-2021-41773", "APPROVED",
     "改版凍結期間暫緩，待 Q3 結束後處理",
     "陳柏翰（應用維運主管）", "2026-08-31", "RISK-2026-0301"),
    # 已撤銷：KEV 收錄之後撤回，用來證明「有人簽過」不等於「現在還算數」
    ("ACC-004", "NS-VPN-GW-01", "CVE-2018-13379", "REVOKED",
     "原以為僅限內部測試介面；CISA KEV 收錄後撤回此接受",
     "林思妤（資安經理）", "2026-12-31", "RISK-2025-0877"),
]


def write_csv(name: str, header: list[str], rows: list[tuple]) -> None:
    with (OUT / name).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    nvd = load_snapshots()
    rules = load_rules(ROOT / "config" / "risk_rules.yaml")

    write_csv("assets.csv", ASSET_HEADER, ASSETS)
    write_csv("controls.csv", CONTROL_HEADER, CONTROLS)
    write_csv("business_context.csv", BUSINESS_HEADER, BUSINESS)
    write_csv("network_edges.csv", NETWORK_HEADER, NETWORK_EDGES)
    write_csv("identity_edges.csv", IDENTITY_HEADER, IDENTITY_EDGES)
    write_csv("remediations.csv", REMEDIATION_HEADER, REMEDIATIONS)
    write_csv("asset_interfaces.csv", INTERFACE_HEADER, ASSET_INTERFACES)
    write_csv("services.csv", SERVICE_HEADER, SERVICES)
    write_csv("network_policies.csv", POLICY_HEADER, NETWORK_POLICIES)
    write_csv("version_evidence.csv", VERSION_EVIDENCE_HEADER, VERSION_EVIDENCE)
    write_csv("risk_acceptances.csv", RISK_ACCEPTANCE_HEADER, RISK_ACCEPTANCES)
    asset_dicts = [dict(zip(ASSET_HEADER, row, strict=True)) for row in ASSETS]
    control_dicts = [dict(zip(CONTROL_HEADER, row, strict=True)) for row in CONTROLS]
    business_dicts = [dict(zip(BUSINESS_HEADER, row, strict=True)) for row in BUSINESS]

    # Business Criticality 由業務事實推導，取代 assets.csv 上人標的 declared_criticality
    derived_business = derive_business_context(business_dicts, rules.business_impact)
    for asset in asset_dicts:
        asset["criticality"] = derived_business[asset["asset_id"]].value

    context = derive_asset_context(asset_dicts, control_dicts, rules, SCENARIO_AS_OF)
    for row in context:
        row["business_source"] = derived_business[row["asset"]].source
    write_csv("asset_context.csv", CONTEXT_HEADER,
              [tuple(row[col] for col in CONTEXT_HEADER) for row in context])

    rows = []
    for asset, cve, service in FINDINGS:
        key = (asset, cve)
        if key in SCANNER_BLANK:
            value = ""
        elif key in SCANNER_STALE:
            value = SCANNER_STALE[key]
        else:
            score = nvd[cve].cvss.preferred(("3.1", "4.0"))
            value = f"{score.base_score:g}" if score else ""
        rows.append((asset, cve, value, service))
    write_csv("scanner.csv", ["asset", "cve", "cvss", "service"], rows)

    cves = sorted({cve for _a, cve, _s in FINDINGS})
    disagreements = [(a["asset_id"], a["declared_criticality"], a["criticality"],
                      derived_business[a["asset_id"]].source)
                     for a in asset_dicts if a["declared_criticality"] != a["criticality"]]
    print(f"assets={len(ASSETS)} findings={len(FINDINGS)} controls={len(CONTROLS)} "
          f"crown_jewels={sum(1 for a in ASSETS if a[6] == 'yes')} distinct_cves={len(cves)}")
    print(f"network_edges={len(NETWORK_EDGES)} identity_edges={len(IDENTITY_EDGES)} "
          f"remediations={len(REMEDIATIONS)}")
    merged = len({row[1] for row in ASSET_INTERFACES})
    print(f"interfaces={len(ASSET_INTERFACES)} -> {merged} assets; "
          f"services={len(SERVICES)} policies={len(NETWORK_POLICIES)}")
    print(f"declared vs derived criticality: {len(disagreements)} disagreement(s)")
    for asset_id, declared, derived, source in disagreements:
        print(f"  {asset_id:<22} {declared:<10} -> {derived:<10} ({source})")


if __name__ == "__main__":
    main()
