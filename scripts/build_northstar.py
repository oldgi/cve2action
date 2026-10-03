"""從快照重建 Northstar 模擬資料集。

資料集是人工設計的（哪台機器有哪個漏洞、控制措施放在哪裡），但**每個 CVSS 都取自
`data/snapshots/` 的真實快照**，不手填。重跑本腳本不打網路，輸出必須逐位元組相同。

執行：uv run python scripts/build_northstar.py
"""

from __future__ import annotations

import csv
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cve2action.collectors.nvd import load_snapshots  # noqa: E402
from cve2action.normalization.business import derive_business_context  # noqa: E402
from cve2action.normalization.exposure import derive_asset_context  # noqa: E402
from cve2action.rules import load_rules  # noqa: E402

OUT = ROOT / "data" / "synthetic" / "northstar"

ASSET_HEADER = ["asset_id", "hostname", "zone", "environment", "business_role",
                "declared_criticality", "crown_jewel", "owner_team"]
BUSINESS_HEADER = ["asset_id", "data_class", "rto_hours", "customer_facing", "notes"]
CONTROL_HEADER = ["asset_id", "control_type", "effectiveness", "evidence", "verified_at"]
NETWORK_HEADER = ["source", "target", "port", "protocol", "allowed"]
IDENTITY_HEADER = ["account", "source", "target", "privilege"]
REMEDIATION_HEADER = ["remediation_id", "asset", "cve", "action", "effort_hours",
                      "downtime_minutes", "compatibility", "notes"]
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
    ("svc_order", "NS-APP-ORDER-01", "NS-DB-CUSTOMER-01", "db_read_write"),
    ("svc_billing", "NS-APP-BILLING-01", "NS-DB-BILLING-01", "db_read_write"),
    ("svc_report", "NS-APP-REPORT-01", "NS-DB-CUSTOMER-01", "db_read_only"),
    ("svc_backup", "NS-BACKUP-01", "NS-DB-CUSTOMER-01", "db_read_only"),
    ("svc_monitor", "NS-MON-01", "NS-APP-ORDER-01", "local_service"),
    ("adm_platform", "NS-JUMP-01", "NS-DB-CUSTOMER-01", "local_admin"),
    ("adm_platform", "NS-JUMP-01", "NS-DB-BILLING-01", "local_admin"),
    ("adm_domain", "NS-JUMP-01", "NS-AD-DC-01", "domain_admin"),
    ("break_glass", "NS-JUMP-01", "NS-AD-DC-01", "domain_admin"),
    ("ops_desktop", "NS-OPS-WS-07", "NS-JUMP-01", "interactive_logon"),
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
    print(f"declared vs derived criticality: {len(disagreements)} disagreement(s)")
    for asset_id, declared, derived, source in disagreements:
        print(f"  {asset_id:<22} {declared:<10} -> {derived:<10} ({source})")


if __name__ == "__main__":
    main()
