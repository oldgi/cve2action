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
from cve2action.normalization.exposure import derive_asset_context  # noqa: E402
from cve2action.rules import load_rules  # noqa: E402

OUT = ROOT / "data" / "synthetic" / "northstar"

ASSET_HEADER = ["asset_id", "hostname", "zone", "environment", "business_role", "criticality",
                "crown_jewel", "owner_team"]
CONTROL_HEADER = ["asset_id", "control_type", "effectiveness", "evidence", "verified_at"]
CONTEXT_HEADER = ["asset", "environment", "reachability", "control_effectiveness",
                  "business_criticality", "reachability_source", "control_source"]

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
    asset_dicts = [dict(zip(ASSET_HEADER, row, strict=True)) for row in ASSETS]
    control_dicts = [dict(zip(CONTROL_HEADER, row, strict=True)) for row in CONTROLS]
    context = derive_asset_context(asset_dicts, control_dicts, rules, SCENARIO_AS_OF)
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
    print(f"assets={len(ASSETS)} findings={len(FINDINGS)} controls={len(CONTROLS)} "
          f"crown_jewels={sum(1 for a in ASSETS if a[6] == 'yes')} distinct_cves={len(cves)}")


if __name__ == "__main__":
    main()
