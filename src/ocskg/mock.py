"""Offline, deterministic security scenarios for a customer-safe product demo.

The mock catalogue deliberately models security evidence as OCSF-shaped events,
alerts, graph entities, and retrieved playbook fragments.  It never creates a
network connection, but it uses the same API shapes as the live path so that a
demo can be switched to a real StarRocks deployment without changing the UI.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from .retrospective import analyze_historical_events
from .text_graph import extract_rule_graph

DEFAULT_SCENARIO = "credential_to_impact"

MOCK_TEXT_REPORTS = {
    "credential_to_impact": (
        "Analyst note: alice authenticated from 203.0.113.42 after repeated failures on "
        "web-01.prod.demo. The host then connected to 198.51.100.9 over TLS/4444 and is "
        "exposed to CVE-2025-9999."
    ),
    "cloud_account_takeover": (
        "Cloud review: jordan logged into acme-prod from 198.51.100.77 without MFA, assumed "
        "DataExportAdmin, and read customer-export-prod objects before a connection to 203.0.113.88."
    ),
    "ransomware_lateral_movement": (
        "Endpoint review: finance-lt-23 at 10.18.5.23 used SMB/445 to reach "
        "finance-fs01.corp.internal and finance-fs02.corp.internal. The file servers changed "
        "many .locked extensions after backup deletion."
    ),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _event(
    event_uid: str,
    time: str,
    class_uid: int,
    class_name: str,
    activity_name: str,
    severity: str,
    message: str,
    **fields: Any,
) -> dict[str, Any]:
    """Create a compact OCSF projection suitable for a visual investigation."""
    return {
        "event_uid": event_uid,
        "time": time,
        "class_uid": class_uid,
        "class_name": class_name,
        "activity_name": activity_name,
        "severity": severity,
        "message": message,
        "metadata": {"product": {"name": "SentinelGraph mock sensor"}},
        **fields,
    }


def _node(entity_id: str, entity_type: str, name: str, role: str) -> dict[str, Any]:
    return {"entity_id": entity_id, "entity_type": entity_type, "name": name, "role": role}


def _edge(
    edge_id: str,
    src_id: str,
    dst_id: str,
    relation: str,
    event_uid: str,
) -> dict[str, str]:
    return {
        "edge_id": edge_id,
        "src_id": src_id,
        "dst_id": dst_id,
        "relation": relation,
        "event_uid": event_uid,
    }


SCENARIOS: dict[str, dict[str, Any]] = {
    "credential_to_impact": {
        "id": "credential_to_impact",
        "title": "互联网凭证攻击 → 异常外联 → 高危暴露",
        "sector": "互联网业务 / Web 服务",
        "summary": "同一公网 IP 对生产账号实施口令喷洒，随后成功登录并从高危暴露的 Web 主机发起异常 TLS 外联。",
        "risk_score": 92,
        "confidence": "高（时间、账号、资产和网络证据可交叉验证）",
        "business_impact": "可能导致生产 Web 服务被远程控制，并进一步访问应用凭据或客户数据。",
        "primary_entity": "user:demo-alice",
        "events": [
            _event(
                "mock-auth-01",
                "2026-08-10T01:01:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Authentication failed: invalid password",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="failure",
            ),
            _event(
                "mock-auth-02",
                "2026-08-10T01:03:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Authentication failed: invalid password",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="failure",
            ),
            _event(
                "mock-auth-03",
                "2026-08-10T01:05:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Authentication failed: invalid password",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="failure",
            ),
            _event(
                "mock-auth-04",
                "2026-08-10T01:07:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Authentication failed: invalid password",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="failure",
            ),
            _event(
                "mock-auth-05",
                "2026-08-10T01:09:00Z",
                3002,
                "Authentication",
                "Logon",
                "high",
                "Authentication failed: invalid password",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="failure",
            ),
            _event(
                "mock-auth-success-01",
                "2026-08-10T01:12:00Z",
                3002,
                "Authentication",
                "Logon",
                "high",
                "Authentication succeeded after repeated failures",
                actor_user_name="alice",
                src_ip="203.0.113.42",
                device_hostname="web-01.prod.demo",
                status="success",
            ),
            _event(
                "mock-egress-01",
                "2026-08-10T01:16:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "Outbound TLS to rare external endpoint on port 4444",
                actor_user_name="alice",
                src_ip="10.24.8.15",
                dst_ip="198.51.100.9",
                dst_port=4444,
                protocol="tls",
                device_hostname="web-01.prod.demo",
            ),
            _event(
                "mock-egress-02",
                "2026-08-10T01:20:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "Repeated outbound TLS to rare external endpoint on port 4444",
                actor_user_name="alice",
                src_ip="10.24.8.15",
                dst_ip="198.51.100.9",
                dst_port=4444,
                protocol="tls",
                device_hostname="web-01.prod.demo",
            ),
            _event(
                "mock-egress-03",
                "2026-08-10T01:24:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "Repeated outbound TLS to rare external endpoint on port 4444",
                actor_user_name="alice",
                src_ip="10.24.8.15",
                dst_ip="198.51.100.9",
                dst_port=4444,
                protocol="tls",
                device_hostname="web-01.prod.demo",
            ),
            _event(
                "mock-vulnerability-01",
                "2026-08-10T01:25:00Z",
                2002,
                "Vulnerability Finding",
                "Scan",
                "critical",
                "Critical remote code execution exposure: CVE-2025-9999",
                device_hostname="web-01.prod.demo",
                resource_uid="pkg:openssl",
                cve="CVE-2025-9999",
                cvss_score=9.8,
            ),
        ],
        "alerts": [
            {
                "alert_id": "mock-auth-burst-001",
                "rule_id": "failed-authentication-burst",
                "severity": "high",
                "title": "口令喷洒：alice / 203.0.113.42（5 次失败）",
                "status": "new",
                "correlation_key": "alice|203.0.113.42",
                "evidence": {
                    "event_count": 5,
                    "window_minutes": 15,
                    "event_uids": [
                        "mock-auth-01",
                        "mock-auth-02",
                        "mock-auth-03",
                        "mock-auth-04",
                        "mock-auth-05",
                    ],
                },
            },
            {
                "alert_id": "mock-valid-account-001",
                "rule_id": "failed-then-success",
                "severity": "critical",
                "title": "失败后成功登录：alice / 203.0.113.42",
                "status": "new",
                "correlation_key": "alice|203.0.113.42",
                "evidence": {
                    "event_uids": ["mock-auth-05", "mock-auth-success-01"],
                    "sequence_minutes": 3,
                },
            },
            {
                "alert_id": "mock-egress-001",
                "rule_id": "suspicious-admin-egress",
                "severity": "high",
                "title": "异常外联：web-01.prod.demo → 198.51.100.9:4444",
                "status": "new",
                "correlation_key": "alice|10.24.8.15|198.51.100.9|4444",
                "evidence": {
                    "event_count": 3,
                    "protocol": "tls",
                    "event_uids": ["mock-egress-01", "mock-egress-02", "mock-egress-03"],
                },
            },
            {
                "alert_id": "mock-cve-001",
                "rule_id": "critical-vulnerability-exposure",
                "severity": "critical",
                "title": "关键漏洞暴露：web-01.prod.demo / CVE-2025-9999",
                "status": "new",
                "correlation_key": "demo-web-01|pkg:openssl",
                "evidence": {"severity": "critical", "event_uids": ["mock-vulnerability-01"]},
            },
        ],
        "nodes": [
            _node("user:demo-alice", "user", "alice", "compromised-account"),
            _node("asset:demo-web-01", "asset", "web-01.prod.demo", "affected-asset"),
            _node("ip:203.0.113.42", "ip", "203.0.113.42", "source"),
            _node("ip:198.51.100.9", "ip", "198.51.100.9", "destination"),
            _node("resource:pkg:openssl", "resource", "OpenSSL on web-01", "exposure"),
            _node("event:mock-auth-05", "event", "Authentication failures", "evidence"),
            _node("event:mock-auth-success-01", "event", "Successful login", "evidence"),
            _node("event:mock-egress-01", "event", "Rare TLS egress", "evidence"),
            _node("event:mock-vulnerability-01", "event", "Critical finding", "evidence"),
        ],
        "edges": [
            _edge("cred-1", "event:mock-auth-05", "user:demo-alice", "observed", "mock-auth-05"),
            _edge(
                "cred-2", "event:mock-auth-05", "ip:203.0.113.42", "originated_from", "mock-auth-05"
            ),
            _edge(
                "cred-3",
                "event:mock-auth-success-01",
                "user:demo-alice",
                "authenticated_as",
                "mock-auth-success-01",
            ),
            _edge(
                "cred-4",
                "event:mock-auth-success-01",
                "asset:demo-web-01",
                "accessed",
                "mock-auth-success-01",
            ),
            _edge(
                "cred-5",
                "event:mock-egress-01",
                "asset:demo-web-01",
                "observed_on",
                "mock-egress-01",
            ),
            _edge(
                "cred-6",
                "event:mock-egress-01",
                "ip:198.51.100.9",
                "connected_to",
                "mock-egress-01",
            ),
            _edge(
                "cred-7", "event:mock-egress-01", "user:demo-alice", "executed_as", "mock-egress-01"
            ),
            _edge(
                "cred-8",
                "event:mock-vulnerability-01",
                "resource:pkg:openssl",
                "found_in",
                "mock-vulnerability-01",
            ),
            _edge(
                "cred-9",
                "event:mock-vulnerability-01",
                "asset:demo-web-01",
                "affects",
                "mock-vulnerability-01",
            ),
        ],
        "documents": [
            {
                "chunk_id": "mock-playbook-auth",
                "score": 0.94,
                "content": "账号疑似失陷：封禁源 IP，吊销会话，重置凭据，并核验 MFA 与近期登录。",
            },
            {
                "chunk_id": "mock-playbook-egress",
                "score": 0.91,
                "content": "异常外联：隔离主机，保全进程与网络证据，并在出口阻断目标地址。",
            },
            {
                "chunk_id": "mock-playbook-cve",
                "score": 0.89,
                "content": "高危暴露：立即实施虚拟补丁或升级，确认漏洞利用痕迹与对外可达性。",
            },
        ],
        "presentation": {
            "attack_stages": [
                {
                    "stage": "01",
                    "title": "凭证压力",
                    "description": "5 次认证失败在 15 分钟内聚合为口令喷洒信号。",
                    "severity": "warning",
                    "evidence_refs": ["mock-auth-01", "mock-auth-05"],
                    "mitre": ["T1110"],
                },
                {
                    "stage": "02",
                    "title": "有效账号",
                    "description": "同源地址在最后一次失败后 3 分钟成功登录生产主机。",
                    "severity": "critical",
                    "evidence_refs": ["mock-auth-05", "mock-auth-success-01"],
                    "mitre": ["T1078"],
                },
                {
                    "stage": "03",
                    "title": "命令与控制疑似外联",
                    "description": "受影响主机连续连接罕见 TLS 目标 198.51.100.9:4444。",
                    "severity": "critical",
                    "evidence_refs": ["mock-egress-01", "mock-egress-03"],
                    "mitre": ["T1071"],
                },
                {
                    "stage": "04",
                    "title": "暴露面放大",
                    "description": "同一资产存在关键远程代码执行暴露，显著提高处置优先级。",
                    "severity": "critical",
                    "evidence_refs": ["mock-vulnerability-01"],
                    "mitre": [],
                },
            ],
            "mitre": ["T1110", "T1078", "T1071"],
            "priority_actions": [
                "隔离 web-01.prod.demo 并保全内存、进程和网络证据。",
                "在边界封禁 203.0.113.42 与 198.51.100.9，复核同段连接。",
                "重置 alice 凭据、吊销活跃会话并检查 MFA 策略。",
                "缓解或修复 CVE-2025-9999，核验对外暴露面。",
            ],
            "uncertainties": [
                "Mock 数据展示的是相关性链路，不等价于归因结论。",
                "外联是否为真实 C2 仍应结合 DNS、进程树和威胁情报确认。",
            ],
            "graph_labels": {
                "primary": "ALICE",
                "asset": "WEB-01",
                "alert": "4 ALERTS",
                "source": "203.0.113.42",
                "impact": "CVE-2025-9999",
            },
        },
    },
    "cloud_account_takeover": {
        "id": "cloud_account_takeover",
        "title": "云账号接管 → 权限提升 → 对象存储访问",
        "sector": "云原生 / 数据平台",
        "summary": "异常公网地址登录云账号后切换高权限角色，并对含敏感导出数据的对象存储执行枚举与读取。",
        "risk_score": 89,
        "confidence": "中高（云审计事件完整，但数据是否离开云环境需要网络账单或访问日志补证）",
        "business_impact": "可能造成客户导出数据、报表或密钥材料泄露，并扩大至订阅级资源。",
        "primary_entity": "user:cloud-jordan",
        "events": [
            _event(
                "mock-cloud-login-01",
                "2026-08-10T02:00:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Cloud console login failed",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                status="failure",
            ),
            _event(
                "mock-cloud-login-02",
                "2026-08-10T02:02:00Z",
                3002,
                "Authentication",
                "Logon",
                "medium",
                "Cloud console login failed",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                status="failure",
            ),
            _event(
                "mock-cloud-login-success",
                "2026-08-10T02:04:00Z",
                3002,
                "Authentication",
                "Logon",
                "high",
                "Cloud console login succeeded from a new geography",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                status="success",
                mfa_used=False,
            ),
            _event(
                "mock-cloud-assume-role",
                "2026-08-10T02:06:00Z",
                6003,
                "Cloud API",
                "AssumeRole",
                "high",
                "Assumed DataExportAdmin role",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                role_name="DataExportAdmin",
            ),
            _event(
                "mock-cloud-list-bucket",
                "2026-08-10T02:08:00Z",
                6003,
                "Cloud API",
                "ListObjects",
                "high",
                "Enumerated objects in customer-export-prod",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                resource_name="customer-export-prod",
            ),
            _event(
                "mock-cloud-get-object",
                "2026-08-10T02:10:00Z",
                6003,
                "Cloud API",
                "GetObject",
                "critical",
                "Read 48 sensitive export objects",
                actor_user_name="jordan",
                src_ip="198.51.100.77",
                cloud_account_uid="acct:acme-prod",
                resource_name="customer-export-prod",
                object_count=48,
            ),
            _event(
                "mock-cloud-egress",
                "2026-08-10T02:13:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "Unusual transfer gateway connection after object reads",
                src_ip="10.8.3.22",
                dst_ip="203.0.113.88",
                dst_port=443,
                protocol="https",
                cloud_account_uid="acct:acme-prod",
            ),
        ],
        "alerts": [
            {
                "alert_id": "mock-cloud-login-001",
                "rule_id": "new-geography-no-mfa",
                "severity": "high",
                "title": "新地理位置且未使用 MFA：jordan",
                "status": "new",
                "correlation_key": "jordan|198.51.100.77",
                "evidence": {
                    "event_uids": [
                        "mock-cloud-login-01",
                        "mock-cloud-login-02",
                        "mock-cloud-login-success",
                    ]
                },
            },
            {
                "alert_id": "mock-cloud-role-001",
                "rule_id": "suspicious-assume-role",
                "severity": "high",
                "title": "异常角色切换：jordan → DataExportAdmin",
                "status": "new",
                "correlation_key": "jordan|DataExportAdmin",
                "evidence": {"event_uids": ["mock-cloud-assume-role"]},
            },
            {
                "alert_id": "mock-cloud-data-001",
                "rule_id": "sensitive-bucket-read",
                "severity": "critical",
                "title": "敏感对象存储读取：customer-export-prod（48 objects）",
                "status": "new",
                "correlation_key": "jordan|customer-export-prod",
                "evidence": {
                    "event_uids": [
                        "mock-cloud-list-bucket",
                        "mock-cloud-get-object",
                        "mock-cloud-egress",
                    ]
                },
            },
        ],
        "nodes": [
            _node("user:cloud-jordan", "user", "jordan", "suspected-account"),
            _node("cloud:acme-prod", "cloud_account", "acme-prod", "cloud-account"),
            _node("role:data-export-admin", "role", "DataExportAdmin", "privileged-role"),
            _node(
                "bucket:customer-export-prod", "resource", "customer-export-prod", "sensitive-data"
            ),
            _node("ip:198.51.100.77", "ip", "198.51.100.77", "source"),
            _node("ip:203.0.113.88", "ip", "203.0.113.88", "destination"),
            _node("event:mock-cloud-login-success", "event", "New geography login", "evidence"),
            _node("event:mock-cloud-assume-role", "event", "AssumeRole", "evidence"),
            _node("event:mock-cloud-get-object", "event", "GetObject x48", "evidence"),
            _node("event:mock-cloud-egress", "event", "Transfer gateway", "evidence"),
        ],
        "edges": [
            _edge(
                "cloud-1",
                "event:mock-cloud-login-success",
                "user:cloud-jordan",
                "authenticated_as",
                "mock-cloud-login-success",
            ),
            _edge(
                "cloud-2",
                "event:mock-cloud-login-success",
                "ip:198.51.100.77",
                "originated_from",
                "mock-cloud-login-success",
            ),
            _edge(
                "cloud-3",
                "event:mock-cloud-login-success",
                "cloud:acme-prod",
                "accessed",
                "mock-cloud-login-success",
            ),
            _edge(
                "cloud-4",
                "event:mock-cloud-assume-role",
                "user:cloud-jordan",
                "executed_as",
                "mock-cloud-assume-role",
            ),
            _edge(
                "cloud-5",
                "event:mock-cloud-assume-role",
                "role:data-export-admin",
                "assumed",
                "mock-cloud-assume-role",
            ),
            _edge(
                "cloud-6",
                "event:mock-cloud-get-object",
                "bucket:customer-export-prod",
                "read",
                "mock-cloud-get-object",
            ),
            _edge(
                "cloud-7",
                "event:mock-cloud-get-object",
                "user:cloud-jordan",
                "executed_as",
                "mock-cloud-get-object",
            ),
            _edge(
                "cloud-8",
                "event:mock-cloud-egress",
                "ip:203.0.113.88",
                "connected_to",
                "mock-cloud-egress",
            ),
        ],
        "documents": [
            {
                "chunk_id": "mock-playbook-cloud-identity",
                "score": 0.96,
                "content": "云账号疑似接管：禁用或吊销会话令牌，轮换访问密钥，并确认 MFA 覆盖。",
            },
            {
                "chunk_id": "mock-playbook-cloud-role",
                "score": 0.92,
                "content": "高权限角色滥用：撤销临时会话，审计角色信任策略与最近权限变更。",
            },
            {
                "chunk_id": "mock-playbook-cloud-data",
                "score": 0.9,
                "content": "敏感对象读取：冻结相关策略变更，保全 CloudTrail 与对象访问日志，评估数据范围。",
            },
        ],
        "presentation": {
            "attack_stages": [
                {
                    "stage": "01",
                    "title": "云身份异常",
                    "description": "同一地址失败后成功登录，且没有使用 MFA。",
                    "severity": "warning",
                    "evidence_refs": ["mock-cloud-login-01", "mock-cloud-login-success"],
                    "mitre": ["T1078"],
                },
                {
                    "stage": "02",
                    "title": "权限提升",
                    "description": "会话立即切换至 DataExportAdmin 高权限角色。",
                    "severity": "critical",
                    "evidence_refs": ["mock-cloud-assume-role"],
                    "mitre": ["T1098"],
                },
                {
                    "stage": "03",
                    "title": "敏感数据访问",
                    "description": "读取 48 个导出对象，随后出现异常转发网关连接。",
                    "severity": "critical",
                    "evidence_refs": ["mock-cloud-get-object", "mock-cloud-egress"],
                    "mitre": ["T1530"],
                },
            ],
            "mitre": ["T1078", "T1098", "T1530"],
            "priority_actions": [
                "立即撤销 jordan 的云会话、访问密钥和临时凭据。",
                "禁用或收紧 DataExportAdmin 的信任关系，核验近期 AssumeRole。",
                "冻结 customer-export-prod 的访问策略变更并保全审计日志。",
                "基于对象访问日志评估读取范围，并启动数据泄露响应流程。",
            ],
            "uncertainties": [
                "对象读取不必然等价于对象已导出至外部。",
                "新地理位置需与差旅、VPN 出口和身份供应商日志交叉核验。",
            ],
            "graph_labels": {
                "primary": "JORDAN",
                "asset": "ACME-PROD",
                "alert": "3 ALERTS",
                "source": "198.51.100.77",
                "impact": "S3 EXPORT",
            },
        },
    },
    "ransomware_lateral_movement": {
        "id": "ransomware_lateral_movement",
        "title": "终端入侵 → 横向移动 → 勒索影响",
        "sector": "企业终端 / 文件服务",
        "summary": "财务终端出现可疑 PowerShell，随后凭据在 SMB 上横向访问文件服务器，并发生备份删除与批量加密迹象。",
        "risk_score": 96,
        "confidence": "高（进程、身份、横向网络和影响行为在短时间窗口内连续出现）",
        "business_impact": "可能中断共享文件与备份恢复能力，影响财务和经营数据可用性。",
        "primary_entity": "asset:finance-lt-23",
        "events": [
            _event(
                "mock-endpoint-ps",
                "2026-08-10T03:00:00Z",
                1007,
                "Process Activity",
                "Launch",
                "high",
                "Encoded PowerShell launched from Office child process",
                actor_user_name="maria",
                device_hostname="finance-lt-23",
                process_name="powershell.exe",
                parent_process_name="winword.exe",
                command_line="powershell -enc <redacted>",
            ),
            _event(
                "mock-endpoint-cred",
                "2026-08-10T03:03:00Z",
                1007,
                "Process Activity",
                "Launch",
                "high",
                "Credential dumping tool execution detected",
                actor_user_name="maria",
                device_hostname="finance-lt-23",
                process_name="rundll32.exe",
                command_line="rundll32 comsvcs.dll, MiniDump <redacted>",
            ),
            _event(
                "mock-smb-01",
                "2026-08-10T03:07:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "SMB administrative share connection to finance-fs01",
                actor_user_name="maria",
                src_ip="10.18.5.23",
                dst_ip="10.18.9.10",
                dst_port=445,
                protocol="smb",
                device_hostname="finance-lt-23",
                target_hostname="finance-fs01",
            ),
            _event(
                "mock-smb-02",
                "2026-08-10T03:09:00Z",
                4001,
                "Network Activity",
                "Connect",
                "high",
                "SMB administrative share connection to finance-fs02",
                actor_user_name="maria",
                src_ip="10.18.5.23",
                dst_ip="10.18.9.11",
                dst_port=445,
                protocol="smb",
                device_hostname="finance-lt-23",
                target_hostname="finance-fs02",
            ),
            _event(
                "mock-backup-delete",
                "2026-08-10T03:14:00Z",
                1007,
                "Process Activity",
                "Launch",
                "critical",
                "Backup catalog deletion command executed",
                actor_user_name="maria",
                device_hostname="finance-fs01",
                process_name="vssadmin.exe",
                command_line="vssadmin delete shadows /all /quiet",
            ),
            _event(
                "mock-encrypt-01",
                "2026-08-10T03:16:00Z",
                1007,
                "Process Activity",
                "Modify",
                "critical",
                "Rapid file extension changes on finance share",
                device_hostname="finance-fs01",
                file_count=1834,
                file_extension=".locked",
            ),
            _event(
                "mock-encrypt-02",
                "2026-08-10T03:18:00Z",
                1007,
                "Process Activity",
                "Modify",
                "critical",
                "Rapid file extension changes on finance share",
                device_hostname="finance-fs02",
                file_count=1261,
                file_extension=".locked",
            ),
        ],
        "alerts": [
            {
                "alert_id": "mock-endpoint-ps-001",
                "rule_id": "suspicious-encoded-powershell",
                "severity": "high",
                "title": "Office 子进程启动编码 PowerShell：finance-lt-23",
                "status": "new",
                "correlation_key": "finance-lt-23|powershell.exe",
                "evidence": {"event_uids": ["mock-endpoint-ps", "mock-endpoint-cred"]},
            },
            {
                "alert_id": "mock-lateral-001",
                "rule_id": "smb-lateral-movement",
                "severity": "critical",
                "title": "横向 SMB 管理共享访问：finance-lt-23 → 2 台文件服务器",
                "status": "new",
                "correlation_key": "finance-lt-23|maria|445",
                "evidence": {"event_uids": ["mock-smb-01", "mock-smb-02"]},
            },
            {
                "alert_id": "mock-ransomware-001",
                "rule_id": "ransomware-impact-chain",
                "severity": "critical",
                "title": "备份删除及批量加密：finance-fs01 / finance-fs02",
                "status": "new",
                "correlation_key": "finance-fileservers|locked",
                "evidence": {
                    "event_uids": ["mock-backup-delete", "mock-encrypt-01", "mock-encrypt-02"]
                },
            },
        ],
        "nodes": [
            _node("asset:finance-lt-23", "asset", "finance-lt-23", "initial-host"),
            _node("user:finance-maria", "user", "maria", "user-context"),
            _node("asset:finance-fs01", "asset", "finance-fs01", "affected-file-server"),
            _node("asset:finance-fs02", "asset", "finance-fs02", "affected-file-server"),
            _node("process:powershell", "process", "powershell.exe", "execution"),
            _node("event:mock-endpoint-ps", "event", "Encoded PowerShell", "evidence"),
            _node("event:mock-smb-01", "event", "SMB lateral movement", "evidence"),
            _node("event:mock-backup-delete", "event", "Backup deletion", "evidence"),
            _node("event:mock-encrypt-01", "event", "Mass encryption FS-01", "evidence"),
            _node("event:mock-encrypt-02", "event", "Mass encryption FS-02", "evidence"),
        ],
        "edges": [
            _edge(
                "ransom-1",
                "event:mock-endpoint-ps",
                "asset:finance-lt-23",
                "observed_on",
                "mock-endpoint-ps",
            ),
            _edge(
                "ransom-2",
                "event:mock-endpoint-ps",
                "process:powershell",
                "launched",
                "mock-endpoint-ps",
            ),
            _edge(
                "ransom-3",
                "event:mock-endpoint-ps",
                "user:finance-maria",
                "executed_as",
                "mock-endpoint-ps",
            ),
            _edge(
                "ransom-4",
                "event:mock-smb-01",
                "asset:finance-lt-23",
                "originated_on",
                "mock-smb-01",
            ),
            _edge(
                "ransom-5", "event:mock-smb-01", "asset:finance-fs01", "connected_to", "mock-smb-01"
            ),
            _edge(
                "ransom-6",
                "event:mock-backup-delete",
                "asset:finance-fs01",
                "observed_on",
                "mock-backup-delete",
            ),
            _edge(
                "ransom-7",
                "event:mock-encrypt-01",
                "asset:finance-fs01",
                "impacted",
                "mock-encrypt-01",
            ),
            _edge(
                "ransom-8",
                "event:mock-encrypt-02",
                "asset:finance-fs02",
                "impacted",
                "mock-encrypt-02",
            ),
        ],
        "documents": [
            {
                "chunk_id": "mock-playbook-ransomware-isolate",
                "score": 0.97,
                "content": "勒索事件：隔离受影响终端和服务器，禁止重启，保全内存、EDR 与网络证据。",
            },
            {
                "chunk_id": "mock-playbook-ransomware-identity",
                "score": 0.93,
                "content": "横向移动：禁用或重置涉事账号，轮换高权限凭据，排查同一会话的横向连接。",
            },
            {
                "chunk_id": "mock-playbook-ransomware-recovery",
                "score": 0.9,
                "content": "恢复：验证离线备份完整性，分段恢复业务，并保留加密样本用于取证。",
            },
        ],
        "presentation": {
            "attack_stages": [
                {
                    "stage": "01",
                    "title": "可疑执行",
                    "description": "Office 子进程启动编码 PowerShell，随后出现凭据转储行为。",
                    "severity": "warning",
                    "evidence_refs": ["mock-endpoint-ps", "mock-endpoint-cred"],
                    "mitre": ["T1059.001", "T1003"],
                },
                {
                    "stage": "02",
                    "title": "横向移动",
                    "description": "同一用户上下文经 SMB 管理共享访问两台财务文件服务器。",
                    "severity": "critical",
                    "evidence_refs": ["mock-smb-01", "mock-smb-02"],
                    "mitre": ["T1021.002"],
                },
                {
                    "stage": "03",
                    "title": "影响",
                    "description": "删除卷影副本并在两台服务器观察到批量文件扩展名变更。",
                    "severity": "critical",
                    "evidence_refs": ["mock-backup-delete", "mock-encrypt-01", "mock-encrypt-02"],
                    "mitre": ["T1490", "T1486"],
                },
            ],
            "mitre": ["T1059.001", "T1003", "T1021.002", "T1490", "T1486"],
            "priority_actions": [
                "立即网络隔离 finance-lt-23、finance-fs01 与 finance-fs02，阻止继续传播。",
                "禁用 maria 会话并轮换可能暴露的高权限凭据。",
                "暂停受影响共享的写入，验证离线备份和灾备恢复路径。",
                "在全网猎杀相同 PowerShell、SMB 和 .locked 文件特征。",
            ],
            "uncertainties": [
                "加密特征是模拟证据；真实事件须以 EDR 文件遥测和勒索样本确认。",
                "需要核验备份删除是否影响所有恢复点及是否存在离线副本。",
            ],
            "graph_labels": {
                "primary": "FIN-LT-23",
                "asset": "FS-01",
                "alert": "3 ALERTS",
                "source": "SMB / 445",
                "impact": ".LOCKED",
            },
        },
    },
}


def _materialize(scenario_id: str, tenant_id: str) -> dict[str, Any]:
    try:
        scenario = deepcopy(SCENARIOS[scenario_id])
    except KeyError as error:
        options = ", ".join(SCENARIOS)
        raise ValueError(
            f"unknown mock scenario: {scenario_id}; choose one of: {options}"
        ) from error

    timestamp = _now()
    for event in scenario["events"]:
        event["tenant_id"] = tenant_id
    for alert in scenario["alerts"]:
        alert["tenant_id"] = tenant_id
        alert["created_at"] = timestamp
    return scenario


def list_scenarios() -> dict[str, Any]:
    """Return small, UI-safe scenario cards without duplicating all evidence."""
    return {
        "mode": "mock",
        "default_scenario": DEFAULT_SCENARIO,
        "scenarios": [
            {
                "id": item["id"],
                "title": item["title"],
                "sector": item["sector"],
                "summary": item["summary"],
                "risk_score": item["risk_score"],
                "confidence": item["confidence"],
            }
            for item in SCENARIOS.values()
        ],
    }


def load_demo(
    tenant_id: str, run_id: str | None = None, scenario_id: str = DEFAULT_SCENARIO
) -> dict[str, Any]:
    scenario = _materialize(scenario_id, tenant_id)
    run_id = run_id or f"mock-{scenario_id}"
    return {
        "mode": "mock",
        "run_id": run_id,
        "tenant_id": tenant_id,
        "scenario": scenario["id"],
        "scenario_summary": {
            **{
                key: scenario[key]
                for key in (
                    "title",
                    "sector",
                    "summary",
                    "risk_score",
                    "confidence",
                    "business_impact",
                    "primary_entity",
                )
            },
            "entity_count": len(scenario["nodes"]),
        },
        "ingested_events": len(scenario["events"]),
        "document_ids": [document["chunk_id"] for document in scenario["documents"]],
        "created_alerts": scenario["alerts"],
        "demo_entities": {
            node["role"]: node["entity_id"]
            for node in scenario["nodes"]
            if node["role"]
            in {
                "compromised-account",
                "suspected-account",
                "initial-host",
                "affected-asset",
                "cloud-account",
                "source",
            }
        },
        "presentation": scenario["presentation"],
        "next_step": "Mock results are deterministic simulated evidence; no StarRocks, vector search, or LLM request was made.",
    }


def alerts(tenant_id: str, scenario_id: str = DEFAULT_SCENARIO) -> dict[str, Any]:
    scenario = _materialize(scenario_id, tenant_id)
    return {
        "mode": "mock",
        "scenario": scenario_id,
        "alerts": scenario["alerts"],
        "risk_score": scenario["risk_score"],
    }


def graph(
    entity_id: str, tenant_id: str, depth: int, scenario_id: str = DEFAULT_SCENARIO
) -> dict[str, Any]:
    scenario = _materialize(scenario_id, tenant_id)
    timestamp = _now()
    nodes = [{**node, "last_seen": timestamp} for node in scenario["nodes"]]
    edges = [{**edge, "event_time": timestamp} for edge in scenario["edges"]]
    return {
        "mode": "mock",
        "scenario": scenario_id,
        "seed": entity_id,
        "tenant_id": tenant_id,
        "depth": depth,
        "nodes": nodes,
        "edges": edges,
        "presentation": scenario["presentation"],
    }


def investigation(
    entity_id: str,
    question: str,
    tenant_id: str,
    depth: int,
    scenario_id: str = DEFAULT_SCENARIO,
) -> dict[str, Any]:
    scenario = _materialize(scenario_id, tenant_id)
    context = graph(entity_id, tenant_id, depth, scenario_id)
    evidence_refs = [event["event_uid"] for event in scenario["events"]]
    return {
        "mode": "mock",
        "scenario": scenario_id,
        "question": question,
        "graph": context,
        "events": scenario["events"],
        "retrieved_context": scenario["documents"],
        "mock_analyst_answer": {
            "executive_assessment": scenario["summary"],
            "risk_score": scenario["risk_score"],
            "confidence": scenario["confidence"],
            "business_impact": scenario["business_impact"],
            "attack_path": scenario["presentation"]["attack_stages"],
            "priority_actions": scenario["presentation"]["priority_actions"],
            "evidence_refs": evidence_refs,
            "uncertainties": scenario["presentation"]["uncertainties"],
            "disclaimer": "This is deterministic mock analysis. It is not an LLM conclusion, live incident verdict, or attribution decision.",
        },
        "agent_instruction": "Mock mode made no StarRocks, vector search, or LLM request.",
    }


def connection() -> dict[str, Any]:
    return {
        "mode": "mock",
        "active": {
            "host": "not-required",
            "port": 0,
            "user": "mock",
            "database": "in-memory-demo",
            "tls": {"enabled": False, "verify_server": False, "custom_ca_configured": False},
            "connect_timeout_seconds": 0,
        },
    }


def text_graph(tenant_id: str, scenario_id: str = DEFAULT_SCENARIO) -> dict[str, Any]:
    """Return a deterministic rule-extraction preview without persisting it."""
    _materialize(scenario_id, tenant_id)  # validates the requested scenario
    source_id = f"mock-report-{scenario_id}"
    result = extract_rule_graph(MOCK_TEXT_REPORTS[scenario_id], source_id, "mock_incident_report")
    result.update(
        {
            "mode": "mock",
            "scenario": scenario_id,
            "tenant_id": tenant_id,
            "persisted": False,
            "next_step": "Mock extraction is a preview only; no database, LLM, or review record was created.",
        }
    )
    return result


def retrospective(tenant_id: str, scenario_id: str = DEFAULT_SCENARIO) -> dict[str, Any]:
    """Run the same explainable post-analysis algorithm on a static evidence slice."""
    scenario = _materialize(scenario_id, tenant_id)
    baseline_by_scenario = {
        "credential_to_impact": [
            {"class_uid": 3002, "event_count": 89400},
            {"class_uid": 4001, "event_count": 2330},
        ],
        "cloud_account_takeover": [
            {"class_uid": 3002, "event_count": 3270},
            {"class_uid": 4001, "event_count": 910},
        ],
        "ransomware_lateral_movement": [
            {"class_uid": 1007, "event_count": 17500},
            {"class_uid": 4001, "event_count": 22400},
        ],
    }
    result = analyze_historical_events(
        scenario["events"],
        tenant_id=tenant_id,
        start_time=datetime(2026, 8, 10, 0, 0),
        end_time=datetime(2026, 8, 10, 4, 0),
        session_gap_minutes=30,
        cluster_limit=12,
        baseline_rows=baseline_by_scenario[scenario_id],
    )
    result.update(
        {
            "mode": "mock",
            "scenario": scenario_id,
            "data_origin": "deterministic curated historical OCSF evidence; no StarRocks or LLM request was made",
            "query_guardrails": {
                "max_events": 20000,
                "partition_pruning": "simulated in mock mode",
                "baseline": "deterministic class-level history before the selected window",
            },
        }
    )
    return result
