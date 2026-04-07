# Mysoft Real Estate ERP Information Leakage Vulnerability

---

## 1. Basic information
- **Vulnerability ID**: [Assigned by CNA]
- **Vulnerability Type**: Information leakage / exposure of sensitive information
- **Severity**: Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Vendor**: Shenzhen Mysoft Co., Ltd.
- **Product**: Mysoft Real Estate ERP
- **Affected Versions**: Publicly deployed instances that expose backup packages such as `bin.rar` or `bin.zip` under the web root
- **Disclosure Status**: Publicly accessible backup files can be downloaded without authentication

---

## 2. Vulnerability description
Shenzhen Mysoft Co., Ltd.'s Mysoft Real Estate ERP contains an **Unauthorized Information Disclosure Vulnerability** (CWE-200: Exposure of Sensitive Information to an Unauthorized Actor). In affected deployments, attackers can directly access exposed backup packages such as `bin.rar` or `bin.zip` from the web root without authentication.

After downloading and decompressing the backup package, attackers can obtain configuration files such as `Mysoft.UTFramework2.UnitTest.dll.config`, which contain **cleartext** sensitive information, including:
- Internal database address
- Database username and password
- Other internal deployment and configuration details

The leaked credentials may allow attackers to directly access the backend database, disclose sensitive business data, tamper with application data, and use the leaked internal information as a foothold for further attacks against internal systems.

---

## 3. Proof of Concept (PoC)
### 3.1 Vulnerability exploitation steps
1. An attacker accesses a publicly exposed backup package, for example:
```
http://124.71.63.145/bin.rar
```
2. Download and decompress the archive.
3. Locate the configuration file:
```
Mysoft.UTFramework2.UnitTest.dll.config
```
4. Open the file and observe that database connection information is stored in clear text, including the database account and password.

### 3.2 Evidence summary
- Publicly accessible `bin.rar` / `bin.zip` backup files were found in multiple exposed deployments.
- Decompressed backup contents included application binaries and configuration files.
- `Mysoft.UTFramework2.UnitTest.dll.config` exposed database credentials in clear text.

---

## 4. Impact analysis
- **Sensitive Information Disclosure**: Attackers can obtain internal database connection details and deployment information.
- **Database Compromise**: Exposed credentials may permit direct access to backend databases, resulting in unauthorized read, write, modification, or deletion of data.
- **Internal Network Exposure**: Internal addresses and configuration details can facilitate further attacks on the internal environment.
- **Business Risk**: Leakage or tampering of ERP data may affect business operations, customer information security, and system availability.

---

## 5. Technical details
- **Root Cause**: Backup archives such as `bin.rar` or `bin.zip` were left in the web-accessible directory and could be downloaded without authentication.
- **Sensitive Data Storage**: Configuration files stored database credentials in clear text without adequate protection.
- **Attack Vector**: Remote unauthenticated HTTP/HTTPS request to download the exposed backup file, followed by decompression and review of configuration files.
- **Attack Complexity**: Low. No authentication, special privileges, or user interaction are required.

---

## 6. Remedial suggestions
1. **Immediate actions**:
- Remove all exposed backup files such as `bin.rar`, `bin.zip`, `*.bak`, and similar archives from the web root.
- Immediately rotate all exposed database credentials and related secrets.
- Restrict database access to trusted hosts or internal network ranges only.
2. **Long-term mitigation**:
- Prohibit storage of backup packages in publicly accessible directories.
- Use secure configuration management to protect sensitive credentials, such as environment variables or encrypted configuration storage.
- Implement deployment checks to prevent accidental publication of backup and configuration files.
- Conduct periodic security scans to identify exposed archives and sensitive files.
