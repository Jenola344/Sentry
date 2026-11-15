# Sentry Safety, Resilience & Edge-Case Protocols

> **Companion Specification to [SKILL.md](../SKILL.md)**  
> **Skill:** `sentry` (UGREEN AI NAS Zero-Egress Auditor)  
> **Scope:** Risk scoring mathematics, zero-leak secret redaction, and failure mode mitigation.

---

## 1. Context-Aware Risk Scoring Model

Risk on a shared network appliance is non-linear. The damage potential of an exposed secret depends directly upon the accessibility and authentication posture of the storage container hosting it.

### Mathematical Formulation

$$R = S \times (1 + \alpha_{\text{multi}} + \beta_{\text{public}})$$

Where:
- **$S \in \{1.0, 3.0, 5.0\}$:** Base Severity rating determined by the intrinsic exploitability of the detected secret.
- **$\alpha_{\text{multi}} \in \{0.00, 0.50\}$:** Multi-User Exposure Multiplier. Evaluates whether the storage pool is shared across multiple local user accounts or groups.
- **$\beta_{\text{public}} \in \{0.00, 0.75\}$:** Public / Guest Exposure Multiplier. Evaluates whether anonymous or guest access (SMB Guest, unauthenticated WebDAV, public share link) is enabled on the directory.

### Base Severity Categorization ($S$)

| Base Severity | Numerical Value ($S$) | Category Definition | Concrete Asset Examples |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | **5.0** | Immediate, active, and unauthenticated compromise vectors. | Cloud root credentials (AWS, GCP, Azure), OpenAI API keys, live SSH/RSA private keys, 12/24-word BIP-39 cryptocurrency seed phrases, unencrypted production database connection strings with passwords. |
| **HIGH** | **3.0** | High-value identity, personal financial, or regulatory data assets. | Scanned passports, government ID numbers (US SSN, UK NINO), payment cards with valid Luhn checksums, corporate payroll ledgers, IRS tax returns (Forms 1040, W-2). |
| **MEDIUM** | **1.0** | Confidential organizational records or degraded / partial secrets. | Bank statements without passwords, internal network architecture diagrams, expired certificates, low-confidence `ug-photo` OCR matches ($< 0.70$), password-protected encrypted archives. |

### Complete Composite Risk Matrix

The table below enumerates all eight possible state permutations for risk score calculation:

| Base Severity ($S$) | Multi-User Share ($\alpha$) | Public / Guest Access ($\beta$) | Composite Multiplier | Final Risk Score ($R$) | Action Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CRITICAL (5.0)** | Yes ($+0.50$) | Yes ($+0.75$) | **$\times 2.25$** | **11.25** | 🚨 **URGENT** (Quarantine Immediately) |
| **CRITICAL (5.0)** | Yes ($+0.50$) | No ($+0.00$) | **$\times 1.50$** | **7.50** | 🔴 **HIGH** (Quarantine Recommended) |
| **CRITICAL (5.0)** | No ($+0.00$) | Yes ($+0.75$) | **$\times 1.75$** | **8.75** | 🚨 **URGENT** (Quarantine Immediately) |
| **CRITICAL (5.0)** | No ($+0.00$) | No ($+0.00$) | **$\times 1.00$** | **5.00** | 🟠 **ELEVATED** (User Review) |
| **HIGH (3.0)** | Yes ($+0.50$) | Yes ($+0.75$) | **$\times 2.25$** | **6.75** | 🔴 **HIGH** (Quarantine Recommended) |
| **HIGH (3.0)** | Yes ($+0.50$) | No ($+0.00$) | **$\times 1.50$** | **4.50** | 🟠 **ELEVATED** (User Review) |
| **HIGH (3.0)** | No ($+0.00$) | Yes ($+0.75$) | **$\times 1.75$** | **5.25** | 🟠 **ELEVATED** (User Review) |
| **HIGH (3.0)** | No ($+0.00$) | No ($+0.00$) | **$\times 1.00$** | **3.00** | 🟡 **MODERATE** (Notify Owner) |
| **MEDIUM (1.0)** | Yes ($+0.50$) | Yes ($+0.75$) | **$\times 2.25$** | **2.25** | 🟡 **MODERATE** (Informational) |
| **MEDIUM (1.0)** | Yes ($+0.50$) | No ($+0.00$) | **$\times 1.50$** | **1.50** | 🟢 **LOW** (Informational) |
| **MEDIUM (1.0)** | No ($+0.00$) | Yes ($+0.75$) | **$\times 1.75$** | **1.75** | 🟢 **LOW** (Informational) |
| **MEDIUM (1.0)** | No ($+0.00$) | No ($+0.00$) | **$\times 1.00$** | **1.00** | 🟢 **LOW** (Informational) |

---

## 2. Strict Zero-Leak Evidence Masking Standard

An auditing tool that exposes plain secrets in its reports or terminal output introduces a severe secondary attack surface. Sentry enforces a strict deterministic redaction algorithm before any string is emitted to standard output or persisted to disk.

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    ZERO-LEAK REDACTION PIPELINE                        │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 1. Detector identifies raw match in RAM buffer.                        │
 │ 2. Match is routed to category-specific redactor function.             │
 │ 3. Redactor replaces sensitive characters with fixed-width asterisks.  │
 │ 4. Output string is verified to ensure zero raw credential bytes.      │
 │ 5. Only the sanitized string is passed to report compiler / terminal.  │
 └────────────────────────────────────────────────────────────────────────┘
```

### Redaction Rules by Asset Category

```python
def mask_secret(secret_type: str, raw_val: str) -> str:
    """Deterministic zero-leak masking ensuring evidence verification without disclosure."""
    val = raw_val.strip()
    if secret_type == "api_key":
        if len(val) <= 10:
            return val[:2] + "****" + val[-2:]
        return val[:4] + "****" + val[-4:]
    
    elif secret_type == "bip39_seed":
        words = val.split()
        first_word = words[0] if words else "unknown"
        return f"[{len(words)}-WORD SEED PHRASE starting with \"{first_word}...\"]"
    
    elif secret_type == "payment_card":
        digits = [c for c in val if c.isdigit()]
        if len(digits) >= 12:
            first4 = "".join(digits[:4])
            last4 = "".join(digits[-4:])
            return f"{first4}-****-****-{last4}"
        return "****-****-****-****"
    
    elif secret_type == "ssn":
        digits = [c for c in val if c.isdigit()]
        last4 = "".join(digits[-4:]) if len(digits) >= 4 else "XXXX"
        return f"***-**-{last4}"
    
    elif secret_type == "iban":
        country = val[:2].upper()
        last4 = val[-4:]
        return f"{country}**-****-****-****-{last4}"
    
    elif secret_type == "passport_mrz":
        return f"[PASSPORT MRZ: {len(val)} characters redacted]"

    elif secret_type == "database_uri":
        # Split on the LAST '@' (the only legal credentials/host separator) so a
        # raw '@', '/' or ':' inside the password cannot shift the split point
        # and leave the tail of the secret in the evidence.
        scheme, sep, rest = val.partition("://")
        if not sep:
            return "****REDACTED****"
        credentials_end = rest.rfind("@")
        if credentials_end == -1:
            return "****REDACTED****"
        userinfo = rest[:credentials_end]
        host, slash, path = rest[credentials_end + 1:].partition("/")
        user, colon, _password = userinfo.partition(":")
        masked_userinfo = f"{user}:********" if colon else user
        return f"{scheme}://{masked_userinfo}@{host}{slash}{path}"

    elif secret_type == "private_key":
        return "[BEGIN PRIVATE KEY: Cryptographic Body Redacted]"
    
    return "****REDACTED****"
```

### Visual Verification Examples

| Secret Category | Raw In-Memory String *(Never Written)* | Masked Report Representation *(Safe)* |
| :--- | :--- | :--- |
| **OpenAI Secret Key** | `sk-live-9f8a32b01c4d9e8f7a6b5c4d3e2f1a0b` | `sk-l****1a0b` |
| **AWS Access Key** | `AKIAIOSFODNN7EXAMPLE` | `AKIA****MPLE` |
| **BIP-39 Mnemonic** | `abandon ability able about above absent absorb abstract absurd abuse access accident` | `[12-WORD SEED PHRASE starting with "abandon..."]` |
| **Visa Credit Card** | `4111 2222 3333 4444` | `4111-****-****-4444` |
| **US Social Security No.** | `123-45-6789` | `***-**-6789` |
| **German IBAN** | `DE89370400440532013000` | `DE**-****-****-****-3000` |
| **PostgreSQL Connection** | `postgres://dbadmin:SuperSecret2026!@10.0.0.5:5432/corp` | `postgres://dbadmin:********@10.0.0.5:5432/corp` |
| **PostgreSQL (delimiter in password)** | `postgres://app:p@ssw0rd@db.internal:5432/prod` | `postgres://app:********@db.internal:5432/prod` |
| **MongoDB (slash + at in password)** | `mongodb+srv://svc:pa/ss@word@cluster0.example.net/app` | `mongodb+srv://svc:********@cluster0.example.net/app` |
| **Passport MRZ** | `P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<` | `[PASSPORT MRZ: 44 characters redacted]` |

---

## 3. Failure Modes & Edge-Case Mitigation

### 1. Password-Protected & Encrypted Files
- **Symptom:** Archive files (`.zip`, `.7z`, `.rar`, `.tar.gz`) or PDF files (`.pdf`) are protected with symmetric encryption.
- **Handling Protocol:**
  - Sentry reads file headers via `ug-document inspect-metadata`.
  - For ZIP files, bit 0 of the general-purpose bit flag indicates encryption.
  - For PDF files, presence of the `/Encrypt` dictionary indicates password restriction.
  - **Hard Rule:** Sentry **never** executes dictionary or brute-force decryption attacks. Brute-forcing exhausts NAS CPU resources and violates safety guidelines.
  - Sentry tags the item as `UNSCANNED_ENCRYPTED` with `MEDIUM` severity, notifying the administrator in the audit report that an uninspected encrypted file resides in a shared folder.

### 2. Corrupt, Truncated & Zero-Byte Files
- **Symptom:** File size reports 0 bytes, or archive decompression returns invalid checksum errors.
- **Handling Protocol:**
  - Sentry catches parser exceptions cleanly without terminating the scan loop.
  - Files are logged under `SKIPPED_CORRUPT` in the scan summary metadata.

### 3. Permission-Denied Storage Nodes (`EACCES` / `EPERM`)
- **Symptom:** System user running Sentry lacks read permissions on a specific subdirectory or file.
- **Handling Protocol:**
  - System call error `EACCES` is caught.
  - The inaccessible path is appended to the `Unscanned / Permission Denied` appendix in the final report.
  - Scan continues seamlessly across remaining directories.

### 4. Low-Confidence Optical Character Recognition (OCR)
- **Scope:** Device-side only. The portable engine performs no pixel OCR — it reads embedded PNG/JPEG text and EXIF metadata, where text is exact and no confidence score exists.
- **Symptom:** In Pass 4, degraded camera uploads or blurry screenshots produce `ug-photo` OCR confidence metrics $< 0.70$.
- **Handling Protocol:**
  - Rather than discarding the finding or generating a false critical alert, Sentry automatically downgrades severity from `HIGH` to `MEDIUM`.
  - The finding is flagged with `CONFIDENCE_UNCERTAIN` and highlighted for manual visual review by the user.

### 5. Circular Symlink Loops & Nested Mounts
- **Symptom:** Symlinks pointing to parent directories (`/volume1/Shared/link -> /volume1/Shared`) can trigger infinite recursion and stack exhaustion.
- **Handling Protocol:**
  - Sentry tracks a set of visited device and inode tuples `(st_dev, st_ino)`.
  - If an inode has already been visited in the current scan path, it is skipped immediately.
  - Maximum folder traversal depth is hard-capped at **16 directory levels**.

### 6. NAS Resource Conservation & Memory Ceiling
- **Symptom:** Multi-terabyte NAS volumes with hundreds of thousands of files risk consuming excessive RAM and causing disk contention.
- **Handling Protocol:**
  - **Memory Ceiling:** The Sentry process memory footprint is governed to remain strictly under **256 MB RAM**.
  - **Streaming Inspection:** Files are parsed via streaming buffers rather than loaded whole into memory.
  - **I/O Throttling:** Disk read operations yield CPU time every 100 scanned files to prevent disk I/O starvation on active media streaming or RAID rebuild tasks.
