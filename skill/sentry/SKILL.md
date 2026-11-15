---
name: sentry
description: Zero-egress, 100% local security auditor for UGREEN AI NAS (UGOS). Scans shared storage for leaked API keys, crypto seed phrases, unencrypted PII, and financial records using native UGOS CLI tools (ug-filesystem, ug-filemgr, ug-document, ug-photo, ug-knowledge). Calculates context-aware risk scores, enforces strict zero-leak evidence masking, generates an interactive Risk Heatmap Report, and executes non-destructive, reversible quarantine strictly upon explicit human confirmation.
---

# Sentry: Zero-Egress Local Security Auditor for UGREEN AI NAS

```text
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
   UGREEN AI NAS (UGOS) — Zero-Egress Autonomous Auditor
```

> **Round 2 Final Submission — UGREEN Hackathon 2026 on AI NAS**  
> **Track:** Open Innovation  
> **Target Platform:** UGREEN AI NAS iDX6011 Pro (UGOS / Linux Kernel 6.x / Intel Core Ultra NPU)  
> **Execution Mode:** 100% On-Device, Declarative Skill Orchestration, Zero External Telemetry  

---

## 1. System Overview & Architectural Manifesto

Network Attached Storage (NAS) devices have evolved from simple backup repositories into multi-user collaborative hubs. On modern AI NAS devices such as the **UGREEN AI NAS iDX6011 Pro**, shared directories frequently aggregate sensitive assets: developer workspaces, cloud deployment secrets, scanned tax documents, crypto wallet backups, and personal identification records. When access permissions shift—or when public guest access is accidentally enabled—these secrets become exposed to unauthorized LAN users, rogue container services, or WAN attackers.

**Sentry** is an autonomous, zero-egress security auditing Skill engineered specifically for UGOS. Sentry leverages UGREEN's native system binaries—`ug-filesystem`, `ug-filemgr`, `ug-document`, `ug-photo`, and `ug-knowledge`—to detect, score, mask, and quarantine exposed secrets without a single byte of telemetry or data leaving the local hardware bus.

```mermaid
flowchart TD
    subgraph Sentry Engine ["Sentry Autonomous Core (Local UGOS)"]
        A["Input Validation & Scope Governance"] --> B["Pass 1: Inventory & Resource Guard<br/>(ug-filesystem)"]
        B --> C["Pass 2: Text, Code & Config Secrets<br/>(ug-document)"]
        C --> D["Pass 3: Structured Docs & Financial Records<br/>(ug-document)"]
        D --> E["Pass 4: Image Text & Metadata Audit<br/>(ug-photo / embedded text)"]
        E --> F["Context-Aware Risk Scoring<br/>R = S * (1 + α + β)"]
        F --> G["Zero-Leak Evidence Redactor"]
        G --> H["Risk Heatmap Report Generation<br/>(ug-knowledge)"]
        H --> I{"Human-in-the-Loop<br/>Confirmation Gate"}
        I -- "User Rejects / Aborts" --> J["Audit Terminated (No File Changes)"]
        I -- "User Confirms IDs" --> K["Collision-Safe Reversible Quarantine<br/>(ug-filemgr)"]
        K --> L["quarantine-manifest.md Generated<br/>(1-Click Rollback Ready)"]
    end
```

### Key Technical Pillars
1. **Zero-Egress Guarantee:** Sentry does not instantiate sockets, call cloud APIs, or emit outbound telemetry. All inspections occur through local UGOS system calls and, where available, on-device NPU models.
2. **Four-Pass Deterministic Pipeline:** Files are routed based on MIME type, extension, and hardware cost, skipping massive binary blobs while thoroughly inspecting code, configurations, structured documents, and visual media.
3. **Context-Aware Exposure Multipliers:** Risk is not assessed in a vacuum. A credential found in an unauthenticated guest-accessible folder is scored higher than one in an authenticated team folder, which in turn is scored higher than one in a private folder.
4. **Strict Zero-Leak Evidence Masking:** Raw secrets are strictly redacted before output to reports, logs, or user interfaces.
5. **Two-Step Human-in-the-Loop Quarantine Gate:** Sentry operates under a strict principle of non-destruction. Automated scans **never** move, rename, or delete files without explicit user review and confirmation.
6. **Reversible Hierarchy-Preserving Vault:** Quarantined files retain their full relative directory tree within a dedicated isolation vault, preventing file overwrite collisions and allowing one-command restoration.

---

## 2. Sector A: Input Validation & Scope Governance

### Parameter Schema

Sentry accepts four structured configuration inputs:

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `target_paths` | `List[String]` | **Required** | One or more storage paths mounted under `/volume*` to be audited. |
| `audit_scope` | `Enum` | `all` | Inspection categories: `credentials`, `identity_pii`, `financial`, or `all`. |
| `scan_depth` | `Enum` | `standard` | `quick` (Passes 1-2), `standard` (Passes 1-3), `deep` (Passes 1-4 including embedded image text and metadata). |
| `quarantine_vault_path` | `String` | `/volume1/Private_Security_Vault/Quarantine_<YYYY-MM-DD>` | Target directory for isolated files. |

### System Path Blacklist & Boundary Enforcement

To protect NAS operating system stability, Sentry enforces an immutable blocklist. If any path in `target_paths` resolves to or nests within system directories, Sentry aborts the execution immediately with an exit status code `E_SYSTEM_PATH_DENIED`.

```text
PROHIBITED SYSTEM PATHS (STRICTLY BLOCKED):
  /            /etc         /usr         /var         /bin         /sbin
  /proc        /sys         /dev         /boot        /lib         /lib64
  /root        /opt         /run         /tmp         /mnt         /lost+found
```

**Allowed Scope:** Sentry only authorizes auditing within mounted storage pools matching the POSIX pattern:
`/volume[0-9]+/(.*)` (e.g., `/volume1/Shared`, `/volume2/Backups`, `/volume1/Media/Documents`).

### Share Context & Permission Probing

Before scanning file contents, Sentry queries `ug-filesystem` and `ug-filemgr` to establish the security posture of each target root:

```bash
# Query storage pool mount metadata and permissions
ug-filesystem stat --path "/volume1/Shared" --format json

# Query network sharing status (SMB, NFS, WebDAV, Guest access)
ug-filesystem share-info --path "/volume1/Shared" --format json
```

Sentry parses the share context flags:
- `is_shared`: `true` if exposed via SMB/NFS/AFP/WebDAV to multiple local accounts.
- `guest_access_allowed`: `true` if public, anonymous, or passwordless access is permitted.
- `permissions_mode`: POSIX bitmask (e.g., `0777`, `0755`, `0700`).

These values dynamically populate the context multipliers ($\alpha_{\text{multi}}$ and $\beta_{\text{public}}$) defined in [Sector C](#4-sector-c-risk-scoring-formula--strict-secret-masking).

---

## 3. Sector B: Four-Pass Local Detection Engine

Sentry structures file inspection into four sequential, resource-governed passes. Detailed regex patterns, token formats, and algorithmic validators are maintained in the companion specification:  
👉 **[detection-taxonomy.md](references/detection-taxonomy.md)**

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      FOUR-PASS DETECTION PIPELINE                      │
 ├──────────────┬──────────────────┬─────────────────┬────────────────────┤
 │ Pass 1       │ Pass 2           │ Pass 3          │ Pass 4             │
 │ Inventory &  │ Text, Code &     │ Structured Docs │ Image Text &       │
 │ Resource     │ Config Secrets   │ & Financial     │ Metadata           │
 │ Guard        │                  │ Records         │ (Deep Scan)        │
 ├──────────────┼──────────────────┼─────────────────┼────────────────────┤
 │ ug-filesystem│ ug-document      │ ug-document     │ ug-photo           │
 │ Size <= 50MB │ .env, .pem, .key │ .pdf, .docx,    │ .png, .jpg, .webp  │
 │ Skip media   │ .json, .yaml     │ .xlsx, .csv     │ Embedded text,     │
 │ Lockfile     │ API keys, DB     │ Tax, payroll,   │ EXIF GPS, cards    │
 │ whitelist    │ URLs, seed words │ SSN, IBAN, DL   │ (no pixel OCR)     │
 └──────────────┴──────────────────┴─────────────────┴────────────────────┘
```

### Pass 1: Inventory & Resource Guard (`ug-filesystem`)
- Traverses `target_paths` recursively using `ug-filesystem list --recursive --metadata --format json`.
- **Resource Guard:** Skips files exceeding **50 MB** in size to prevent memory starvation and disk I/O thrashing on NAS pools during active workloads.
- **Media Filter:** Ignores pure media streaming containers (`.mp4`, `.mkv`, `.avi`, `.mov`, `.wmv`, `.flv`, `.mp3`, `.wav`, `.flac`, `.aac`, `.iso`, `.img`, `.vmdk`, `.qcow2`).
- **Dependency Whitelist:** Suppresses false positives from package lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `composer.lock`) which contain legitimate SHA hashes that mimic cryptographic tokens.

### Pass 2: Text, Code & Configuration Secrets (`ug-document`)
- Targets developer and operational configurations: `.env*`, `.pem`, `.key`, `.p12`, `.json`, `.yaml`, `.yml`, `.txt`, `.md`, `.csv`, `.log`, `.sql`, `.xml`.
- Extracts plain text via `ug-document extract --path <path> --format text/plain --max-bytes 52428800`.
- Scans for:
  - **Cloud & API Credentials:** OpenAI (`sk-live-`, `sk-proj-`), AWS access keys (`AKIA...`) and `aws_secret_access_key` values, GitHub (`ghp_`, `gho_`), Slack (`xoxb-` legacy and three-segment tokens), Google Cloud (`AIza...`), Stripe (`sk_live_`, `rk_live_`).
  - **Cryptographic Keys:** RSA/EC/OpenSSH private key banners (`-----BEGIN ... PRIVATE KEY-----`).
  - **Database Connection URIs:** PostgreSQL, MongoDB, MySQL URIs with plaintext credentials embedded (`postgres://user:pass@host:5432/db`).
  - **BIP-39 Cryptocurrency Recovery Phrases:** 12 or 24-word sequences matched against the full 2,048-word English dictionary. A 24-word mnemonic is reported once as a 24-word phrase.

### Pass 3: Structured Documents & Financial Records (`ug-document`)
- Inspects business documents: `.pdf`, `.docx`, `.xlsx`, `.csv`.
- Dissects tabular and formatted text for high-risk identity and financial exposure:
  - **Banking Data:** International Bank Account Numbers (IBAN), SWIFT/BIC codes, account balances, routing numbers.
  - **Government Identifiers:** US Social Security Numbers (SSN) and Passport Machine-Readable Zone (MRZ) line-1 strings.
  - **Financial Ledgers:** Corporate payroll sheets, tax filings (Forms 1040, W-2, 1099), earnings summaries.

### Pass 4: Image Text & Metadata Audit (`ug-photo`, active when `scan_depth=deep`)
- Inspects image files that commonly carry embedded text or exposure metadata: `.png`, `.jpg`, `.jpeg`, `.webp`.
- **Embedded text layer (no OCR):** reads text already stored in the file — PNG `tEXt`/`zTXt`/`iTXt` chunks, JPEG `COM` comments and EXIF text tags — and scans it with the Pass 2 detectors.
- **Exposure metadata:** flags EXIF GPS presence as `MEDIUM`, because a photographed document in a shared folder also leaks where it was taken.
- **Delegated OCR:** on UGOS the Skill dispatches pixel OCR to `ug-photo ocr --path <path> --lang eng,auto --format json` and consumes the returned text blocks. Sentry itself never performs pixel OCR, and the portable reference engine (`engine/`) implements only the embedded-text and metadata layer.
- Findings from this pass are labelled as image-text findings so an operator can distinguish them from text-file hits.

---

## 4. Sector C: Risk Scoring Formula & Strict Secret Masking

### Mathematical Risk Model

NAS exposure risk is a function of both intrinsic payload sensitivity and storage visibility. Sentry computes a deterministic Risk Score $R$ for every detected finding:

$$R = S \times (1 + \alpha_{\text{multi}} + \beta_{\text{public}})$$

Where:
- **$S$ (Base Severity):** Intrinsic threat level of the exposed data asset:
  - `CRITICAL` ($S = 5.0$): Active cloud credentials, private keys, crypto seed phrases, unencrypted root database strings.
  - `HIGH` ($S = 3.0$): Government IDs, passports, SSNs, credit card numbers, payroll ledgers.
  - `MEDIUM` ($S = 1.0$): Internal bank statements without credentials, masked documents, low-confidence OCR findings reported by `ug-photo`.
- **$\alpha_{\text{multi}}$ (Multi-User Factor):**
  - $\alpha_{\text{multi}} = 0.50$ if the file resides in a multi-user shared folder.
  - $\alpha_{\text{multi}} = 0.00$ if the file resides in a strictly private user home directory.
- **$\beta_{\text{public}}$ (Public / Guest Factor):**
  - $\beta_{\text{public}} = 0.75$ if guest, anonymous, or passwordless network access is enabled on the storage share.
  - $\beta_{\text{public}} = 0.00$ if access requires authenticated credentials.

#### Composite Score Tiers
- **$R \ge 8.0$ (URGENT / CRITICAL):** Immediate risk of automated exploitation or widespread identity compromise. Recommended for immediate quarantine.
- **$4.0 \le R < 8.0$ (HIGH RISK):** Severe data exposure requiring prompt isolation or permission hardening.
- **$R < 4.0$ (ELEVATED / MEDIUM):** Sensitive organizational or personal record requiring review.

### Strict Zero-Leak Evidence Masking Standard

A security auditor must never become a secondary leak vector. All finding evidence printed to terminal output, chat responses, or generated Markdown reports **must be strictly redacted** according to the following deterministic rules:

| Secret Type | Redaction Rule | Masked Representation Example |
| :--- | :--- | :--- |
| **API Keys & Tokens** | Retain first 4 and last 4 chars; mask interior with `****` | `sk-live-****89a2` |
| **AWS Access Keys** | Retain first 4 and last 4 chars | `AKIA****MPLE` |
| **Private Keys** | Show key header type only; suppress key body | `[BEGIN RSA PRIVATE KEY: 2048-bit redacted]` |
| **Crypto Seed Phrases** | Retain word count and first word only | `[12-WORD SEED PHRASE starting with "abandon..."]` |
| **Payment Cards** | Retain first 4 and last 4 digits; mask middle 8–11 digits | `4111-****-****-1111` |
| **SSN / National IDs** | Mask all except last 4 digits | `***-**-6789` |
| **Bank Accounts / IBAN** | Mask country code + last 4 digits only | `DE**-****-****-****-4821` |
| **Database URIs** | Redact password token completely | `postgres://admin:********@192.168.1.100:5432/prod` |

> [!CAUTION]
> **Zero-Leak Invariant:** Under no circumstances shall an unredacted secret, full password, or complete government identifier be written to standard output or persisted to disk.

---

## 5. Sector D: Interactive Risk Heatmap Report & Confirmation Gate

### Report Generation via `ug-knowledge`

Upon scan completion, Sentry compiles the complete audit telemetry into a structured Markdown artifact entitled:  
`Risk_Heatmap_Report_<YYYY-MM-DD>.md`

The report is indexed into the NAS local semantic repository via:
```bash
ug-knowledge store --collection sentry_reports \
  --title "Risk Heatmap Report 2026-11-15" \
  --doc "Risk_Heatmap_Report_2026-11-15.md" \
  --format markdown
```

#### Canonical Report Structure
```markdown
# 🛡️ Sentry Local Security Audit — Risk Heatmap Report
**Audit Date:** 2026-11-15 09:30:00 UTC  
**Target Storage Roots:** `/volume1/Shared`  
**NAS Hardware:** UGREEN AI NAS iDX6011 Pro (UGOS 6.1)  
**Egress Status:** Verified 0 Bytes Transmitted (100% Local Execution)

---

### Executive Summary
- **Total Files Evaluated:** 1,482
- **Skipped Files (>50MB / Media Containers):** 89
- **Encrypted / Password-Protected Archives:** 3
- **Identified Security Findings:** 4
  - 🔴 **Critical Severity:** 2
  - 🟠 **High Severity:** 1
  - 🟡 **Medium Severity:** 1
- **Composite Risk Index:** 26.25 / 100

---

### Findings Matrix
| Finding ID | Severity | Score R | Category | Source Path | Masked Evidence | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `FIND-001` | `CRITICAL` | 11.25 | Cloud Key | `/volume1/Shared/Projects/app1/.env` | `sk-live-****89a2` | Immediate Quarantine |
| `FIND-002` | `CRITICAL` | 11.25 | Crypto Seed | `/volume1/Shared/Backups/wallet.txt` | `[12-WORD SEED: "abandon..."]` | Immediate Quarantine |
| `FIND-003` | `HIGH` | 6.75 | PII / SSN | `/volume1/Shared/Finance/payroll.csv` | `***-**-4491` | Quarantine / Restrict |
| `FIND-004` | `HIGH` | 6.75 | Payment Card | `/volume1/Shared/Photos/card_scan.png` | `4111-****-****-1111` | Quarantine |
```

---

## 6. Two-Step Human-in-the-Loop Quarantine Gate

Sentry adheres to a non-negotiable policy of human oversight: **no file is ever moved, renamed, or modified without explicit, authenticated user approval.**

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   TWO-STEP HUMAN CONFIRMATION GATE                     │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 1. Sentry presents Risk Heatmap Report in terminal / chat.             │
 │ 2. HARD STOP: Execution pauses. Sentry awaits explicit command:        │
 │      - APPROVE ALL CRITICAL                                            │
 │      - APPROVE FIND-001, FIND-002                                      │
 │      - ABORT                                                           │
 │ 3. User specifies or confirms target quarantine vault path:            │
 │      Default: /volume1/Private_Security_Vault/Quarantine_<YYYY-MM-DD>  │
 │ 4. Sentry executes atomic, non-destructive move via ug-filemgr:        │
 │      Preserves full relative directory hierarchy.                      │
 │ 5. Sentry writes quarantine-manifest.md for 1-click reversibility.     │
 └────────────────────────────────────────────────────────────────────────┘
```

### Collision-Safe Directory Preservation

To prevent file overwrite collisions (e.g., when two distinct projects contain identical filenames like `.env`), Sentry mirrors the relative directory structure inside the isolation vault:

```text
Original Locations:
  /volume1/Shared/Projects/app1/.env
  /volume1/Shared/Projects/app2/.env

Quarantine Vault Layout:
  /volume1/Private_Security_Vault/Quarantine_2026-11-15/
  └── Shared/
      └── Projects/
          ├── app1/
          │   └── .env
          └── app2/
              └── .env
```

### Manifest Generation & 1-Click Rollback (`quarantine-manifest.md`)

Each quarantine execution records an immutable audit ledger:

```markdown
# Sentry Quarantine Manifest
**Execution Timestamp:** 2026-11-15T09:42:15Z  
**Quarantine Vault:** `/volume1/Private_Security_Vault/Quarantine_2026-11-15`

| Finding ID | Original Path | Vault Path | SHA-256 Checksum | Quarantined At |
| :--- | :--- | :--- | :--- | :--- |
| `FIND-001` | `/volume1/Shared/Projects/app1/.env` | `/volume1/Private_Security_Vault/Quarantine_2026-11-15/Shared/Projects/app1/.env` | `e3b0c44298fc1c149afbf4c8996fb924...` | 2026-11-15T09:42:15Z |
| `FIND-002` | `/volume1/Shared/Backups/wallet.txt` | `/volume1/Private_Security_Vault/Quarantine_2026-11-15/Shared/Backups/wallet.txt` | `a1b2c3d4e5f60718293a4b5c6d7e8f90...` | 2026-11-15T09:42:16Z |

### 1-Click Rollback Command
To restore quarantined files to their original locations, execute:
`ug-filemgr move --source "<Vault Path>" --dest "<Original Path>" --create-parents`
```

---

## 7. Sector E: Edge Cases & Fault Tolerance

Sentry is engineered to handle real-world NAS operational quirks gracefully. Complete edge-case specifications are detailed in:  
👉 **[safety-and-edge-cases.md](references/safety-and-edge-cases.md)**

1. **Encrypted & Password-Protected Archives:** If an archive (`.zip`, `.7z`, `.rar`) or document (`.pdf`) is encrypted, Sentry marks it as `UNSCANNED_ENCRYPTED` with a `MEDIUM` severity reminder. Sentry **never** attempts brute-force decryption, preserving NAS CPU cycles.
2. **Corrupted & Zero-Byte Files:** Recorded as `SKIPPED_CORRUPT` without halting the pipeline.
3. **Permission-Denied Folders (`EACCES`):** Logged to the audit warnings section and skipped cleanly.
4. **Low-Confidence OCR Results:** Text returned by `ug-photo ocr` with confidence scores below 0.70 is downgraded to `MEDIUM` and tagged `CONFIDENCE_UNCERTAIN` for human review. The portable reference engine performs no OCR, so this tier applies only to the device path.
5. **Symlinks & Circular Mounts:** Sentry tracks visited inodes (`st_ino`, `st_dev`) and caps traversal depth at 16 levels to prevent infinite recursion across NFS or loop mounts.

---

## 8. UGOS CLI Orchestration Reference

All interactions with storage, documents, images, and knowledge graphs route strictly through native UGOS command-line utilities. Complete command flags, JSON response schemas, and error codes are documented in:  
👉 **[ugos-cli-orchestration.md](references/ugos-cli-orchestration.md)**

```bash
# Core UGOS Command Suite Utilized by Sentry:
ug-filesystem   # Storage enumeration, POSIX permission check, share metadata
ug-filemgr      # Atomic file isolation, directory creation, rollback restore
ug-document     # Text extraction, structured document decoding (.pdf, .docx, .xlsx)
ug-photo        # Delegated OCR and layout analysis (device-side; the engine does not OCR)
ug-knowledge    # Local report indexing and persistent audit history queries
```

---

## 9. Validation, Testing & Hackathon Demo Guide

For test harness instructions, synthetic mock generators, and judge validation workflows on the **UGREEN AI NAS iDX6011 Pro**, consult:  
👉 **[demo-and-validation-guide.md](references/demo-and-validation-guide.md)**

---

## 10. Mandatory Disclosures Section

In strict compliance with the **Uliya Skill Development Standard** and the **UGREEN Hackathon 2026 on AI NAS** rules:

1. **Third-Party Components & Licenses:**
   - **None.** Sentry is authored as a pure declarative Markdown Skill that orchestrates native UGREEN UGOS operating system binaries (`ug-filesystem`, `ug-filemgr`, `ug-document`, `ug-photo`, `ug-knowledge`). It contains no third-party libraries, binaries, proprietary runtimes, or external cloud dependencies.
2. **Principal Functionality Developed for Hackathon 2026:**
   - Designed and built the 4-Pass Deterministic Local Auditing Architecture specifically tailored to UGREEN NAS hardware characteristics.
   - Formulated the NAS context-aware exposure scoring formula ($R = S \times (1 + \alpha_{\text{multi}} + \beta_{\text{public}})$).
   - Engineered the Zero-Leak Evidence Masking Standard to prevent secondary leaks.
   - Developed the Two-Step Human-in-the-Loop Confirmation Gate with collision-safe relative directory preservation and 1-click rollback manifests.
3. **AI Tools Used During Authoring:**
   - Authoring, structural schema formatting, mathematical LaTeX rendering, and test harness authoring were assisted by Google DeepMind's Antigravity Agent and Gemini 3.8 Flash model. All detection logic, regex taxonomies, and UGOS orchestration specifications were reviewed, verified, and tuned for UGREEN AI NAS production readiness.
