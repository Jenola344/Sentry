# Sentry: Zero-Egress Local Security Auditor for UGREEN AI NAS

<div align="center">

```text
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
```

**Autonomous 100% Local Security Auditor & Reversible Quarantine Vault for UGREEN AI NAS (UGOS)**

[![UGREEN Hackathon 2026](https://img.shields.io/badge/UGREEN_Hackathon-2026_AI_NAS-00C853?style=for-the-badge&logo=shield)](https://github.com)
[![Track: Open Innovation](https://img.shields.io/badge/Track-Open_Innovation-blue?style=for-the-badge)](https://github.com)
[![Target: UGREEN iDX6011 Pro](https://img.shields.io/badge/Target-UGREEN_iDX6011_Pro-8A2BE2?style=for-the-badge&logo=linux)](https://github.com)
[![Zero-Egress Guaranteed](https://img.shields.io/badge/Zero--Egress-100%25_Local_Inspection-emerald?style=for-the-badge)](https://github.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

[Live Interactive Web Demo](#-live-interactive-web-demo) • [UGOS CLI Engine](#-engine-local-cli--python-engine) • [Uliya Skill Standard](#-skill-ugreen-uliya-skill-package) • [Architecture](#-core-architecture)

</div>

---

## 📖 Executive Summary

Network Attached Storage (NAS) appliances are rapidly transitioning from passive file servers into collaborative private clouds. On devices like the **UGREEN AI NAS iDX6011 Pro**, multi-user storage pools routinely hold developer workspaces, active deployment secrets, personal tax documents, cryptocurrency wallet seeds, and corporate payroll ledgers.

When folder permissions drift or public guest access is inadvertently enabled, these critical secrets become vulnerable to unauthorized LAN users, compromised Docker containers, or WAN exploit scanners.

**Sentry** is an autonomous, 100% on-device security auditor built natively for **UGREEN UGOS**. It operates with **zero external telemetry and zero cloud dependencies**, routing all inspections through native UGOS binaries (`ug-filesystem`, `ug-filemgr`, `ug-document`, `ug-photo`, `ug-knowledge`). Sentry maps storage, identifies exposed secrets, calculates context-aware risk scores, enforces strict zero-leak evidence redaction, and isolates files into a collision-safe vault **only upon explicit human confirmation**.

---

## 🏛️ Core Architecture

```mermaid
flowchart TD
    subgraph Sentry Engine ["Sentry Autonomous Core (Local UGOS)"]
        A["Input Validation & Scope Governance"] --> B["Pass 1: Inventory & Resource Guard<br/>(ug-filesystem)"]
        B --> C["Pass 2: Text, Code & Config Secrets<br/>(ug-document)"]
        C --> D["Pass 3: Structured Docs & Financial Records<br/>(ug-document)"]
        D --> E["Pass 4: Image Text & Metadata Audit<br/>(embedded text / EXIF)"]
        E --> F["Context-Aware Risk Scoring<br/>R = S × (1 + α + β)"]
        F --> G["Zero-Leak Evidence Redactor"]
        G --> H["Risk Heatmap Report Generation<br/>(ug-knowledge)"]
        H --> I{"Human-in-the-Loop<br/>Confirmation Gate"}
        I -- "User Rejects / Aborts" --> J["Audit Terminated (No File Changes)"]
        I -- "User Confirms IDs" --> K["Collision-Safe Reversible Quarantine<br/>(ug-filemgr)"]
        K --> L["quarantine-manifest.md Generated<br/>(1-Click Rollback Ready)"]
    end
```

---

## 🛡️ Key Pillars & Hackathon Innovations

### 1. 100% Zero-Egress Local Processing
Sentry never opens external network sockets, sends telemetry, or calls remote cloud APIs. All file parsing, regular-expression evaluation and metadata inspection execute locally on the NAS CPU; where the native `ug-photo` binary is present, pixel OCR runs on the on-device Intel AI Boost NPU.

### 2. Four-Pass Deterministic Pipeline
- **Pass 1 — Inventory & Resource Guard (`ug-filesystem`):** Maps directory trees while enforcing a strict 50 MB file size ceiling, bypassing streaming media containers (`.mp4`, `.mkv`), and whitelisting dependency lockfiles (`package-lock.json`, `Cargo.lock`) to suppress false positives on cryptographic hashes.
- **Pass 2 — Text, Code & Secrets (`ug-document`):** Scans `.env*`, `.pem`, `.json`, `.yaml`, and code files for cloud credentials (OpenAI, AWS access and secret keys, GitHub, Slack, Google Cloud, Stripe), private key headers, database connection URIs, and 12/24-word BIP-39 recovery phrases matched against the full 2,048-word English dictionary.
- **Pass 3 — Structured Documents & Financials (`ug-document`):** Parses `.pdf`, `.csv` and `.tsv` files for US SSNs, IBAN account numbers, passport MRZ lines, and bank-statement markers (`Account Balance`, `Routing Number`, `Wire Transfer`). Office containers (`.docx`, `.xlsx`) are not parsed.
- **Pass 4 — Image Text & Metadata (deep scans):** Reads text that is already stored inside image files — PNG `tEXt`/`zTXt`/`iTXt` chunks and JPEG `COM`/EXIF text tags — plus exposure-relevant metadata such as EXIF GPS presence. That text is scanned for payment card numbers (validated with the ISO/IEC 7812 Luhn algorithm), cloud API keys, SSNs and BIP-39 seed phrases. The portable engine performs **no pixel OCR**: on UGOS, pixel OCR is delegated to the native `ug-photo ocr` binary declared in the Skill.

### 3. Context-Aware Risk Scoring Formula
Risk is a function of both payload severity and network visibility:

$$R = S \times (1 + \alpha_{\text{multi}} + \beta_{\text{public}})$$

- **Base Severity ($S$):** `CRITICAL = 5.0` (Active API keys, root credentials, seed phrases), `HIGH = 3.0` (PII, payment cards, SSNs, payroll), `MEDIUM = 1.0` (Bank statements, encrypted archives).
- **Multi-User Multiplier ($\alpha_{\text{multi}}$):** $+0.50$ only when the file and every directory between it and the audited root grant group access (`g+r` on the file, `g+x` on the path).
- **Public / Guest Multiplier ($\beta_{\text{public}}$):** $+0.75$ only when the same chain grants other-user access (`o+r` / `o+x`) — i.e. the file is genuinely reachable by guests and unrelated accounts.
- **Maximum Composite Score:** $5.0 \times (1 + 0.50 + 0.75) = 11.25$.

Multipliers are **measured, not assumed**: the engine walks POSIX reachability per finding, so a `0644` file behind a `0700` directory scores $5.0$, not $11.25$, and a `0600` file inside a `0777` directory is still private. Unreadable metadata fails closed (treated as exposed) so an optimistic default can never under-report. Operators can pin the context explicitly with `--shared/--no-shared` and `--public/--no-public` when the NAS reports share state through SMB/NFS/guest settings rather than POSIX bits; the saved audit state records whether the values were derived, explicit, or mixed.

### 4. Strict Zero-Leak Evidence Masking Standard
Sentry never prints full raw secrets to terminal logs or markdown reports:
- **API Keys / Tokens:** First 4 and last 4 characters preserved (`sk-live-****89a2`).
- **Seed Phrases:** Mnemonic word count and first word only (`[12-WORD SEED PHRASE starting with "abandon..."]`).
- **Payment Cards:** Mask middle 8–11 digits (`4111-****-****-1111`).
- **SSN / National IDs:** Redacted except for last 4 digits (`***-**-6789`).
- **Database URIs:** Password token redacted completely (`postgres://user:********@host:5432/db`).

### 5. Two-Step Human-in-the-Loop Quarantine Gate
- **Zero Automated Deletions:** Sentry pauses immediately after presenting the Risk Heatmap.
- **Explicit Confirmation Grammar:** Requires user command (`APPROVE ALL CRITICAL` or `APPROVE FIND-001, FIND-002`).
- **Collision-Safe Vault:** Preserves full relative directory trees (`<Vault>/Shared/Projects/app1/.env` vs `<Vault>/Shared/Projects/app2/.env`), preventing file overwrites.
- **Owner-Only Vault (`0700`):** The vault root, session directory and every parent inside it are created `0700`, so quarantined files stay unreadable to other NAS accounts even though each file keeps its original mode. An existing looser vault is tightened on the next run.
- **Vault Outside the Share:** An audit refuses to start when `--vault` resolves inside `--target` — a vault below the share would keep the secrets in the exposed pool and be rescanned on the next pass.
- **Verified Custody:** The manifest checksum is recomputed *after* the move. If the file changed in transit it is returned to its original path and reported, instead of being filed under a hash it no longer matches.
- **1-Click Rollback:** Generates `quarantine-manifest.md` with SHA-256 hashes for instantaneous restoration.

---

## 📂 Repository Structure

```text
sentry-ugreen-nas/
├── README.md                          # Executive documentation & architecture
├── LICENSE                            # MIT Open Source License
├── skill/                             # Official UGREEN Uliya Skill Package
│   └── sentry/
│       ├── SKILL.md                   # Main Skill declaration & frontmatter
│       └── references/
│           ├── detection-taxonomy.md  # 4-Pass detection rules & regexes
│           ├── safety-and-edge-cases.md # Scoring formulas & failure modes
│           ├── ugos-cli-orchestration.md# Native UGOS command schemas
│           └── demo-and-validation-guide.md # Judge evaluation guide
├── engine/                            # Standalone Local Python CLI Engine
│   ├── sentry_cli.py                  # 4-pass scanner + interactive quarantine CLI
│   ├── rules.py                       # Modular regex, entropy, and masking detectors
│   ├── image_text.py                  # Embedded PNG/JPEG text + EXIF metadata extractor
│   ├── tests/                         # Pytest suite (masking, scoring, quarantine, rollback)
│   ├── requirements.txt               # Dependencies (rich, pypdf, pillow)
│   ├── sample_nas/                    # Safe synthetic NAS test dataset (4 passes)
│   │   └── generate_fixtures.py       # Deterministic fixture builder
├── web-demo/                          # Interactive Web Simulator (React + Vite)
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx                    # Main interactive dashboard
│       ├── engine/                    # 100% client-side 4-pass scanner
│       └── components/                # Visualizer, Heatmap, and Quarantine Vault
├── scripts/                           # Release and packaging utilities
│   └── package_skill.py               # Uliya SKILL.md validator & ZIP packager
└── .github/
    └── workflows/
        └── ci-and-package.yml         # CI automated testing & Uliya packaging
```

---

## 🚀 Quickstart Guides

### 1. Engine: Local CLI & Python Engine

Run the standalone CLI engine against the built-in synthetic NAS sample:

```bash
# Clone the repository
git clone https://github.com/your-org/sentry-ugreen-nas.git
cd sentry-ugreen-nas/engine

# Install lightweight dependencies
pip install -r requirements.txt

# Run the 4-Pass Deep Audit (exposure is derived from POSIX reachability)
python sentry_cli.py --target ./sample_nas/Shared --vault ./sample_nas/Private_Security_Vault --depth deep

# Or pin the share posture explicitly when POSIX bits do not express it
python sentry_cli.py --target ./sample_nas/Shared --vault ./sample_nas/Private_Security_Vault --public --no-shared

# Execute Human-Confirmed Quarantine for Critical Findings
# (confirms the saved audit state from the previous command — no rescan, so finding IDs cannot drift)
python sentry_cli.py --target ./sample_nas/Shared --vault ./sample_nas/Private_Security_Vault --approve "ALL CRITICAL"
# Equivalent explicit grammar: --approve "APPROVE ALL CRITICAL" / "FIND-001, FIND-002" / "ALL"

# Execute 1-Click Rollback via Manifest
python sentry_cli.py --action rollback --manifest ./sample_nas/Private_Security_Vault/Quarantine_*/quarantine-manifest.md
```

---

### 2. 🌐 Live Interactive Web Demo

Experience the full Sentry audit pipeline directly in your browser with **zero backend installation and zero server uploads**:

```bash
cd web-demo
npm install
npm run dev
```

1. Click **"Load Sample NAS Drive"** to populate a realistic UGREEN NAS storage structure with developer `.env` files, payroll spreadsheets, seed backups, and card scans.
2. Or click **"Drop / Upload Local Files"** to test your own files locally (processed entirely within your browser via FileReader).
3. Toggle **Multi-User** and **Guest Public** sharing contexts to watch the risk score $R$ adjust dynamically.
4. Click **"Run Sentry Audit"** to observe real-time Pass 1 $\rightarrow$ Pass 4 execution.
5. Select findings and click **"Proceed to Quarantine"** to test the Human Confirmation Gate, collision-safe vault tree, and 1-click rollback manifest.

---

### 3. 📦 Skill: UGREEN Uliya Skill Package

The `skill/sentry/` folder adheres strictly to the **Uliya Skill Development Standard**:
- **Format:** 100% Pure UTF-8 Markdown (`.md` files only; zero executable scripts or binaries inside the package).
- **Size Budget:** Total package is under 70 KB (far below the 10 MB ceiling).
- **Frontmatter:** Valid YAML with `name: sentry` and concise description ($< 1,024$ chars).
- **UGOS Native Orchestration:** Declarative command specifications for `ug-filesystem`, `ug-filemgr`, `ug-document`, `ug-photo`, and `ug-knowledge`.

To validate and build the release ZIP package:
```bash
python scripts/package_skill.py
# Outputs: sentry-final-round2.zip
```

---

## 📜 Mandatory Disclosures

In compliance with the **UGREEN Hackathon 2026 on AI NAS** rules:
1. **Third-Party Components & Licenses:** None. The core Uliya Skill package is pure declarative Markdown orchestrating native UGOS system binaries. The optional standalone CLI engine and web demo are open-sourced under the MIT License.
2. **Principal Functionality Developed for Hackathon 2026:**
   - 4-Pass Deterministic Local Auditing Architecture tailored to NAS storage.
   - Context-Aware NAS Risk Scoring Model ($R = S \times (1 + \alpha + \beta)$).
   - Zero-Leak Secret Redactor and collision-safe relative directory quarantine vault.
3. **AI Tools Used:** Structural formatting and validation scripting were assisted by Google DeepMind's Antigravity Agent and Gemini 3.8 Flash. All detection logic, regex taxonomies, and UGOS orchestration specifications were authored specifically for UGREEN UGOS production deployment.

---

<div align="center">
<b>UGREEN Hackathon 2026 on AI NAS • Track: Open Innovation • Target: UGREEN AI NAS iDX6011 Pro</b>
</div>
