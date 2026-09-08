# WRAITH — Full-Spectrum Offensive Security & Pentest Platform

> **The benchmark of agentic and application security.** A unified, fully-local platform that combines recon, web application scanning, API security testing, network pentesting, cloud infrastructure assessment, static analysis, dynamic exploitation, and continuous governance — all under one architecture.

**Version:** 2.1
**Status:** Architecture Definition
**Owner:** Ali Moyo — Cybersecurity & AI Engineer
**Intended Deployment:** Fully local (BYO LLM API key for dynamic modes)

---

## Table of Contents

1. [What is WRAITH](#1-what-is-wraith)
2. [Guiding Principles](#2-guiding-principles)
3. [Architecture Layers](#3-architecture-layers)
   - Architecture Overview — Non-Linear Flow
   - Dependencies & Routing Rules
   - Target-Specific Tool Selection
   - Layer 0: Target Acquisition & Reconnaissance
   - Layer 1: Intake & Safety
   - Layer 2: Web Application Vulnerability Scanning
   - Layer 3: API & Service Security Testing
   - Layer 4: Network & Infrastructure Pentesting
   - Layer 5: Cloud & Infrastructure Assessment
   - Layer 6: Static Analysis (SAST)
   - Layer 7: Agentic Security & Trust Analysis
   - Layer 8: Exploitation Engine
   - Layer 9: Post-Exploitation & Lateral Movement
   - Layer 10: Code Review & Remediation
   - Layer 11: Reporting & Governance
   - Layer 12: Orchestration & Runtime
4. [Component Catalog](#4-component-catalog)
5. [Security Skills Integration](#5-security-skills-integration)
6. [Detection Domain Coverage](#6-detection-domain-coverage)
7. [Local Deployment Architecture](#7-local-deployment-architecture)
8. [Phase Roadmap](#8-phase-roadmap)
 9. [Attack Surface Mapping](#9-attack-surface-mapping)
 10. [References & Repositories](#10-references--repositories)
 11. [Known Gaps & Risks](#11-known-gaps--risks)

---

## 1. What is WRAITH

WRAITH is a unified offensive security platform that answers one question:

> **"Is this target — web app, API, network, cloud, agent, or repository — secure?"**

It replaces fragmented toolchains with a layered architecture covering the full attack lifecycle. The name reflects its dual nature:

- **Offensive (the WRAITH):** The active probing, scanning, and exploitation engines that hunt vulnerabilities — Strix, SkillSpector's dynamic modes, and our 50+ offensive security skills form this capability.
- **Defensive (the analysis):** The static analysis, trust-boundary verification, and governance that prevent exploitation before it reaches production.

### Key Differentiators

| Feature | WRAITH | Traditional Toolchain |
|---------|--------|----------------------|
| Full-spectrum coverage (web + API + network + cloud + agentic) | Unified pipeline | 5+ separate tools |
| Agent-specific detection (MCP, tool poisoning, delegation) | First-class | Not covered |
| Web application scanning (OWASP Top 10) | Native (Strix + skills) | Burp Suite / ZAP |
| API security testing (REST/GraphQL/JWT) | Native | Postman / Insomnia |
| Network pentesting (ports, services, AD) | Integrated | Nmap / Nessus |
| Cloud infrastructure assessment | Integrated | ScoutSuite / Prowler |
| Autonomous pentesting agents | Native (Strix) | Manual testing |
| Dynamic evaluation with hardware-isolated sandbox | Phase 2 (CubeSandbox) | Not covered |
| Static analysis with agentic domain rules | Native (SkillSpector) | Generic SAST only |
| Code review & minimization | Integrated (Ponytail) | Separate tool |
| 50+ offensive skill knowledge base | Built-in methodology | Generic CWE only |
| Fully local, no telemetry | Default | SaaS-dependent |
| Agent BOM with composition drift | First-class | Not available |

---

## 2. Guiding Principles

> **External content is data, not authority.** — ScanAgenticRisk v2.0

### The WRAITH Security Model

```
Trusted Instructions (system policy, signed config, approved manifests)
    |
    ├── Deterministic authorization controls
    ├── Scoped credentials
    ├── Destination allowlists
    └── Transaction-bound approval

Untrusted Content (user input, MCP output, RAG, web, agent messages)
    |
    ├── MUST NOT influence authorization decisions
    ├── MUST be validated at every trust boundary
    └── Provenance MUST be tracked end-to-end
```

### Operational Principles

1. **Target-Read-Only** — WRAITH never modifies the scanned target. Output goes to a separate results directory.
2. **NOT_EVALUATED over PASS** — A rule whose capabilities are not available returns NOT_EVALUATED, never a clean bill of health.
3. **Hostile-by-default** — Every target is treated as potentially malicious. No code execution, no dependency install, no lifecycle scripts.
4. **Deterministic findings first** — Static analysis is the foundation. LLM augmentation is optional and clearly labeled.
5. **Verified controls only** — Only VERIFIED controls reduce risk. FAILED controls are surfaced as actionable findings.
6. **Process isolation** — Each engine runs in its own venv/container to prevent dependency conflicts.
7. **No telemetry by default** — All processing is local. No data leaves the machine unless explicitly configured for enrichment.
8. **Consent-first scanning** — WRAITH only scans targets you explicitly authorize. No passive discovery without user intent.

---

## 3. Architecture Layers

### Architecture Overview — Non-Linear Flow

WRAITH is NOT a linear pipeline. Analysis follows **three parallel tracks**, each targeting a different class of target with dedicated tools and skills, coordinated by a central Orchestrator.

```
                    ┌──────────────────────────────────────────────────┐
                    │         Target Acquisition & Reconnaissance      │
                    │  (DNS, subdomains, ports, tech profiling, OSINT) │
                    └────┬─────────────┬──────────────────┬───────────┘
                         │             │                  │
          ┌──────────────┘    ┌────────┘         ┌───────┘
          ▼                    ▼                   ▼
┌─────────────────────┐ ┌────────────────┐ ┌─────────────────────┐
│ TRACK A             │ │ TRACK B        │ │ TRACK C             │
│ Web & API Security  │ │ Network &      │ │ SAST & Agentic      │
│                     │ │ Cloud Security │ │ Security            │
│ Targets: web apps,  │ │ Targets: hosts,│ │ Targets: code repos,│
│ APIs, forms         │ │ AD, cloud, K8s │ │ MCP manifests,      │
│                     │ │                │ │ agent configs       │
│ Tools: Strix, Burp, │ │ Tools: Nmap,   │ │ Tools: SkillSpector,│
│ SQLMap, OWASP skills │ │ Metasploit,   │ │ Strix, Ponytail     │
│                     │ │ cloud scanners │ │                     │
│ Skills: web-vuln-   │ │ Skills: AD,    │ │ Skills: code-audit, │
│ playbooks, api-     │ │ cloud, network │ │ supply-chain, llm-  │
│ security-testing    │ │ pentest skills │ │ security-testing    │
└──────────┬──────────┘ └───────┬────────┘ └──────────┬──────────┘
           │                    │                     │
           ▼                    ▼                     ▼
     ┌──────────────────────────────────────────────────────┐
     │               Orchestrator (Coordinator)              │
     │  Routes findings, manages dependencies, schedules    │
     │  exploitation, aggregates reports                    │
     └──────┬──────────────┬──────────────────┬─────────────┘
            │              │                  │
            ▼              ▼                  ▼
     ┌──────────┐ ┌──────────────┐ ┌──────────────────┐
     │Exploit   │ │Post-Exploit  │ │Governance        │
     │Engine    │ │& Lateral     │ │(Reporting, BOM,  │
     │          │ │Movement      │ │compliance, GRC)  │
     │Input:    │ │              │ │                  │
     │confirmed │ │Input: exploit │ │Input: aggregated │
     │vulns from│ │access +      │ │findings from all │
     │Track A/B │ │agent findings│ │tracks + tracks   │
     │          │ │from Track C  │ │                  │
     └──────────┘ └──────────────┘ └──────────────────┘
```

#### Dependencies & Routing Rules

| From | To | Condition | Description |
|------|----|-----------|-------------|
| Recon (Layer 0) | Track A (Web/API) | Endpoint discovered | URLs, API routes found in recon |
| Recon (Layer 0) | Track B (Network/Cloud) | Host/port discovered | IPs, domains, cloud accounts found |
| Recon (Layer 0) | Track C (SAST/Agentic) | Repo/config found | Git repos, manifests, agent configs |
| Track A (Web vulns) | Orchestrator | Confirmed finding | Routes confirmed SQLi, XSS, IDOR etc. to Exploit |
| Track B (Cloud vulns) | Exploitation | High-confidence finding | Cloud misconfigs go direct to exploitation |
| Track C (Agent threats) | Post-Exploit | Agent finding confirmed | MCP poisoning, excessive agency go to post-exploit |
| Track B (Network vulns) | Orchestrator | AD/service finding | Routes AD credentials, service vulns to Exploit |
| Exploitation | Orchestrator | Access gained | Session info fed back for deeper scanning |
| Post-Exploit | Orchestrator | Lateral move detected | New targets discovered fed back to Recon |
| All Tracks | Governance | Scan complete | Findings aggregated for reporting |

#### Target-Specific Tool Selection

| Target Type | Tracks Used | Primary Tools | Secondary Tools |
|-------------|-------------|--------------|-----------------|
| Web application | Track A | Strix web scanner, Burp Suite | SQLMap, OWASP skills |
| REST/GraphQL API | Track A | Strix API fuzzer | Burp, jwt-oauth skills |
| Network host | Track B | Nmap, Strix | Metasploit auxiliary |
| Active Directory | Track B | Strix AD agent | Metasploit AD modules |
| AWS/Azure/GCP | Track B | Strix cloud scanner | Cloud-specific skills |
| Kubernetes cluster | Track B | Strix K8s scanner | Cloud penetration skills |
| Git repository | Track C | SkillSpector | Strix SAST, Ponytail |
| MCP server manifest | Track C | SkillSpector TP rules | Strix agentic security |
| AI agent config | Track C | ScanAgenticRisk spec | SkillSpector EA/PE rules |
| Mixed target | All 3 tracks | Orchestrator dispatches | Parallel execution |

### Layer 0 — Target Acquisition & Reconnaissance

**Purpose:** Discover, enumerate, and profile the target surface before any active scanning begins.

**Components:**
- **OSINT Gathering** — Domain enumeration, WHOIS, DNS records, certificate transparency
- **Subdomain Discovery** — DNS brute-force, passive enumeration, certificate logs
- **Shodan Integration** — Internet-wide device/service discovery, banner grabbing
- **Port Scanning** — TCP/UDP port discovery, service fingerprinting, version detection
- **Technology Profiling** — Wappalyzer-style tech stack detection, framework identification
- **Web Crawling** — Sitemap generation, endpoint discovery, parameter mining

**Inputs:** Domains, IP ranges, URLs, company names, org names
**Outputs:** Enriched target inventory (endpoints, services, technologies, open ports)

**Integration:**
- **Strix** — Multi-agent recon workflows (recon agent as first stage)
- **Shodan CLI** — Internet-wide device fingerprinting
- **Nmap** — Port scanning and service enumeration
- **50 skills methodology** — `shodan-reconnaissance`, `pentest-commands`, `wireshark-network-traffic-analysis`

**Offensive Security Skills:**
- `shodan-reconnaissance-and-pentesting` — Shodan API for internet-scale recon
- `wireshark-network-traffic-analysis` — Network traffic profiling
- `pentest-commands` — Essential scanning command references
- `pentest-checklist` — Structured recon methodology

---

### Layer 1 — Intake & Safety

**Purpose:** Safely acquire, validate, and prepare target artifacts for analysis. Only applies to file/repo-based targets.

**Components:**
- **Path Security** — Canonicalize paths, enforce scan root, reject symlink escapes
- **Archive Safety** — Zip bomb protection, path traversal guards, size limits
- **File Discovery** — Supported file type detection, exclusion patterns, content hashing
- **Pre-scan Vetting** — Untrusted-skill-repo-extraction protocol

**Inputs:** Git repos, archives, directories, single files, raw source
**Outputs:** Deterministic scan inventory (hashed file list with parser types)

**Integration:** [SkillSpector](https://github.com/NVIDIA/SkillSpector) `input_handler.py` — hardened discovery engine with 100 MiB ingest cap, 10K zip member cap, 16 MiB central-directory cap, 4 KiB path cap, symlink rejection, and O_PATH traversal.

**Offensive Security Skills:** `untrusted-skill-repo-extraction`, `file-uploads`, `security-ownership-map`

---

### Layer 2 — Web Application Vulnerability Scanning

**Purpose:** Identify vulnerabilities in web applications through automated scanning, fuzzing, and manual-style probe sequences.

**Components:**

#### 2.1 OWASP Top 10 Coverage
- **SQL Injection** — Error-based, boolean blind, time-based, out-of-band, second-order
- **Cross-Site Scripting (XSS)** — Reflected, stored, DOM-based, mXSS
- **Cross-Site Request Forgery (CSRF)** — Token validation, same-origin checks
- **Server-Side Request Forgery (SSRF)** — URL validation, SSRF to RCE chains
- **Security Misconfiguration** — Default credentials, debug endpoints, directory listing
- **Broken Access Control** — IDOR, privilege escalation, forced browsing
- **Insecure Deserialization** — Object injection, gadget chains
- **File Upload Vulnerabilities** — MIME validation, extension bypass, content inspection
- **XXE (XML External Entities)** — Document parsing, entity expansion, SSRF via XXE

#### 2.2 Form & Parameter Fuzzing
- Input validation bypass techniques
- Content-type switching
- HTTP parameter pollution
- Encoding/decoding fuzzing
- Boundary value analysis

#### 2.3 CMS & Framework Detection
- WordPress vulnerability scanning
- Joomla, Drupal, Magento detection
- Framework version fingerprinting
- Known CVE database matching

**Integration:**
- **Strix** — Multi-agent web scanning with active exploit validation
- **Strix** `web_vulnerability_assessment` skill — Full OWASP methodology
- **Burp Suite** — Interception and manual testing workflows
- **SQLMap** — Automated SQL injection detection and exploitation

**Offensive Security Skills:**
- `web-security-testing` — OWASP Top 10 testing workflow
- `web-vuln-playbooks` — SQLi, XSS, SSRF, RCE, IDOR playbooks
- `sql-injection-testing` — Full SQLi methodology
- `cross-site-scripting-and-html-injection-testing` — XSS testing
- `idor-vulnerability-testing` — IDOR detection and exploitation
- `file-path-traversal-testing` — Directory traversal testing
- `broken-authentication-testing` — Auth testing methodology
- `burp-suite-web-application-testing` — Web testing with Burp Suite
- `top-100-web-vulnerabilities-reference` — Vulnerability taxonomy
- `vulnerability-scanner` — Advanced vulnerability analysis
- `sqlmap-database-penetration-testing` — Automated SQLi with sqlmap
- `html-injection-testing` — HTML injection techniques

---

### Layer 3 — API & Service Security Testing

**Purpose:** Identify vulnerabilities in REST, GraphQL, and service APIs.

**Components:**

#### 3.1 REST API Testing
- **Authentication** — JWT weakness, token expiry, OAuth misconfiguration
- **Authorization** — BOLA, mass assignment, privilege escalation
- **Rate Limiting** — Brute force protection, throttling bypass
- **Input Validation** — Injection, schema validation, content-type attacks
- **Information Disclosure** — Error messages, stack traces, debug endpoints

#### 3.2 GraphQL API Testing
- Introspection query analysis
- Batching attacks (extracting data via batch queries)
- Depth-based DoS testing
- Field suggestion attacks
- Arbitrary field injection

#### 3.3 JWT & OAuth Security
- Algorithm confusion (none, HS256 on RS256 keys)
- Token expiration and revocation
- JWT injection attacks
- OAuth redirect URI manipulation
- CSRF on OAuth flows

**Integration:**
- **Strix** — API fuzzing and authentication testing
- **Strix** `api_fuzzing` skill — Automated API security testing
- **Burp Suite** — Interception and replay testing

**Offensive Security Skills:**
- `api-security-testing` — REST/GraphQL API security testing
- `jwt-oauth-graphql-testing` — JWT/OAuth/GraphQL testing
- `api-fuzzing-for-bug-bounty` — API fuzzing techniques
- `api-security-best-practices` — Secure API design patterns

---

### Layer 4 — Network & Infrastructure Pentesting

**Purpose:** Discover and exploit network-level vulnerabilities, service misconfigurations, and infrastructure weaknesses.

**Components:**

#### 4.1 Port Scanning & Service Enumeration
- TCP connect/SYN scans
- UDP port scanning
- Service version detection
- OS fingerprinting
- NSE script execution (Nmap Scripting Engine)

#### 4.2 Service-Specific Testing
- **SSH** — Weak cipher support, key exchange algorithms, default credentials
- **SMTP** — Open relay, user enumeration, STARTTLS downgrade
- **DNS** — Zone transfer, subdomain enumeration, DNSSEC validation
- **FTP** — Anonymous access, path traversal, credential brute-force
- **SMB** — Null session, relay attacks, SMB signing

#### 4.3 Active Directory Assessment
- LDAP enumeration
- Kerberos attacks (AS-REP roasting, Kerberoasting)
- NTLM relay and pass-the-hash
- Domain trust analysis
- Group Policy Object review

**Integration:**
- **Nmap** — Primary port scanning and service enumeration
- **Strix** — Multi-agent network pentesting workflows
- **Metasploit** — Network exploitation modules

**Offensive Security Skills:**
- `active-directory-attacks` — AD security testing
- `ssh-penetration-testing` — SSH security assessment
- `smtp-penetration-testing` — Email server testing
- `wireshark-network-traffic-analysis` — Network traffic analysis
- `pentest-checklist` — Structured pentest methodology
- `pentest-commands` — Essential pentesting commands
- `red-team-tools-and-methodology` — Full red team toolkit
- `red-team-tactics` — MITRE ATT&CK-aligned tactics

---

### Layer 5 — Cloud & Infrastructure Assessment

**Purpose:** Assess cloud platform configurations, IAM policies, and infrastructure security posture.

**Components:**

#### 5.1 AWS Assessment
- IAM policy review (over-permissive roles, trust policies)
- S3 bucket permissions and public access
- EC2 security group analysis
- CloudTrail and logging configuration
- KMS key management

#### 5.2 Azure Assessment
- RBAC role assignments
- Azure AD configuration
- Key Vault access policies
- Storage account security
- Network security group rules

#### 5.3 GCP Assessment
- IAM policy review
- Cloud Storage bucket permissions
- GKE cluster security
- VPC firewall rules
- Cloud SQL configuration

#### 5.4 Kubernetes Security
- RBAC configuration review
- Pod security policies
- Network policy analysis
- Container image vulnerability scanning
- Secret management

**Integration:**
- **Strix** — Cloud infrastructure misconfiguration scanning
- **50 skills methodology** — Cloud-specific testing techniques

**Offensive Security Skills:**
- `cloud-penetration-testing` — AWS/Azure/GCP security assessment
- `aws-penetration-testing` — AWS-specific testing
- `google-cloud-waf-security` — GCP security assessment
- `google-cloud-auth` — GCP authentication testing
- `google-cloud-waf-reliability` — GCP reliability assessment
- `google-cloud-networking-observability` — GCP network analysis

---

### Layer 6 — Static Analysis Core (SAST)

**Purpose:** Identify vulnerabilities through static analysis of source code, configurations, and manifests without executing the target.

**Components:**

#### 6.1 Python AST Analysis
- Parse Python source with `ast.parse()`
- Name and scope resolution
- Control-flow graph construction
- Intraprocedural taint tracking

#### 6.2 Configuration & Manifest Analysis
- JSON/YAML/TOML parsing (safe loaders only)
- Dockerfile and CI/CD workflow analysis
- Dependency files (pip, npm, poetry, etc.)
- Infrastructure as Code (Terraform, CloudFormation)

#### 6.3 Multi-Format Scanning
- JSON, YAML, TOML parsers
- Container image analysis
- Prompt template inspection (.jinja, .prompt)

#### 6.4 Rule Engine
- Declarative rule contracts (rule ID, base severity, modifiers, taxonomy mappings)
- Capability-aware evaluation (NOT_EVALUATED for unimplemented rules)
- Confidence scoring with false-positive suppression
- Organization-specific rule packs

#### 6.5 Secrets Detection
- Credential patterns (API keys, tokens, passwords, JWTs)
- Redacted evidence output (never full secrets in reports)
- Remediation recommendations for exposed credentials

#### 6.6 Dependency & Supply Chain
- Lock file integrity verification
- Pinned vs floating dependencies
- Package name similarity (squatting detection)
- OSV.dev integration (optional, offline-capable)

**Integration:**
- **[SkillSpector](https://github.com/NVIDIA/SkillSpector)** — Primary SAST engine. 18 pattern categories spanning static analysis, MCP tool poisoning, supply chain, behavioral AST, and YARA matching. Two-stage analysis (static + optional LLM).
- **ScanAgenticRisk** — Self-developed rule contract framework, capability registry, NOT_EVALUATED discipline.
- **[Strix](https://github.com/usestrix/strix)** `source_aware_sast` — Semgrep/AST/secrets/supply-chain static triage workflow.

**Offensive Security Skills:**
- `code-audit` — Source-code security review and SAST workflows
- `fastapi-security-audit` — FastAPI-specific security auditing
- `sast-configuration` — SAST tool setup and custom rule creation
- `supply-chain-guard` — Supply chain attack detection
- `supply-chain-security` — SBOM/SCA and CI/CD auditing
- `secrets-management` — Secrets management best practices
- `security-best-practices` — Language/framework-specific security reviews
- `api-security-best-practices` — Secure API design patterns

---

### Layer 7 — Agentic Security & Trust Analysis

**Purpose:** The distinguishing capability of WRAITH. Detect threats unique to AI agent ecosystems — prompt injection, MCP tool poisoning, agent hijacking, delegation abuse, excessive agency.

#### 7.1 MCP Security Analysis
- **Tool poisoning** (SkillSpector TP1-TP4):
  - TP1: Hidden instructions in metadata (HTML comments, zero-width chars, base64 blobs)
  - TP2: Unicode deception (homoglyphs, RTL overrides)
  - TP3: Parameter description injection
  - TP4: Description-behavior mismatch (LLM-powered, optional)
- **Least-privilege verification** (SkillSpector LP1-LP3)
- **Configuration security** — transport, auth, permissions, wildcards

#### 7.2 Indirect Prompt Injection & Agent Hijacking
- Trust-flow analysis from untrusted sources to model context
- MCP output to LLM prompt paths
- RAG retrieval to tool selection paths
- System prompt contamination detection

#### 7.3 Excessive Agency & Authorization
- Permission analysis (wildcards, overbroad scopes)
- Role-mining from manifest declarations
- Write/delete capability detection
- Credential scope analysis (OAuth scopes, API key permissions)

#### 7.4 Memory & RAG Security
- Memory poisoning detection
- Untrusted content persistence tracking
- Tenant isolation verification
- Provenance tracking in retrieval pipelines

#### 7.5 Multi-Agent & A2A Security
- Delegation chain analysis (read to admin escalation)
- Authority amplification detection
- Cross-agent trust flow verification
- Agent-to-agent protocol analysis

#### 7.6 Browser & Computer-Use Agent Security
- DOM/UI content as injection surface
- Vision input as untrusted content
- click/navigate/form-execution sink detection
- Screen content to instruction path analysis

**Integration:**
- **[SkillSpector](https://github.com/NVIDIA/SkillSpector)** — MCP tool poisoning, excessive agency, privilege escalation, memory poisoning detection
- **[Strix](https://github.com/usestrix/strix)** `agentic_system_security` skill — Effective authority mapping, confused deputy testing, MCP ecosystem security
- **[Strix](https://github.com/usestrix/strix)** `llm_prompt_injection` skill — Direct/indirect/multimodal/memory injection testing

**Offensive Security Skills:**
- `llm-security-testing` — Prompt injection testing methodology
- `security-threat-model` — Repository-grounded threat modeling
- `threat-modeling-expert` — STRIDE, PASTA, attack trees

---

### Layer 8 — Exploitation Engine

**Purpose:** Actively exploit confirmed vulnerabilities to demonstrate impact, and automate exploitation workflows.

**Components:**

#### 8.1 Automated Exploitation (Metasploit)
- Payload generation and delivery
- Exploit module selection and execution
- Post-exploitation module integration
- Meterpreter session management
- Auxiliary module scanning

#### 8.2 SQL Injection Exploitation (SQLMap)
- Automated SQL injection detection
- Database fingerprinting
- Data extraction (tables, schemas, rows)
- OS command execution via SQL
- File read/write via SQL injection

#### 8.3 Web Application Exploitation (Burp Suite)
- Interception and replay
- Intruder-based fuzzing and brute-force
- Repeater for manual testing
- Scanner for automated detection
- Extender for custom plugins

#### 8.4 Custom Exploit Development
- Python-based PoC generation
- Exploit code review and adaptation
- Shellcode generation
- Payload encoding and obfuscation

**Integration:**
- **Metasploit Framework** — Automated exploitation and payload delivery
- **SQLMap** — Automated SQL injection exploitation
- **Burp Suite** — Web application exploitation
- **Strix** — Multi-agent exploitation orchestration

**Offensive Security Skills:**
- `metasploit-framework` — Exploitation with Metasploit
- `sqlmap-database-penetration-testing` — Automated SQLi with sqlmap
- `burp-suite-web-application-testing` — Web testing with Burp Suite
- `red-team-tools-and-methodology` — Full red team toolkit
- `red-team-tactics` — MITRE ATT&CK-aligned tactics
- `ethical-hacking-methodology` — Full pentest lifecycle
- `api-fuzzing-for-bug-bounty` — API fuzzing for exploitation

---

### Layer 9 — Post-Exploitation & Lateral Movement

**Purpose:** After initial access, expand foothold, escalate privileges, and move laterally through the target environment.

**Components:**

#### 9.1 Privilege Escalation
- **Linux** — SUID/SGID binaries, kernel exploits, cron jobs, sudo misconfigurations, capability abuse
- **Windows** — Token manipulation, service permissions, DLL hijacking, UAC bypass, unquoted service paths
- **Cloud** — IAM privilege escalation, role chaining, trust policy abuse

#### 9.2 Lateral Movement
- SSH key harvesting and reuse
- Pass-the-hash and pass-the-ticket
- Remote WMI and PowerShell execution
- SMB/PsExec remote execution
- Cloud provider API pivoting

#### 9.3 Persistence Mechanisms
- Backdoor user accounts
- SSH authorized_keys manipulation
- Cron job / scheduled task injection
- Web shell deployment
- Cloud resource backdoor creation

#### 9.4 Data Exfiltration
- Sensitive data discovery
- Archive and exfiltrate techniques
- Network egress detection
- Data loss prevention bypass testing

**Integration:**
- **Metasploit** — Post-exploitation modules
- **Strix** — Multi-agent lateral movement workflows
- **50 skills methodology** — Privesc and lateral movement techniques

**Offensive Security Skills:**
- `linux-privilege-escalation` — Linux privesc techniques
- `windows-privilege-escalation` — Windows privesc techniques
- `privilege-escalation-methods` — Cross-platform privesc
- `active-directory-attacks` — AD lateral movement
- `red-team-tactics` — MITRE ATT&CK-aligned post-exploitation

---

### Layer 10 — Code Review & Remediation

**Purpose:** Review findings, generate remediation proposals, verify fixes, and minimize code churn.

#### 10.1 Code Review Engine
- Lazy senior dev principle (Ponytail's 7-rung ladder):
  1. Does this need to exist? (YAGNI)
  2. Already in this codebase? Reuse it.
  3. Stdlib does it? Use it.
  4. Native platform feature? Use it.
  5. Installed dependency? Use it.
  6. One line? One line.
  7. Minimum that works.
- Two-axis code review (standards vs spec) — from `mattpocock/skills`

#### 10.2 Remediation Generation
- **Advisory mode** — Root cause explanation + architectural fix
- **Patch proposal** — Unified diff (applied by separate write-enabled process)
- **Safe autofix** — Deterministic autofix candidates (flag changes, not semantic fixes)
- **Manual remediation** — Human-guided fix with verification steps

#### 10.3 Fix Verification
- Re-run WRAITH against the patched code
- Verify no regressions (no NEW findings introduced by the fix)
- Baseline comparison (only new issues surfaced)

**Integration:**
- **[Ponytail](https://github.com/DietrichGebert/ponytail)** — Code review/minimization plugin. Reduces code by ~54%, cost by ~20%.
- **[Strix](https://github.com/usestrix/strix)** `fix-security-vulnerabilities-with-strix` skill — Automated fix generation and verification

**Offensive Security Skills:**
- `code-review-excellence` — Code review best practices
- `debugging-strategies` — Systematic debugging for fix verification
- `code-simplifier` — Code simplification and refactoring

---

### Layer 11 — Reporting & Governance

**Purpose:** Aggregate findings, track security posture over time, detect drift, and integrate with GRC platforms.

#### 11.1 Findings Aggregation
- Unified finding format across all layers
- Severity scoring (CVSS 3.1 base + WRAITH modifiers)
- Confidence scoring
- Evidence capture (screenshots, request/response pairs, code snippets)

#### 11.2 Agent Bill of Materials (BOM)
```
Agent
├── Model & Provider
├── System prompt
├── Skills & Plugins
├── MCP servers (tools, resources, permissions)
├── Dependencies (pinned, hashed)
├── Containers
├── Credentials (scopes, expiry)
├── RAG stores
├── Memory stores
└── External endpoints
```

#### 11.3 Composition Drift Detection
- Hashed BOM snapshot at approval time
- Current BOM compared to approved baseline
- Composition diff triggers security review requirement

#### 11.4 Control Effectiveness Monitoring
- **Control states:** EFFECTIVE / PARTIALLY_EFFECTIVE / INEFFECTIVE / NOT_TESTED / NOT_APPLICABLE
- **Policy-evidence state machine:** VERIFIED / CANDIDATE / ABSENT / UNKNOWN / FAILED
- Trend history across repeated scans
- Remediation SLA tracking

#### 11.5 CI/CD Integration
- **Output formats:** JSON, SARIF 2.1.0, Markdown, HTML
- **Quality gates:**
  - Fail: Any critical finding, High + High confidence, attack chain rated Critical
  - Warn: Medium findings, low-confidence Highs, missing lock files
- **Modes:** Full scan / incremental (changed files only) / PR scan

#### 11.6 Compliance Mapping
- OWASP Top 10 for Web Applications 2021
- OWASP API Top 10 2023
- OWASP GenAI LLM Top 10 2026
- OWASP Top 10 for Agentic Applications 2026
- OWASP MCP Top 10
- CWE / MITRE ATLAS / MITRE ATT&CK
- ISO/IEC 27001, ISO/IEC 42001
- PCI DSS, GDPR, SOC 2

**Integration:**
- **[ThemisIQ](https://github.com/AliMoyo1/themis-iq-platform)** — Continuous control monitoring consumer (takes WRAITH's JSON/SARIF as evidence input)

---

### Layer 12 — Orchestration & Runtime

**Purpose:** Route analysis tasks to the correct engine based on trigger taxonomy, manage process isolation, and coordinate parallel workstreams.

#### 12.1 Task Router (Option A Prototype)
Based on the Agent Runtime prototype (at `./agent-runtime/` relative to the WRAITH workspace):

- **YAML trigger rules** (`triggers.yaml`) — Priority-ordered rule table
- **Engine adapters** — Each engine in its own venv with lazy imports
- **Trigger taxonomy:**

| Trigger / Flag | Routes to | Use Case |
|---------------|-----------|----------|
| `requires_code` | smolagents CodeAgent | Code generation, transformation, PII sanitization |
| `multi_agent` | CrewAI Crew | Team-based investigation (recon + compliance + report) |
| `human_gates + retries` | CrewAI Flow | Audit pipeline with approval gates |
| `flow_pipeline` | CrewAI Flow | Sequential multi-step analysis |
| `mcp_client` | MCP-tool agent | Direct MCP tool invocation |
| `scan_target` | WRAITH static scan | Security repository scanning |
| `dynamic_eval` | Strix + CubeSandbox | Offensive validation + sandboxed evaluation |
| `web_scan` | Strix web vuln scanner | Web application vulnerability scanning |
| `api_scan` | Strix API fuzzer | API security testing |
| `network_scan` | Nmap + Strix | Network pentesting |
| `exploit` | Metasploit/SQLMap | Active exploitation |
| `cloud_audit` | Strix cloud scanner | Cloud infrastructure assessment |
| (default fallback) | Lite tool agent | Simple queries, reading, explaining |

#### 12.2 Process Isolation
- Each engine runs in its own virtual environment
- smolagents venv (light, ~12K lines)
- CrewAI venv (heavy, ~320K lines)
- Strix venv (Docker-managed sandbox)
- Metasploit/SQLMap/Burp via native installs
- Pass results between engines via JSON contract

#### 12.3 Demultiplexing & Scheduling
- Parallel scanning (independent targets → concurrent analysis)
- Incremental scanning (Git commit baseline + changed files)
- Batch scanning for target collections
- Priority-based scheduling (critical targets first)

**Integration:**
- **Agent Runtime Prototype** (`./agent-runtime/`) — 11 tests green, OpenRouter DeepSeek wired
- **WRAITH CLI** — Unified interface that wraps all engines

---

## 4. Component Catalog

### Primary Repositories

| Repo | Lines (core) | Language | License | Role in WRAITH |
|------|-------------|----------|---------|----------------|
| **[SkillSpector](https://github.com/NVIDIA/SkillSpector)** | ~56K (src + contrib) | Python | Apache 2.0 | **Core SAST engine.** 18 pattern categories, MCP tool poisoning (TP1-TP4), behavioral AST, YARA. |
| **[Strix](https://github.com/usestrix/strix)** | ~69K | Python | Apache 2.0 | **Autonomous pentesting.** Multi-agent orchestration, web/API/network scanning, active exploitation. |
| **[CubeSandbox](https://github.com/TencentCloud/CubeSandbox)** | ~39K (Python core; 226K Rust + 122K Go incl. vendored KVM/RustVMM) | Rust+Python+Go | Apache 2.0 | **Hardware-isolated sandbox.** KVM/RustVMM, <60ms startup, E2B-compatible. |
| **[Ponytail](https://github.com/DietrichGebert/ponytail)** | ~2K | JavaScript | MIT | **Code review/minimization.** Reduces code ~54%, cost ~20%. |
| **[Handy](https://github.com/cjpais/Handy)** | ~100K (Rust backend + TSX frontend) | Rust+TS | MIT | Voice attestation (non-security, reference only). |

Counts are source-lines-of-code measured on the cloned repos; CubeSandbox splits core Python from vendored Go/Rust hypervisor code. Star counts are omitted — they age quickly and add no architectural value.

### Supporting Tools

| Tool | Location | Role |
|------|----------|------|
| **ScanAgenticRisk** | Self-developed spec | Rule contract framework, detection domains, governance model |
| **Agent Runtime (Option A)** | `./agent-runtime/` | Task routing, process isolation, cross-engine orchestration |
| **Metasploit Framework** | System install | Automated exploitation, payload delivery, post-exploitation |
| **SQLMap** | System/native install | Automated SQL injection detection and exploitation |
| **Burp Suite** | System install | Web application interception, fuzzing, exploitation |
| **Nmap** | System install | Port scanning, service enumeration, NSE scripts |
| **Shodan CLI** | System install | Internet-scale reconnaissance |
| **smolagents** | Tool Repo | Hugging Face code-agent (code execution engine) |
| **CrewAI** | Tool Repo | Multi-agent orchestration (team-based investigation flows) |
| **mattpocock/skills** | Tool Repo | Two-axis code review, tight-loop debugging |
| **Semantica KG** | Local | Decision provenance recording for audit trails |

### Repository Map (Cloned for Review)

All repos cloned to `./repos/` (relative to the WRAITH workspace):

```
repos/
├── SkillSpector/          # NVIDIA agent skill scanner (primary SAST)
├── strix/                 # Autonomous AI pentesting agent
├── CubeSandbox/           # Hardware-isolated sandbox (Tencent Cloud)
├── ponytail/              # Code review/minimization plugin
└── Handy/                 # Speech-to-text (non-security, reference only)
```

---

## 5. Security Skills Integration

All 50+ security skills from the Hermes skills library are integrated into WRAITH's knowledge base. They serve as:

1. **Methodology guides** for Strix agents (loaded as skill packs)
2. **Detection rule templates** for WRAITH's rule contract framework
3. **Analyst guidance** for human review of findings

### Skills by Layer

#### Layer 0 — Reconnaissance Skills
- `shodan-reconnaissance-and-pentesting` — Shodan API for internet-scale recon
- `wireshark-network-traffic-analysis` — Network traffic profiling
- `pentest-commands` — Essential scanning command references
- `pentest-checklist` — Structured recon methodology

#### Layer 1 — Intake & Discovery Skills
- `untrusted-skill-repo-extraction` — Safe repo extraction protocol
- `file-uploads` — Secure file handling, path validation
- `security-ownership-map` — Git-based security ownership analysis

#### Layer 2 — Web Application Skills
- `web-security-testing` — OWASP Top 10 testing workflow
- `web-vuln-playbooks` — SQLi, XSS, SSRF, RCE, IDOR playbooks
- `sql-injection-testing` — Full SQLi methodology
- `cross-site-scripting-and-html-injection-testing` — XSS testing
- `idor-vulnerability-testing` — IDOR detection and exploitation
- `file-path-traversal-testing` — Directory traversal testing
- `broken-authentication-testing` — Auth testing methodology
- `burp-suite-web-application-testing` — Web testing with Burp Suite
- `html-injection-testing` — HTML injection techniques
- `top-100-web-vulnerabilities-reference` — Vulnerability taxonomy
- `vulnerability-scanner` — Advanced vulnerability analysis

#### Layer 3 — API Security Skills
- `api-security-testing` — REST/GraphQL API security testing
- `jwt-oauth-graphql-testing` — JWT/OAuth/GraphQL testing
- `api-fuzzing-for-bug-bounty` — API fuzzing techniques
- `api-security-best-practices` — Secure API design patterns

#### Layer 4 — Network & AD Skills
- `active-directory-attacks` — AD security testing
- `ssh-penetration-testing` — SSH security assessment
- `smtp-penetration-testing` — Email server testing

#### Layer 5 — Cloud Skills
- `cloud-penetration-testing` — AWS/Azure/GCP security assessment
- `aws-penetration-testing` — AWS-specific testing
- `google-cloud-waf-security` — GCP security assessment
- `google-cloud-auth` — GCP authentication testing
- `google-cloud-waf-reliability` — GCP reliability assessment
- `google-cloud-networking-observability` — GCP network analysis

#### Layer 6 — SAST & Static Analysis Skills
- `code-audit` — Source-code security review and SAST workflows
- `fastapi-security-audit` — FastAPI-specific security auditing
- `sast-configuration` — SAST tool setup and custom rule creation
- `supply-chain-guard` — Supply chain attack detection
- `supply-chain-security` — SBOM/SCA and CI/CD auditing
- `secrets-management` — Secrets management best practices
- `security-best-practices` — Language/framework-specific security reviews
- `security-review` — Security architecture review
- `security-audit` — Comprehensive security auditing workflow

#### Layer 7 — Agentic Security Skills
- `llm-security-testing` — Prompt injection testing methodology
- `security-threat-model` — Repository-grounded threat modeling
- `threat-modeling-expert` — STRIDE, PASTA, attack trees

#### Layer 8 — Exploitation Skills
- `metasploit-framework` — Exploitation with Metasploit
- `sqlmap-database-penetration-testing` — Automated SQLi with sqlmap
- `red-team-tools-and-methodology` — Full red team toolkit
- `red-team-tactics` — MITRE ATT&CK-aligned tactics
- `ethical-hacking-methodology` — Full pentest lifecycle

#### Layer 9 — Post-Exploitation Skills
- `linux-privilege-escalation` — Linux privesc techniques
- `windows-privilege-escalation` — Windows privesc techniques
- `privilege-escalation-methods` — Cross-platform privesc

#### Layer 10 — Code Review Skills
- `code-review-excellence` — Code review best practices
- `debugging-strategies` — Systematic debugging for fix verification
- `code-simplifier` — Code simplification and refactoring

---

## 6. Detection Domain Coverage

| Domain | WRAITH Coverage | Tool | Skill |
|--------|----------------|------|-------|
| **SQL Injection** | ✓ | Strix + SQLMap | `sql-injection-testing`, `sqlmap` |
| **Cross-Site Scripting (XSS)** | ✓ | Strix + Burp | `cross-site-scripting` |
| **Cross-Site Request Forgery** | ✓ | Strix | `web-vuln-playbooks` |
| **Server-Side Request Forgery** | ✓ | Strix | `web-vuln-playbooks` |
| **IDOR / BOLA** | ✓ | Strix | `idor-vulnerability-testing` |
| **Broken Authentication** | ✓ | Strix + Burp | `broken-authentication-testing` |
| **File Upload Vulnerabilities** | ✓ | SkillSpector + Strix | `file-uploads` |
| **Path Traversal** | ✓ | SkillSpector + Strix | `file-path-traversal-testing` |
| **Insecure Deserialization** | ✓ | SkillSpector AST | `metasploit-framework` |
| **XXE** | ✓ | Strix | `web-vuln-playbooks` |
| **Security Misconfiguration** | ✓ | Strix + SkillSpector | `vulnerability-scanner` |
| **JWT / OAuth Weaknesses** | ✓ | Strix | `jwt-oauth-graphql-testing` |
| **GraphQL Introspection/Batching** | ✓ | Strix | `api-security-testing` |
| **API Fuzzing** | ✓ | Strix | `api-fuzzing-for-bug-bounty` |
| **Port Scanning / Enumeration** | ✓ | Nmap + Strix | `pentest-commands` |
| **SSH Security** | ✓ | Nmap + Strix | `ssh-penetration-testing` |
| **SMTP Security** | ✓ | Nmap + Strix | `smtp-penetration-testing` |
| **Active Directory** | ✓ | Strix | `active-directory-attacks` |
| **DNS Zone Transfer** | ✓ | Nmap + Strix | `pentest-commands` |
| **AWS IAM / S3 / EC2** | ✓ | Strix | `aws-penetration-testing` |
| **Azure AD / RBAC** | ✓ | Strix | `cloud-penetration-testing` |
| **GCP IAM / GKE** | ✓ | Strix | `google-cloud-waf-security` |
| **Kubernetes RBAC** | ✓ | Strix | `cloud-penetration-testing` |
| **Indirect Prompt Injection** | ✓ | ScanAgenticRisk + Strix | `llm-security-testing` |
| **MCP Tool Poisoning** | ✓ | SkillSpector TP1-TP4 | — |
| **Tool Shadowing** | ✓ | SkillSpector + ScanAgenticRisk | — |
| **Excessive Agency** | ✓ | SkillSpector EA1-EA5 | `privilege-escalation-methods` |
| **Memory Poisoning** | ✓ | SkillSpector MP1-MP3 | — |
| **RAG / Vector-Store Risks** | ✓ | ScanAgenticRisk | — |
| **Multi-Agent / A2A** | ✓ | ScanAgenticRisk + Strix | — |
| **Supply Chain / Slopsquatting** | ✓ | SkillSpector + Strix | `supply-chain-guard` |
| **Linux Privilege Escalation** | ✓ | Strix + Metasploit | `linux-privilege-escalation` |
| **Windows Privilege Escalation** | ✓ | Strix + Metasploit | `windows-privilege-escalation` |
| **Lateral Movement** | ✓ | Metasploit + Strix | `red-team-tactics` |
| **Data Exfiltration** | ✓ | Strix | `red-team-tools-and-methodology` |

---

## 7. Local Deployment Architecture

### Fully-Local Stack (BYO LLM Key)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          WRAITH Orchestrator                                   │
│                    (Agent Runtime / WRAITH CLI)                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────┬──────────────────────┬───────────────��─────────┐    │
│  │     TRACK A         │     TRACK B          │     TRACK C             │    │
│  │  Web & API          │  Network & Cloud     │  SAST & Agentic         │    │
│  │                     │                      │                         │    │
│  │ ┌───────────────┐   │ ┌────────────────┐   │ ┌───────────────────┐  │    │
│  │ │ Strix (web/   │   │ │ Nmap / Strix   │   │ │ SkillSpector      │  │    │
│  │ │ API scanner)  │   │ │ (network/cloud)│   │ │ (AST / YARA /     │  │    │
│  │ │ Burp Suite    │   │ │ Metasploit     │   │ │  agent patterns)  │  │    │
│  │ │ SQLMap        │   │ │ Shodan         │   │ │ Strix (SAST mode) │  │    │
│  │ └───────────────┘   │ └────────────────┘   │ │ Ponytail          │  │    │
│  │                     │                      │ └───────────────────┘  │    │
│  │  Web vuln skills    │  AD / cloud /        │  SAST / agentic /      │    │
│  │  API security skills│  network skills      │  supply-chain skills   │    │
│  └──────────┬──────────┘ └─────────┬──────────┘ └───────────┬──────────┘    │
│             │                      │                        │               │
│             ▼                      ▼                        ▼               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                 Cross-Cutting Coordination Layer                     │    │
│  │  Orchestrator aggregates findings → routes to Exploit / Post-Exploit│    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌──────────────┐  ┌──────────────────────┐  ┌──────────────────────────┐   │
│  │  Exploitation │  │  Post-Exploit &      │  │  Governance              │   │
│  │  Metasploit   │  │  Lateral Movement    │  │  JSON/SARIF/MD/HTML/PDF  │   │
│  │  SQLMap/Burp  │  │  Privesc + Pivoting  │  │  Agent BOM + Drift       │   │
│  └──────┬───────┘  └──────────┬───────────┘  └────────────┬─────────────┘   │
│         │                     │                           │                  │
│         ▼                     ▼                           ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Outputs & Integrations                           │    │
│  │  ThemisIQ (GRC) ←─ SARIF / JSON  │  Obsidian Vault ←─ Markdown     │    │
│  └─────────────────────────────────────────────────────���───────────────┘    │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Prerequisites (Minimal)

| Requirement | Purpose | Notes |
|-------------|---------|-------|
| Python 3.12+ | Engine runtime | Primary language for SAST + Strix |
| uv | Dependency management | Faster than pip |
| Node.js 20+ | Ponytail plugin | Only if using code-review mode |
| LLM API key | Optional enrichment | OpenRouter/OpenAI for LLM-augmented analysis |
| Docker | Strix dynamic mode | Optional — SAST works without it |
| Metasploit | Exploitation | Optional — only for Layer 8 |
| Nmap | Network scanning | Optional — only for Layer 4 |
| Burp Suite | Web exploitation | Optional — only for Layer 2/8 |

### Network Isolation

- **Default:** All outbound blocked
- **Optional enrichment:** OSV.dev lookups (disabled by default)
- **Cloud mode:** Strix Cloud (opt-in, for team dashboards)
- **Target scanning:** Outbound to target only (no telemetry)

---

## 8. Phase Roadmap

WRAITH phases are organized by **parallel track maturity**, not sequential completion. The three analysis tracks (Web/API, Network/Cloud, SAST/Agentic) can be developed and deployed independently. Phase 0 (Foundation) is a prerequisite for all tracks. Phases 1-3 build the three tracks in parallel. Phases 4-7 add cross-cutting capabilities that depend on track output.

```
Phase 0 (Foundation) ─────────────────────────────────────────────────
    │
    ├── Phase 1 (Web/API Track) ── Phase 4 (Exploitation Engine)
    ├── Phase 2 (Network/Cloud Track) ──┘
    ├── Phase 3 (SAST/Agentic Track) ── Phase 5 (Post-Exploit)
    │
    └── Phase 6 (Governance) ── Phase 7 (Dynamic Eval) ── Phase 8 (Full Orchestration)
```

### Phase 0 — Foundation (Prerequisite: None)
- WRAITH rule vocabulary and schemas
- Severity and capability models
- Fixture corpus (positive/negative/ambiguous/evasion/malicious-target)
- WRAITH CLI skeleton
- **Dependencies:** WRAITH spec → SkillSpector contracts

### Phase 1 — Web/API Track (Track A)
- **Parallel with:** Phase 2, Phase 3
- OWASP Top 10 detection engine
- SQLi, XSS, SSRF, IDOR, CSRF probe templates
- Form fuzzing and parameter discovery
- CMS vulnerability scanning
- REST/GraphQL API security testing
- JWT/OAuth token testing
- API fuzzing engine
- **Dependencies:** Strix web_vulnerability_assessment, Burp Suite, SQLMap
- **Output feeds:** Phase 4 (Exploitation Engine)

### Phase 2 — Network/Cloud Track (Track B)
- **Parallel with:** Phase 1, Phase 3
- Port scanning automation
- Service enumeration with NSE
- AD assessment workflows
- Cloud infrastructure scanning (AWS/Azure/GCP/K8s)
- DNS enumeration, subdomain discovery
- Shodan integration
- Technology profiling
- **Dependencies:** Nmap, Strix, Metasploit auxiliary, Shodan CLI, cloud-specific tools
- **Output feeds:** Phase 4 (Exploitation Engine)

### Phase 3 — SAST/Agentic Track (Track C)
- **Parallel with:** Phase 1, Phase 2
- SkillSpector integration (18 pattern categories: static analysis, MCP tool poisoning, supply chain, behavioral AST, YARA)
- MCP tool poisoning detection (TP1-TP4)
- Prompt injection detection (P1-P4, P9)
- Excessive agency analysis (EA1-EA5)
- Supply chain / slopsquatting detection
- Agent BOM generation
- Code review engine (Ponytail integration)
- **Dependencies:** SkillSpector, ScanAgenticRisk spec, Ponytail
- **Output feeds:** Phase 5 (Post-Exploit & Lateral Movement)

### Phase 4 — Exploitation Engine (Cross-Cutting)
- **Depends on:** Phase 1 (Web/API findings) + Phase 2 (Network/Cloud findings)
- Metasploit integration
- SQLMap automation
- Custom exploit runner
- Burp Suite exploitation workflows
- **Dependencies:** Metasploit Framework, SQLMap, Burp Suite

### Phase 5 — Post-Exploitation & Lateral Movement (Cross-Cutting)
- **Depends on:** Phase 3 (SAST/Agentic findings) + Phase 4 (Exploitation access)
- Privilege escalation workflows
- Lateral movement automation
- Persistence mechanism detection
- **Dependencies:** Metasploit, Strix

### Phase 6 — Governance & Continuous Monitoring
- **Depends on:** All tracks (1-3)
- Baselines and exception management
- Risk acceptance with expiry
- Remediation SLA tracking
- ThemisIQ integration
- Composition drift monitoring
- **Dependencies:** Phase 1-3 findings → governance layer

### Phase 7 — Controlled Dynamic Evaluation
- **Depends on:** Phase 0-6 static foundation
- Strix integration (autonomous pentesting against code repos)
- CubeSandbox integration (hardware-isolated behavioral testing)
- Synthetic secrets and credentials
- Mock MCP servers for tool-behavior testing
- Multi-run attack success rate measurement
- Control bypass rate tracking
- **Dependencies:** Phase 1-6 static foundation → dynamic evaluation

### Phase 8 — Full Orchestration & Demultiplexing
- **Depends on:** All phases
- Unified task router (Agent Runtime option A) final integration
- Parallel target dispatch across all 3 tracks
- Dependency-aware scheduling (exploit waits for track findings)
- Feedback loop wiring (post-exploit → recon re-scan)
- Cross-track correlation and reporting

---

## 9. Attack Surface Mapping

### MITRE ATT&CK Mapping (Enterprise)

| MITRE ATT&CK ID | Technique | WRAITH Layer |
|-----------------|-----------|-------------|
| TA0001 — Initial Access | Exploit Public-Facing Application | Layer 2 (Web Scanning) |
| TA0002 — Execution | Command and Scripting Interpreter | Layer 8 (Exploitation) |
| TA0003 — Persistence | Account Manipulation, Web Shell | Layer 9 (Post-Exploit) |
| TA0004 — Privilege Escalation | Exploitation for Privilege Escalation | Layer 9 (Post-Exploit) |
| TA0005 — Defense Evasion | Obfuscated Files or Information | Layer 8 (Exploitation) |
| TA0006 — Credential Access | OS Credential Dumping, Brute Force | Layer 8-9 (Exploit + Post-Exploit) |
| TA0007 — Discovery | Network Service Discovery, System Info Discovery | Layer 0 (Recon), Layer 4 (Network) |
| TA0008 — Lateral Movement | Remote Services, Lateral Tool Transfer | Layer 9 (Post-Exploit) |
| TA0009 — Collection | Data from Information Repositories | Layer 9 (Post-Exploit) |
| TA0010 — Exfiltration | Exfiltration Over C2 Channel | Layer 9 (Post-Exploit) |
| TA0011 — Command & Control | Ingress Tool Transfer | Layer 8 (Exploitation) |

### MITRE ATLAS Mapping (Agentic)

**Note:** Entries marked with * are likely mappings based on analyzer capability but not explicitly stated in the SkillSpector codebase. Only AML.T0080 and AML.T0051 are confirmed in the source.

| MITRE ATLAS ID | Technique | WRAITH Detection | Status |
|---------------|-----------|-----------------|--------|
| AML.T0051 | LLM Prompt Injection | Layer 7 (SkillSpector P1-P4, P9; Strix) | Confirmed in source |
| AML.T0080 | AI Agent Context Poisoning | Layer 7 (SkillSpector TP1-TP4, MP1-MP3) | Confirmed in source |
| AML.T0020 | Data Poisoning | Layer 7 (SkillSpector SC1-SC4, supply chain) | Likely* |
| AML.T0058 | Excessive Agency | Layer 7 (SkillSpector EA1-EA5) | Likely* |
| AML.T0040 | Privilege Escalation | Layer 7 (SkillSpector PE1-PE5) | Likely* |
| AML.T0043 | Data Exfiltration | Layer 7 (SkillSpector E1-E5) | Likely* |

### OWASP Top 10 for Web Applications 2021

| ID | Vulnerability | WRAITH Coverage |
|----|--------------|-----------------|
| A01:2021 | Broken Access Control | Layer 2 (IDOR, privilege escalation) |
| A02:2021 | Cryptographic Failures | Layer 2 (JWT, TLS testing) |
| A03:2021 | Injection | Layer 2 (SQLi, XSS, command injection) |
| A04:2021 | Insecure Design | Layer 2 (business logic, rate limiting) |
| A05:2021 | Security Misconfiguration | Layer 2 (default creds, debug endpoints) |
| A06:2021 | Vulnerable Components | Layer 6 (dependency scanning) |
| A07:2021 | ID & Auth Failures | Layer 2-3 (auth, JWT, OAuth) |
| A08:2021 | Software Data Integrity | Layer 6 (supply chain) |
| A09:2021 | Security Logging & Monitoring | Layer 11 (governance) |
| A10:2021 | SSRF | Layer 2 (SSRF detection) |

### OWASP API Top 10 2023

| ID | Vulnerability | WRAITH Coverage |
|----|--------------|-----------------|
| API1:2023 | Broken Object Level Auth | Layer 3 (BOLA testing) |
| API2:2023 | Broken Authentication | Layer 3 (JWT, OAuth) |
| API3:2023 | Broken Object Property Level Auth | Layer 3 (mass assignment) |
| API4:2023 | Unrestricted Resource Consumption | Layer 3 (rate limiting) |
| API5:2023 | Broken Function Level Auth | Layer 3 (privilege escalation) |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Layer 3 (business logic) |
| API7:2023 | Server-Side Request Forgery | Layer 3 (SSRF) |
| API8:2023 | Security Misconfiguration | Layer 3 (CORS, headers) |
| API9:2023 | Improper Inventory Management | Layer 3 (endpoint discovery) |
| API10:2023 | Unsafe Consumption of APIs | Layer 3 (supply chain) |

### OWASP Top 10 for Agentic Applications 2026

| ID | Vulnerability | WRAITH Coverage |
|----|--------------|-----------------|
| AGENTIC-LLM01-2026 | Agent Goal Hijack | Layer 7 (Strix LLM injection) |
| AGENTIC-LLM02-2026 | Tool Misuse | Layer 7 (SkillSpector TM1-TM4) |
| AGENTIC-LLM03-2026 | Identity & Privilege Abuse | Layer 7 (EA1-EA5, PE1-PE5) |
| AGENTIC-LLM04-2026 | Agentic Supply Chain | Layer 7 (SC1-SC4, Strix) |
| AGENTIC-LLM05-2026 | Unexpected Code Execution | Layer 7 (AST1-AST10) |
| AGENTIC-LLM06-2026 | Sensitive Info Disclosure | Layer 7 (E1-E5, secret redaction) |
| AGENTIC-LLM07-2026 | Unsafe Delegation | Layer 7 (ScanAgenticRisk 8.17) |
| AGENTIC-LLM08-2026 | Memory & Data Poisoning | Layer 7 (MP1-MP3) |
| AGENTIC-LLM09-2026 | Lateral Movement | Layer 7 (Strix + CubeSandbox) |
| AGENTIC-LLM10-2026 | Denial of Service | Layer 7 (CubeSandbox resource limits) |

---

## 10. References & Repositories

### Primary Repos
- **[NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector)** — Agent skill security scanner. 18 pattern categories incl. MCP tool poisoning, behavioral AST, YARA, supply chain. The core SAST engine.
- **[usestrix/strix](https://github.com/usestrix/strix)** — Autonomous AI pentesting agent. Multi-agent orchestration with web/API/network scanning.
- **[TencentCloud/CubeSandbox](https://github.com/TencentCloud/CubeSandbox)** — KVM/RustVMM sandbox. <60ms startup, hardware isolation, E2B-compatible.
- **[DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail)** — Lazy senior dev AI agent plugin. ~54% less code, 100% safe.
- **[cjpais/Handy](https://github.com/cjpais/Handy)** — Desktop speech-to-text app (non-security — voice attestation reference).

### Self-Developed
- **WRAITH CLI** — Unified interface wrapping all engines (planned, Phase 0)
- **Agent Runtime** (`./agent-runtime/`) — Task routing and process isolation prototype
- **ScanAgenticRisk v2.0** — Rule contract framework and governance model specification
- **ThemisIQ Integration Layer** — GRC platform consuming WRAITH output

### External Tools
- **[Metasploit Framework](https://github.com/rapid7/metasploit-framework)** — Exploitation framework
- **[SQLMap](https://github.com/sqlmapproject/sqlmap)** — Automated SQL injection tool
- **[Nmap](https://nmap.org/)** — Port scanning and service enumeration
- **[Burp Suite](https://portswigger.net/burp)** — Web application security testing
- **[Shodan](https://www.shodan.io/)** — Internet-wide device/service discovery

### Supporting Repositories
- **[smolagents](https://github.com/huggingface/smolagents)** — Hugging Face code-agent library
- **[CrewAI](https://github.com/crewAIInc/crewAI)** — Multi-agent orchestration framework
- **mattpocock/skills** — Agent skill collection (code review, debugging)
- **Hermes Agent** — Our host platform (Nous Research)

### Cloned Paths
```
./repos/
  ├── SkillSpector/        (depth 1, ~56K lines Python)
  ├── strix/               (depth 1, ~69K lines Python)
  ├── CubeSandbox/         (depth 1, ~39K Python + ~226K Rust + ~122K Go)
  ├── ponytail/            (depth 1, ~2K lines JS)
  └── Handy/               (depth 1, ~100K lines Rust+TS, non-security reference)
```

---

## 11. Known Gaps & Risks

These are deliberate design gaps that need concrete resolution before WRAITH can be operational. They are enumerated here so the architecture is honest about what it does not yet specify.

### 11.1 Authorization / Rules of Engagement (CRITICAL)

WRAITH automates exploitation (Layer 8), persistence, lateral movement, and exfiltration (Layer 9). There is currently **no mechanism** to enforce scope boundaries:

- No target scope allowlist or blocklist
- No target-authorization binding per session
- No engagement record or signed ROE document
- No hard human gate that the exploitation engine checks before firing

**What is needed before Layer 8-9 can be operational:**
- `Scope` object — a signed allowlist of target CIDRs, domains, URL patterns, and repo paths
- `Engagement` record — per-session authorization with human approval timestamp
- `human_gates` as a **mandatory precondition** (not just a routing trigger) for Layers 8-9
- Scope check on every engine invocation: reject if target is outside scope

### 11.2 Autonomy Blast Radius

Autonomous multi-agent exploitation (Strix) plus automated persistence means a wrong or over-broad scope can do real damage.

**Required controls:**
- **Mandatory human gate before Layer 8** — no autonomous exploitation without explicit approval
- **Kill-switch** — emergency stop for all running engines, flushable per engagement
- **Hard target-scope binding** on every engine invocation
- **Dry-run / read-only mode** for Layers 8-9 that reports what would be done without executing

### 11.3 LLM Data Boundary

"Fully local / no telemetry" is true of WRAITH's own code, but dynamic and LLM-augmented modes send target findings to an external LLM provider (OpenRouter / OpenAI API). This is an outbound data path for sensitive vulnerability data.

**Required:**
- Explicit data boundary: define what leaves the local machine (never raw targets or credentials)
- **Redaction layer** before LLM dispatch: strip secrets, PII, and internal hostnames
- Opt-in-only for LLM-augmented modes; pure static mode must be fully air-gapped
- Document which LLM providers see what, with a data-processing agreement reference

### 11.4 MVP Definition

Thirteen layers, five engines, five external tools, eight phases. There is no defined minimum viable product.

**Proposed MVP:** Layers 0-1 (Recon + Intake) + Layer 6 (SAST via SkillSpector) + Layer 7 (Agentic Security) + output to SARIF. This covers the unique value proposition (agentic security) without requiring external exploitation tools, cloud scanning, or network pentesting infrastructure. Phase 2+ can be added incrementally.

### 11.5 Results-Store Sensitivity

The output directory will contain secrets, exploit paths, session material, and vulnerability findings. It is as sensitive as the target itself.

**Required:**
- Encrypted results store (per-engagement key)
- Access control — only the owning user/process can read
- Automatic purge or archive on engagement close
- Audit log of all result reads/exports

### 11.6 License & Packaging

The engine mix has real distribution implications:

| Component | License | Restriction |
|-----------|---------|-------------|
| SkillSpector | Apache 2.0 | No restrictions |
| Strix | Apache 2.0 | No restrictions |
| CubeSandbox | Apache 2.0 | No restrictions |
| Ponytail | MIT | No restrictions |
| Handy | MIT | No restrictions |
| Metasploit Framework | BSD | No restrictions (Rex/Post/Msf core) |
| Nmap | Custom NPSA | Modified Apache — allows redistribution |
| SQLMap | GPLv2 | **Copyleft** — if bundled, WRAITH must be GPLv2 |
| Burp Suite | Commercial | **Cannot be bundled** — must be installed separately by user |

**Implication:** A packaged WRAITH distribution must either (a) exclude SQLMap and Burp and install them as external dependencies, or (b) license WRAITH under GPLv2 to accommodate SQLMap. Burp cannot be bundled under any license.

---

> **WRAITH is the benchmark.** Not because of any single tool, but because of the architecture — 3 parallel analysis tracks, 13 layers, 5 primary engines, 50+ offensive skills, Metasploit/SQLMap/Burp/Nmap/Shodan integration, all coordinated by a central Orchestrator that routes findings by dependency, not by position in a chain. Every target that arrives in your scope gets the right track at the right time: recon, parallel scan, dependency-aware probe, exploit, verify, and report. Continuously.

---

*WRAITH v2.1 — Full-Spectrum Offensive Security Architecture (Non-Linear, 3 Parallel Tracks) — Ali Moyo — September 2026*