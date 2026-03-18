# Comprehensive Cybersecurity Knowledge

Learned from 734 skills across 36 subdomains in the [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) repository.

## Domain Coverage (734 Skills, 36 Subdomains)

### Cloud Security (60 skills)
- AWS/Azure/GCP security posture management, CloudTrail/Activity Log analysis
- IAM privilege escalation detection (boto3, Cloudsplaining)
- S3/Blob misconfiguration remediation, GuardDuty automation
- Zero trust in cloud (NIST SP 800-207, BeyondCorp, AWS Verified Access)
- Cloud incident response: identity-based containment, IMDS token theft investigation
- Cloud credential exposure detection (TruffleHog, git-secrets)
- Azure service principal abuse, lateral movement detection via KQL
- GCP Security Command Center, Workload Identity Federation
- Tools: Prowler, ScoutSuite, Steampipe, Cartography, Cado Response

### Threat Intelligence (50 skills)
- MITRE ATT&CK Navigator for APT group analysis and coverage mapping
- STIX/TAXII 2.1 for automated indicator exchange (OpenTAXII, MISP)
- IOC lifecycle management: validation, enrichment, confidence scoring, retirement
- Campaign attribution and correlation across organizations
- Certificate transparency monitoring for phishing detection
- Threat feed aggregation and deduplication (MISP, OTX, AlienVault)
- Diamond Model and Kill Chain analysis frameworks
- IP reputation analysis (Shodan API, AbuseIPDB, VirusTotal)
- Threat actor infrastructure tracking (passive DNS, Censys, WHOIS pivoting)
- Dark web monitoring for credential exposure

### Malware Analysis (39 skills)
- Static analysis: PE file structure, import table analysis, string extraction
- Dynamic analysis: sandbox execution, API monitoring, network traffic capture
- Ransomware encryption analysis: AES-256-CBC/CTR + RSA-2048/4096 hybrid schemes
- Key generation weakness identification (predictable seeds, ECB mode, key reuse)
- Android malware reverse engineering (APKTool, JADX)
- .NET malware decompilation (dnSpy)
- Rust malware reverse engineering (crate extraction, fat pointer handling)
- Cobalt Strike beacon config extraction
- Memory forensics for malware (Volatility framework)
- JavaScript/PowerShell deobfuscation techniques
- Ghidra disassembly and decompilation workflows
- YARA rule writing for malware classification
- Tools: Ghidra, IDA Pro, PyCryptodome, PEFile, NoMoreRansom.org

### Digital Forensics (37 skills)
- Disk imaging with dd/dcfldd, chain of custody procedures
- Memory forensics with Volatility (process analysis, network connections, registry)
- Browser forensics with Hindsight (Chrome history, cache, cookies)
- Linux log forensics (syslog, auth.log, systemd journal)
- Windows event log analysis (Security, Sysmon, PowerShell)
- MFT analysis for file recovery and timeline reconstruction
- Email header forensics for phishing investigation
- Network forensics with Wireshark/Zeek
- Mobile device forensics (Android/iOS)
- PhotoRec file carving for deleted file recovery
- Timeline analysis and event correlation
- Tools: Autopsy, Velociraptor, KAPE, Plaso, log2timeline

### Security Operations / SOC (36 skills)
- SIEM correlation: Splunk (SPL), Elastic (EQL/KQL), QRadar (AQL)
- Sigma rule creation: vendor-agnostic detection rules with pySigma backends
- Alert triage workflows and escalation matrices
- SOC metrics and KPIs (MTTD, MTTR, false positive rates)
- Log source onboarding and normalization
- Threat modeling with MITRE ATT&CK technique mapping
- Incident ticketing integration (ServiceNow, Jira, TheHive)
- IOC enrichment automation (VirusTotal, AbuseIPDB, Shodan)
- Lateral movement detection (Pass-the-Hash, PsExec, WMI, RDP)
- Beaconing pattern detection with statistical analysis
- Tools: Splunk ES, Elastic Security, IBM QRadar, Sigma, Uncoder.IO

### Threat Hunting (35+ skills)
- Living off the Land (LOLBins) detection: certutil, mshta, rundll32, regsvr32
- DNS tunneling and beaconing detection via Zeek conn.log analysis
- Credential dumping detection (LSASS access, SAM export, NTDS.dit theft)
- Kerberoasting and AS-REP roasting detection
- PowerShell-based attack hunting (encoded commands, download cradles)
- Threat hunting hypothesis development and testing
- Hunt library management and pivot interfaces
- MITRE ATT&CK coverage heatmap generation
- Network flow analysis for lateral movement patterns
- Tools: Velociraptor (VQL), osquery, Zeek, BloodHound

### Network Security (33 skills)
- Nmap advanced scanning: NSE scripts, timing controls, evasion techniques
- IDS/IPS configuration: Snort 3, Suricata with Emerging Threats rulesets
- Network segmentation with VLANs and firewall rules (pfSense)
- ARP poisoning detection (ARPWatch, Dynamic ARP Inspection)
- DNS security: DNSSEC, DNS-over-HTTPS, DNS-over-TLS
- Wireless security auditing and rogue AP detection
- Network traffic analysis with Zeek (SMB, Kerberos, DCE-RPC logs)
- DDoS mitigation strategies
- VPN configuration and zero trust network access
- Tools: Nmap, Zeek, Suricata, Snort, Wireshark, pfSense

### Identity & Access Management (33 skills)
- Active Directory security: ACL abuse analysis, BloodHound attack paths
- OAuth 2.0/OIDC flow security: PKCE, token validation, redirect URI checks
- MFA implementation (Duo, FIDO2, phishing-resistant authenticators)
- Zero standing privilege with CyberArk JIT access
- LDAP hardening: channel binding, LDAPS enforcement
- Conditional Access policies (Azure AD/Entra ID)
- SCIM provisioning and identity lifecycle management
- Privileged Access Management (PAM) workflows
- Service account security and rotation
- Tools: CyberArk, Okta, Azure AD, Google Workspace, BeyondTrust

### OT/ICS Security (28 skills)
- Purdue Model network segmentation (Levels 0-5, Level 3.5 DMZ)
- Industrial protocol monitoring: Modbus, EtherNet/IP, S7comm, DNP3, OPC UA
- SCADA attack detection and historian server protection
- ICS asset discovery with Claroty xDome passive monitoring
- IEC 62443 zone/conduit architecture
- Data diodes for unidirectional OT-to-IT data flow
- PLC firmware integrity verification
- IT/OT convergence security patterns
- Tools: Claroty, Dragos, Nozomi Networks, Grassmarlin

### API Security (28 skills)
- OWASP API Security Top 10 testing methodology
- JWT vulnerabilities: none algorithm, algorithm confusion, kid injection
- BOLA/IDOR detection and prevention
- API rate limiting: sliding window, token bucket, tiered plans (Redis-backed)
- GraphQL security: introspection disabling, query depth limiting
- OAuth2 implementation flaw testing (redirect URI manipulation, PKCE bypass)
- WebSocket security testing (CSWSH, message injection)
- API gateway security with AWS WAF
- Mass assignment and excessive data exposure detection
- Tools: Burp Suite, Postman, OWASP ZAP, jwt_tool

### Container Security (26 skills)
- Kubernetes penetration testing: API server, kubelet, etcd, RBAC exploitation
- CIS Benchmark assessment with kube-bench
- Container image scanning: Trivy, Grype, Anchore
- Runtime security with Falco (syscall monitoring, escape detection rules)
- Container escape detection: namespace breakout, cgroup abuse, Docker socket access
- Kubernetes manifest scanning with Kubesec
- Network policy enforcement and testing
- Secret management in Kubernetes (etcd encryption, external vaults)
- Container drift detection at runtime
- Tools: Falco, Trivy, kube-hunter, Kubescape, kube-bench, Grype

### Vulnerability Management (24 skills)
- Nessus/Tenable scanning and policy configuration
- Greenbone/OpenVAS deployment and scan management
- SSVC framework for vulnerability triage (CISA decision trees)
- Vulnerability remediation SLA enforcement and breach alerting
- CVSS scoring interpretation and risk prioritization
- Patch management workflows and compliance reporting
- Tools: Nessus, OpenVAS/Greenbone, Qualys, Rapid7

### Red Teaming (24 skills)
- Kerberoasting and AS-REP roasting attacks
- EvilGinx3 adversary-in-the-middle for MFA bypass
- Lateral movement with WMIExec/PsExec/RDP
- Cobalt Strike beacon deployment and C2 operations
- Active Directory attack paths (BloodHound)
- Initial access via phishing simulations (GoPhish)
- Tools: Impacket, CrackMapExec, BloodHound, Cobalt Strike, EvilGinx3

### Incident Response (24 skills)
- NIST SP 800-61r3 and SANS PICERL frameworks
- Cloud IR: identity containment, evidence preservation, cross-account investigation
- Ransomware recovery: DSRM, krbtgt double-reset, phased system restoration
- Active breach containment strategies (network isolation, credential revocation)
- Insider threat investigation with UEBA correlation
- Velociraptor deployment for scalable endpoint collection
- Post-incident hardening and lessons learned
- Tools: Velociraptor, TheHive, DFIR-IRIS, Cado Response

### Penetration Testing (23 skills)
- Web application testing: XSS, SQLi, SSRF, XXE, CORS misconfiguration
- IoT security assessment (firmware extraction, UART/JTAG, protocol analysis)
- Mobile API authentication testing
- Business logic vulnerability identification
- Host header injection and open redirect testing
- Tools: Burp Suite, Metasploit, sqlmap, Frida

### Web Application Security (41 skills)
- OWASP Top 10 testing methodologies
- SQL injection (blind, time-based, error-based)
- XSS (reflected, stored, DOM-based) with context-aware payloads
- SSRF exploitation and bypass techniques
- Broken access control and IDOR testing
- Prototype pollution in Node.js applications
- Race condition exploitation
- ModSecurity WAF with OWASP CRS configuration
- XML injection and XXE exploitation
- Email header injection testing
- Tools: Burp Suite, OWASP ZAP, Semgrep, nuclei

### Zero Trust Architecture (17 skills)
- NIST SP 800-207 implementation across AWS/Azure/GCP
- Identity-Aware Proxy deployment (Google IAP, AWS Verified Access)
- Micro-segmentation with security groups and network policies
- Continuous verification with Conditional Access and device trust
- Software-Defined Perimeter architecture
- ZTNA with Zscaler, Cloudflare Access, Palo Alto Prisma Access
- Zero trust DNS with NextDNS
- Tools: Zscaler ZPA, Cloudflare Access, Tailscale, Google BeyondCorp

### Endpoint Security (16 skills)
- EDR deployment and configuration (CrowdStrike Falcon, Microsoft Defender)
- Windows Defender advanced settings (ASR rules, controlled folder access)
- USB device control policies
- osquery for endpoint monitoring (SQL-based queries)
- Attack surface reduction and exploit protection
- Application whitelisting strategies

### DevSecOps (16 skills)
- CI/CD pipeline security scanning (SAST, SCA, container scanning)
- Secret detection in code repos (Gitleaks, TruffleHog)
- Trivy integration in CI/CD for container vulnerability scanning
- GitLab CI security pipeline configuration
- Infrastructure as Code scanning
- Dependency vulnerability management
- Tools: Semgrep, Trivy, Gitleaks, Snyk, SonarQube

### Phishing Defense (16 skills)
- DMARC/DKIM/SPF email authentication implementation
- BEC detection with AI/NLP behavioral analysis
- GoPhish phishing simulation campaigns
- QR code phishing (quishing) detection
- Proofpoint/Google Workspace email gateway configuration
- SOAR playbook for automated phishing response
- Anti-phishing training program development
- Certificate transparency monitoring for look-alike domains

### Cryptography (13 skills)
- TLS 1.3 configuration and hardening
- Zero-knowledge proof authentication (Schnorr protocol)
- Post-quantum cryptography readiness assessment
- Certificate management and PKI operations
- Encryption at rest and in transit best practices
- Key management and rotation strategies

### Mobile Security (12 skills)
- Android malware analysis with APKTool/JADX
- iOS reverse engineering with Frida dynamic instrumentation
- Mobile API authentication testing
- OWASP Mobile Top 10 assessment
- MDM integration and device posture checks

### Ransomware Defense (5 skills)
- Ransomware canary file deployment for early detection
- Encryption mechanism analysis for decryption feasibility
- Full recovery procedures (AD restore, krbtgt reset, phased reconnection)
- Kill switch and isolation strategies
- Backup verification and immutability enforcement

### Compliance & Governance (5 skills)
- Framework mapping: NIST CSF, ISO 27001, SOC 2, PCI DSS
- NIS2, DORA, CMMC, NERC CIP, IEC 62443 compliance
- Security metrics and board-level reporting
- Risk assessment methodologies

## Key Detection Engineering Patterns

### Sigma Rule Structure
```yaml
title: Detection Rule Title
id: UUID
status: stable
level: high
description: What this detects
logsource:
  category: process_creation|network_connection|process_access
  product: windows|linux
detection:
  selection:
    FieldName|modifier: value
  filter:
    FieldName: legitimate_value
  condition: selection and not filter
tags:
  - attack.tactic_name
  - attack.tXXXX.XXX
falsepositives:
  - Known legitimate uses
```

### MITRE ATT&CK Key Techniques
- T1003: OS Credential Dumping (LSASS, SAM, NTDS.dit)
- T1053: Scheduled Task/Job
- T1059: Command and Scripting Interpreter
- T1078: Valid Accounts
- T1110: Brute Force
- T1190: Exploit Public-Facing Application
- T1486: Data Encrypted for Impact (Ransomware)
- T1550: Use Alternate Authentication Material (PtH)
- T1611: Escape to Host (Container Escape)

## Key Tools Reference

| Category | Tools |
|----------|-------|
| SIEM | Splunk ES, Elastic Security, IBM QRadar, Microsoft Sentinel |
| Detection | Sigma, pySigma, Uncoder.IO, YARA |
| Forensics | Volatility, Autopsy, Velociraptor, KAPE, Plaso |
| Network | Zeek, Suricata, Snort, Wireshark, Nmap |
| Cloud | Prowler, ScoutSuite, Steampipe, Cartography |
| Container | Falco, Trivy, kube-bench, Kubescape, Grype |
| Malware | Ghidra, IDA Pro, YARA, PEFile, dnSpy |
| Pentest | Burp Suite, Metasploit, Impacket, CrackMapExec |
| Threat Intel | MISP, OpenTAXII, VirusTotal, Shodan, Censys |
| Identity | BloodHound, CyberArk, Okta, Azure AD |
| DevSecOps | Semgrep, Gitleaks, TruffleHog, Snyk |
| OT/ICS | Claroty, Dragos, Nozomi Networks |
| Email | Proofpoint, dmarcian, GoPhish |

## Applying to SecureNexus

This knowledge directly maps to SecureNexus features:
- **Detection Engine**: Sigma rule format, MITRE ATT&CK mapping, 45+ built-in rules
- **Threat Intelligence**: STIX/TAXII, IOC lifecycle, campaign correlation
- **Incident Response**: Cloud IR workflows, containment playbooks, war rooms
- **CSPM**: AWS/Azure/GCP scanning, drift detection, auto-remediation
- **OT/ICS Security**: Purdue Model, protocol parsers, IT/OT boundary monitoring
- **Identity Governance**: PAM, access reviews, blast radius analysis
- **Supply Chain**: SBOM ingestion, typosquatting detection, IaC scanning
- **Ransomware Defense**: Kill switch, canary files, recovery runbooks
- **Email Security**: BEC detection, DMARC/DKIM/SPF, header analysis
- **DNS Security**: DNSSEC validation, domain reputation, tunnel detection
- **API Security**: Rate limiting, JWT validation, BOLA detection
- **Container Security**: Falco rules, image scanning, K8s hardening
- **Deception Technology**: Canary tokens, honeypots, network decoys
- **Security Chaos Engineering**: Purple team automation, BAS dashboard
- **AI Detection Rules**: LLM-powered Sigma/YARA generation
- **Threat Hunting Workbench**: Query engine, pivot interface, hunt library
