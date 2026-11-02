# Indonesia & International Standards Compliance Mapping — Draft

**Caution:** This is engineering applicability mapping, not legal advice, a certification statement or assertion that the institution has completed required governance approvals. Formal obligations need institutional counsel/DPO and Pemda SPBE officials.

## Indonesian regulatory context
| Instrument | Relevant system activity / implementation evidence |
| --- | --- |
| UU No. 27/2022 Pelindungan Data Pribadi | Define data controller/processor, purpose/legal basis, privacy notice, access protection, data minimization, retention and breach response. Prefer aggregate-only clicks. |
| PP No. 71/2019 Penyelenggaraan Sistem dan Transaksi Elektronik | Reliability, information security and operation of electronic systems; verify PSE Public Sector expectations. |
| Perpres No. 95/2018 SPBE | Governance and interoperability for government digital service, institutional approval and accountability. |
| Peraturan BSSN No. 4/2021 | SPBE information security management guidelines; threat review, access management and incident response. |
| UU No. 25/2009 Pelayanan Publik | Accessible, reliable delivery of public information and complaints. |
| UU No. 1/2024 (Perubahan Kedua UU ITE) | Proper electronic information governance and responsible use. |
| Applicable .go.id / Pemda domain policies | Obtain written domain/path authorization, use official identity and published abuse contact, respect institutional change control. |

## International controls
| Standard | Relevant outcome in AW Shortlink |
| --- | --- |
| ISO/IEC 27001 | ISMS risk ownership, access control, incident management, security evidence |
| ISO/IEC 27002 | Secure configuration, roles, logging, vulnerability & supplier control |
| ISO/IEC 27005 | Threat risk assessment and mitigation monitoring |
| ISO/IEC 27017 | Cloud service configuration and shared-responsibility assessment (if cloud host) |
| ISO/IEC 27018 | PII protection in public cloud context |
| ISO/IEC 27701 | Privacy information management: retention, processing inventory and rights handling |
| ISO/IEC 27034 | Secure application lifecycle and verification |
| ISO/IEC 20000-1 | Service, incident, change and release management |
| ISO 22301 | Business continuity, recovery and restore testing |
| ISO/IEC 15408 | Security evaluation assurance when relevant to component procurement; not required certification for simple short links |
| ISO/IEC 25010 | Usability, reliability, performance, maintainability and security quality model |
| ISO/IEC 29100 | Privacy framework for data processing |
| OWASP ASVS + Top 10 | App controls against SSRF, open redirect, XSS, authorization failures |
| W3C WCAG 2.2 AA | Accessibility testing for public and admin interfaces |

## Minimum evidence for production
Institutional domain owner approval; privacy classification and lawful basis record; access/role mapping; STRIDE risk register; dependency/SBOM scan; secure release signoff; parent website regression; incident runbook; backup restore demonstration; security test results and accessibility validation. ISO alignment is descriptive unless certified by accredited body.

## Sources
- UU PDP: https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022
- PP 71/2019: https://peraturan.bpk.go.id/Details/122030/pp-no-71-tahun-2019
- Perpres 95/2018: https://peraturan.bpk.go.id/Details/96913/perpres-no-95-tahun-2018
- BSSN no. 4/2021: https://peraturan.bpk.go.id/Details/210198/peraturan-bssn-no-4-tahun-2021
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- ISO catalog: https://www.iso.org/standards.html


## Additional least-privilege access controls
User, role, permission, unit delegation and versioned ABAC administration become a mandatory P0 module, supported by PostgreSQL RLS with least-privilege SQL roles and testing. This maps to ISO/IEC 27001/27002/27005 access, role lifecycle, logging and security risk controls; ISO/IEC 27701 identity data management; and relevant SPBE control governance. Reference is not a certification claim. See identity-rbac-abac.md and postgresql-rls-design.md.
