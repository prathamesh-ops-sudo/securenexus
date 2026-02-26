# Dependency License Policy

This document defines the approved and denied open-source licenses for SecureNexus dependencies, along with the exception request process.

## Approved Licenses

The following licenses are pre-approved for use in production dependencies:

| License | SPDX Identifier | Notes |
|---------|-----------------|-------|
| MIT | MIT | Permissive, no restrictions |
| Apache 2.0 | Apache-2.0 | Permissive, patent grant |
| BSD 2-Clause | BSD-2-Clause | Permissive |
| BSD 3-Clause | BSD-3-Clause | Permissive |
| ISC | ISC | Permissive, MIT-equivalent |
| 0BSD | 0BSD | Public domain equivalent |
| CC0-1.0 | CC0-1.0 | Public domain dedication |
| Unlicense | Unlicense | Public domain equivalent |
| BlueOak-1.0.0 | BlueOak-1.0.0 | Permissive |
| Python-2.0 | Python-2.0 | Permissive |
| Zlib | Zlib | Permissive |

## Denied Licenses

The following licenses are **not permitted** in production dependencies without an approved exception:

| License | SPDX Identifier | Reason |
|---------|-----------------|--------|
| AGPL-3.0 | AGPL-3.0-only / AGPL-3.0-or-later | Copyleft extends to network use |
| AGPL-1.0 | AGPL-1.0-only | Copyleft extends to network use |
| GPL-2.0 | GPL-2.0-only / GPL-2.0-or-later | Strong copyleft |
| GPL-3.0 | GPL-3.0-only / GPL-3.0-or-later | Strong copyleft |
| SSPL | SSPL-1.0 | Server-side copyleft |
| BSL | BSL-1.0 | Time-delayed open source |
| EUPL | EUPL-1.1 / EUPL-1.2 | Strong copyleft |
| CPAL | CPAL-1.0 | Attribution + copyleft |
| OSL | OSL-3.0 | Network copyleft |

## Conditionally Approved Licenses

These licenses require team lead approval before use:

| License | SPDX Identifier | Condition |
|---------|-----------------|-----------|
| LGPL-2.1 | LGPL-2.1-only | Only if dynamically linked |
| LGPL-3.0 | LGPL-3.0-only | Only if dynamically linked |
| MPL-2.0 | MPL-2.0 | File-level copyleft; acceptable if isolated |
| CC-BY-4.0 | CC-BY-4.0 | Acceptable for documentation/data, not code |
| CC-BY-SA-4.0 | CC-BY-SA-4.0 | Requires attribution and share-alike |

## CI Enforcement

The CI pipeline runs `license-checker` on every pull request and reports any denied licenses as warnings. The license report is uploaded as a build artifact for review.

Current thresholds:
- **Denied licenses**: Reported as warnings (will be upgraded to errors in a future release)
- **Unknown licenses**: Flagged for manual review

## Exception Request Process

To request an exception for a denied or conditionally-approved license:

1. **Open a GitHub Issue** with the title `License Exception: {package-name}`
2. **Include the following information**:
   - Package name and version
   - License identifier (SPDX)
   - Business justification for using this package
   - Alternative packages considered and why they were rejected
   - How the package is used (runtime dependency, build tool, dev-only)
   - Risk assessment: does the license affect SecureNexus's licensing?
3. **Review**: The security team reviews the request within 5 business days
4. **Approval**: If approved, the package is added to the exceptions list and documented below

## Current Exceptions

No exceptions have been granted yet.

## SBOM Generation

A CycloneDX SBOM (Software Bill of Materials) is generated on every CI run and uploaded as a build artifact. The SBOM includes all production dependencies with their versions and licenses.

SBOM format: CycloneDX 1.5 (JSON)
Retention: 90 days as a CI artifact
