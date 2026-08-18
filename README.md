# cisa-yara-rules

Community-maintained YARA rule collection extracted from official CISA
(Cybersecurity and Infrastructure Security Agency) Malware Analysis
Reports (MAR) and Analysis Reports (AR).

CISA publishes YARA detection rules embedded inside PDF/HTML incident
reports rather than as a standalone, git-trackable rule feed. This
repository collects, normalizes, and validates those rules into a
single machine-readable format so they can be integrated into existing
detection pipelines (SIEM, EDR, email security gateways, etc.).

## Why this repository exists

- CISA rules are high-confidence (each rule is tied to a real incident
  and reverse-engineering report) but low-volume and hard to consume
  programmatically.
- This project makes them git-clone-able like other popular YARA
  feeds (Neo23x0/signature-base, elastic/protections-artifacts,
  Yara-Rules/rules).

## Structure

- rules/          YARA rules, one file per source report
- tests/corpus/   test files used for false positive / true positive validation
- tools/          validation and testing scripts
- docs/           source tracking, methodology, test results

## Source tracking

Every rule includes source_report and source_url metadata fields
pointing back to the original CISA publication. See docs/SOURCES.md
for the full index.

## Validation

Run ./tools/validate.sh to compile-check all rules and verify
required metadata fields are present.

## License

Rules are sourced from CISA (a U.S. federal government agency) and
published under TLP:CLEAR, meaning they may be shared without
restriction. This repository's own scripts and documentation are
released under the MIT License.

## Disclaimer

Rules are provided as-is. False positive testing results are tracked
in docs/ - review before deploying to production detection pipelines.
