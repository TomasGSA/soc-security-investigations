# Azure AD Suspicious Sign-on Investigation

## Overview

This repository documents a repeatable investigation workflow for behavioral detections involving a successful Microsoft Entra ID sign-in with unusual attributes, such as a new location, source IP, browser, device, or application.

The workflow uses:

- Vectra AI detection context
- Splunk Search Processing Language (SPL)
- Microsoft Entra ID sign-in logs
- Microsoft 365 Unified Audit Log activity

All examples are sanitized. Replace bracketed variables before executing a query.

## Repository structure

- `README.md`: Repository overview and navigation.
- `Detection-engineering.md`: Detection logic, telemetry requirements, tuning, and validation strategy.
- `investigation.md`: Technical analysis methodology and evidence domains.
- `lessons_learned.md`: Key findings and reusable investigative lessons.
- `playbook.md`: Operational SOC playbook with SPL queries and decision criteria.

## Detection objective

Determine whether an unusual successful sign-in represents:

1. Expected user activity
2. Legitimate activity requiring user validation
3. Suspicious activity
4. Confirmed account compromise

## Required data

| Parameter | Description |
|---|---|
| `[USER]` | Full user principal name |
| `[USERID]` | Microsoft Entra object ID |
| `[ALERT_TIME]` | Alert timestamp and timezone |
| `[ALERT_IP]` | Source IP reported by the detection |
| `[APPLICATION]` | Application or resource accessed |
| `[DETECTION_ID]` | Detection identifier |

## Recommended time windows

- Alert context: 24 hours before to 24 hours after the detection
- Behavioral baseline: previous 30 days
- Extended baseline: 90 days when activity is sparse or the observed attribute appears genuinely new

## Investigation principles

- An anomaly is not automatically a compromise.
- A successful sign-in must be correlated with its authentication controls and subsequent activity.
- An unmanaged or unidentified device is a risk factor, not proof of malicious activity.
- A valid MFA claim in a token does not indicate an MFA bypass.
- Microsoft service activity must be separated from interactive user activity.
- Absence of evidence in a limited export is not evidence of absence.

## High-level workflow

1. Identify the best sign-in dataset.
2. Locate the alert event.
3. Build a historical sign-in baseline.
4. Compare the source IP, location, application, browser, and device.
5. Validate MFA and Conditional Access.
6. Correlate the sign-in with Microsoft 365 activity.
7. Search for mailbox persistence, unauthorized sending, deletion, or OAuth abuse.
8. Classify the activity and document the rationale.

## Classification

| Classification | Summary |
|---|---|
| Benign / Expected | Historical attributes, successful MFA and Conditional Access, and no harmful follow-on activity |
| Benign with validation | New but plausible context with no malicious activity; confirmation is required |
| Suspicious | Multiple unusual attributes, weak authentication evidence, or abnormal post-authentication behavior |
| Confirmed compromise | User denial or direct evidence of unauthorized access, persistence, abuse, or exfiltration |

## Security and privacy

Do not commit real usernames, email addresses, public IP addresses, tenant IDs, correlation IDs, token identifiers, mailbox subjects, policy names, or company-specific index names to a public repository. Use placeholders or synthetic examples.

## MITRE ATT&CK mapping

- T1078: Valid Accounts

## Disclaimer

The SPL examples reflect one telemetry model. Field names, indexes, sourcetypes, retention, and normalization may differ between environments. Validate every query before operational use.

