# Detection Engineering: Azure AD Suspicious Sign-on

## 1. Purpose

This document describes the engineering considerations for detecting successful Microsoft Entra ID sign-ins that deviate from an account's established behavior.

The goal is not to alert on every new attribute. The goal is to identify combinations of novelty, authentication risk, account sensitivity, and post-authentication behavior that create a meaningful security signal.

## 2. Threat hypothesis

An adversary who obtains valid credentials, a session cookie, or an access token may authenticate successfully while bypassing controls that depend only on failed-login detection.

A compromised sign-in may differ from the user's baseline through one or more attributes:

- Source IP or autonomous system
- Country, region, or city
- Device ID or trust type
- Managed or compliant device state
- Operating system or browser
- Client application
- Target resource
- Authentication protocol
- MFA result or authentication method
- Conditional Access result
- Session or token characteristics

## 3. Data requirements

### Required telemetry

- User principal name and immutable user ID
- Event timestamp in UTC
- Source IP
- Sign-in result and error code
- Application and resource
- Client type
- Location
- Conditional Access status
- Risk level during sign-in
- Correlation or session identifier

### Recommended telemetry

- Device ID and display name
- Managed and compliant state
- Browser, operating system, and full user agent
- Authentication requirement and step details
- Applied Conditional Access policies
- Token and session identifiers
- Autonomous system number
- Microsoft 365 Unified Audit Log
- Identity risk events
- Account privilege and business role

## 4. Detection design

### Baseline dimensions

Maintain historical profiles for:

- User to source IP
- User to ASN
- User to country and region
- User to device ID
- User to browser and operating system
- User to application and resource
- User to client type
- User to typical access hours

### Suggested behavioral features

- First-seen IP for the user
- First-seen country for the user
- First-seen device and application combination
- Rare ASN for the organization
- Unmanaged device combined with a new location
- High or medium Entra sign-in risk
- Successful sign-in after repeated failures
- New browser plus new IP plus new country
- Access to an administrative resource not previously used
- Rapid geographic change between successful sign-ins
- New sign-in followed by mailbox-rule or OAuth changes

### Risk weighting model

Example weights for an environment-specific score:

| Signal | Example weight |
|---|---:|
| New country | 30 |
| New ASN | 15 |
| New device | 15 |
| New application | 10 |
| Unmanaged device | 10 |
| Medium Entra risk | 25 |
| High Entra risk | 50 |
| MFA not applied when expected | 40 |
| Suspicious mailbox change after sign-in | 40 |
| User denied the activity | 100 |

Do not copy these values directly into production. Calibrate them using historical detections and confirmed outcomes.

## 5. Source coverage query

```spl
(
    index IN ("[ENTRA_INDEX_1]", "[ENTRA_INDEX_2]", "[ENTRA_INDEX_3]")
    sourcetype="azure:monitor:aad"
    (
        category="SignInLogs"
        OR operationName="Sign-in activity"
    )
)
OR
(
    index IN ("[O365_INDEX_1]", "[O365_INDEX_2]")
    sourcetype="o365:graph:api"
    source="AuditLogs.SignIns"
)
OR
(
    index="[AZURE_INDEX]"
    sourcetype="azure:aad:signin"
)
| eval dataset=case(
    sourcetype="azure:monitor:aad", "Azure Monitor AAD",
    sourcetype="o365:graph:api", "O365 Graph Sign-ins",
    sourcetype="azure:aad:signin", "Azure AAD Sign-in",
    true(), "Other"
)
| stats
    count
    count(userPrincipalName) as events_with_UPN
    count('properties.userPrincipalName') as events_with_properties_UPN
    count(ipAddress) as events_with_IP
    count('properties.ipAddress') as events_with_properties_IP
    count(appDisplayName) as events_with_application
    count('properties.appDisplayName') as events_with_properties_application
    count(conditionalAccessStatus) as events_with_CA
    count('properties.conditionalAccessStatus') as events_with_properties_CA
    count(riskLevelDuringSignIn) as events_with_risk
    count('properties.riskLevelDuringSignIn') as events_with_properties_risk
    by dataset index sourcetype
| sort -count
```

## 6. Correlation opportunities

Correlate the alert event with:

- Microsoft 365 mailbox operations
- Inbox-rule creation or modification
- External forwarding configuration
- Mailbox permission changes
- `Send`, `SendAs`, or `SendOnBehalf`
- OAuth consent and service-principal activity
- MFA method changes
- Password resets
- Session revocation
- SharePoint and OneDrive access
- Administrative portal activity

## 7. False-positive patterns

Common legitimate causes include:

- Travel or relocation
- ISP geolocation changes
- Corporate VPN or secure web gateway egress
- Browser or operating-system update
- Device replacement or rebuild
- BYOD access permitted by policy
- New business application
- Mobile carrier IP rotation
- Microsoft service-to-service operations recorded against the mailbox

## 8. Tuning recommendations

- Suppress city-only novelty when the IP and country are unchanged.
- Reduce severity when the IP has been used repeatedly by the same user.
- Increase severity when several attributes are simultaneously new.
- Maintain allowlists for known corporate egress, but do not suppress other risk indicators.
- Enrich with account privilege and resource sensitivity.
- Separate interactive user activity from `UserType=5` or application-context service activity.
- Do not suppress solely because Entra risk is `none`.
- Review recurring benign detections for model or threshold adjustment.

## 9. Validation tests

Detection validation should include:

1. A known historical IP and normal application
2. A new city with the same IP and country
3. A new country and ASN
4. A new device with successful MFA
5. A new application accessing a sensitive resource
6. A risky sign-in followed by mailbox-rule creation
7. Service-to-service mailbox access with `UserType=5`
8. A sign-in where MFA was satisfied by a token claim

## 10. Detection quality metrics

Track:

- Alert volume
- Unique users
- True-positive rate
- Benign rate
- User-validation rate
- Median investigation time
- Percentage with complete MFA evidence
- Percentage with complete device evidence
- Recurrence by user, IP, application, and detection reason
- Number of detections upgraded after post-authentication correlation

## 11. Engineering backlog

- Normalize all sign-in sources to a shared field model.
- Add ASN and network-owner enrichment.
- Build a lookup of authorized application IDs.
- Add account privilege and asset criticality.
- Create session-aware correlation with Microsoft 365 activity.
- Add automated checks for forwarding, inbox rules, permissions, and OAuth consent.
- Record analyst verdicts for feedback and tuning.

