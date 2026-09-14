# Playbook: Vectra Azure AD Suspicious Sign-on

## 1. Objective

Determine whether an unusual successful Microsoft Entra ID sign-in represents expected activity, activity requiring validation, suspicious activity, or confirmed account compromise.

## 2. Inputs

- `[USER]`: Full user principal name
- `[USERID]`: Microsoft Entra object ID
- `[ALERT_TIME]`: Alert timestamp and timezone
- `[ALERT_IP]`: Source IP reported by the detection
- `[APPLICATION]`: Application or resource
- `[DETECTION_ID]`: Detection identifier

Text variables must be enclosed in double quotes after replacement.

## 3. Time windows

- Immediate context: 24 hours before to 24 hours after the alert
- Baseline: previous 30 days
- Extended baseline: 90 days when evidence is sparse

## 4. Phase 1: Identify the sign-in source

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

### Analyst actions

- Select the source with the best identity, IP, application, Conditional Access, risk, device, and correlation coverage.
- Record missing fields.
- Identify duplicate ingestion before counting events.

## 5. Phase 2: Build the user sign-in timeline

```spl
index="[AZURE_INDEX]"
sourcetype="azure:aad:signin"
(
    user="[USER]"
    OR userPrincipalName="[USER]"
    OR user_id="[USERID]"
)
| table
    _time
    user
    src_ip
    location.city
    app
    clientAppUsed
    deviceDetail.browser
    deviceDetail.deviceId
    deviceDetail.displayName
    deviceDetail.isManaged
    deviceDetail.isCompliant
    conditionalAccessStatus
    riskLevelDuringSignIn
    action
    status.errorCode
    status.failureReason
    correlationId
| sort 0 _time
```

### Validate

- Was the sign-in successful?
- Was `[ALERT_IP]` previously observed?
- Is the country or region compatible with the user profile?
- Did only the city label change while IP and country remained constant?
- Is the application expected?
- Is the browser or operating-system change compatible with a normal update?
- Is the device new, unmanaged, noncompliant, or unidentified?
- Were there authentication failures immediately before success?
- Did Entra ID assign medium or high risk?

## 6. Phase 3: Validate MFA and Conditional Access

Review the complete sign-in event for:

- `status.additionalDetails`
- `conditionalAccessStatus`
- `appliedConditionalAccessPolicies`
- `authenticationRequirement`
- `authenticationDetails`

### Expected evidence

- Applicable MFA policy result is `success`
- Conditional Access result is `success`
- No unexpected exclusion or legacy authentication

### Token-claim interpretation

`MFA requirement satisfied by claim in the token` is valid evidence that an existing MFA claim satisfied the requirement. Confirm that the session, token, location, and application remain compatible with the user baseline.

### Escalate when

- MFA was not applied when expected
- A policy was unexpectedly excluded
- Repeated MFA denials were followed by an approval
- The session is risky or token theft is suspected
- Legacy authentication was used

## 7. Phase 4: Review Microsoft 365 activity

```spl
index="[O365_INDEX]"
sourcetype="o365:management:activity"
(
    UserId="[USER]"
    OR MailboxOwnerUPN="[USER]"
)
Operation=*
| eval source_ip=coalesce(ClientIPAddress,ClientIP,ActorIpAddress)
| stats
    count
    min(_time) as first_seen
    max(_time) as last_seen
    values(ResultStatus) as results
    values(source_ip) as source_ips
    values(ClientAppId) as client_app_ids
    values(AppId) as app_ids
    values(UserType) as user_types
    values(ExternalAccess) as external_access
    by Operation
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

### High-priority operations

- `New-InboxRule`
- `Set-InboxRule`
- `UpdateInboxRules`
- `Remove-InboxRule`
- `Set-Mailbox`
- `Set-MailboxAutoReplyConfiguration`
- `Add-MailboxPermission`
- `Add-RecipientPermission`
- `Send`
- `SendAs`
- `SendOnBehalf`
- `SoftDelete`
- `HardDelete`
- `MoveToDeletedItems`
- `MailItemsAccessed`
- `AttachmentAccess`
- `Update`
- `UserLoggedIn`

## 8. Distinguish interactive and automated activity

### Interactive indicators

- `UserType=0`
- Source IP matches the sign-in
- Application ID matches the client
- `TokenObjectId` matches the user
- `AADSessionId` or `SessionId` correlates

### Service indicators

- `UserType=5`
- `ExternalAccess=false`
- Microsoft or internal service IP
- `RESTSystem` or application context
- Token belongs to an application
- Session differs from the interactive session

Do not attribute service activity to the user without correlation.

## 9. Persistence and impact checks

Investigate explicitly for:

- Inbox rules that hide, move, or delete messages
- External forwarding
- Mailbox permission changes
- Delegated or unauthorized sending
- Mass deletion
- OAuth consent or new service principals
- MFA method changes
- Password or token changes
- SharePoint and OneDrive access
- Administrative portal activity

## 10. Classification criteria

### Benign / Expected User Activity

- Historical IP or expected network
- Expected region and application
- Successful MFA and Conditional Access
- No Entra risk or other high-risk evidence
- Session activity is consistent with normal usage
- No persistence, abuse, or impact identified

### Benign with user validation

- New but plausible IP, device, location, or application
- MFA and Conditional Access succeeded
- No malicious follow-on activity
- Business context is required to close

### Suspicious

- New IP, country, device, and application combination
- Hosting, anonymizing, or unusual infrastructure
- Missing or unexpected MFA
- Medium or high risk
- Abnormal mailbox, OAuth, or administrative activity

### Confirmed compromise

- User denies the activity
- Malicious forwarding or inbox rules
- Unauthorized OAuth consent
- MFA-method manipulation
- Fraudulent sending
- Token theft
- Confirmed unauthorized data access or exfiltration

## 11. Response actions

### Benign

1. Document the historical comparison.
2. Record MFA, Conditional Access, and risk results.
3. Summarize post-authentication activity.
4. Close as expected user activity.

### Validation required

1. Contact the user or manager through an approved channel.
2. Confirm travel, network, device, and application.
3. Require reauthentication if uncertainty remains.

### Suspicious or confirmed

1. Revoke sessions and refresh tokens.
2. Reset the password.
3. Review and correct MFA methods.
4. Disable the account when justified.
5. Remove malicious rules, forwarding, permissions, and OAuth consent.
6. Review all cloud workloads for impact.
7. Hunt the IP, app ID, token, and user agent across other users.
8. Escalate to incident response.

## 12. Final checklist

- [ ] User and object ID identified
- [ ] Alert event located
- [ ] IP compared with historical activity
- [ ] Country and city compared with expected profile
- [ ] Application and client reviewed
- [ ] Browser and device reviewed
- [ ] MFA validated
- [ ] Conditional Access validated
- [ ] Entra risk reviewed
- [ ] Microsoft 365 activity analyzed
- [ ] Interactive and automated activity separated
- [ ] Inbox rules and forwarding reviewed
- [ ] Mailbox permissions reviewed
- [ ] Sending and deletion reviewed
- [ ] OAuth activity reviewed
- [ ] User validation completed if required
- [ ] Classification justified with evidence
- [ ] Response actions documented

## 13. Closure template

```text
Detection: Azure AD Suspicious Sign-on
Detection ID: [DETECTION_ID]
User: [USER]
Alert time: [ALERT_TIME]
Alerted IP: [ALERT_IP]
Application: [APPLICATION]
Historical comparison: [SUMMARY]
MFA: [RESULT]
Conditional Access: [RESULT]
Entra risk: [RESULT]
Post-authentication activity: [SUMMARY]
Persistence or impact: [OBSERVED / NOT OBSERVED]
User validation: [CONFIRMED / DENIED / NOT REQUIRED / PENDING]
Classification: [VERDICT]
Confidence: [LOW / MEDIUM / HIGH]
Rationale: [EVIDENCE-BASED EXPLANATION]
```

## 14. Benign closure example

The unusual sign-in was investigated using Microsoft Entra ID sign-in logs and Microsoft 365 audit activity. The source network, region, application, browser, and operating system were compatible with the account's historical pattern. Conditional Access completed successfully and the applicable MFA requirement was satisfied. No elevated Entra sign-in risk was assigned.

Post-authentication activity was correlated with the sign-in context. No suspicious inbox rules, external forwarding, permission changes, unauthorized sending, abnormal deletion activity, unauthorized application access, or other persistence mechanisms were observed in the reviewed data. Additional service IPs were associated with automated cloud processing rather than separate interactive user sessions.

The detection is classified as benign expected user activity.
