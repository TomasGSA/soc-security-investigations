# Investigation: Azure AD Suspicious Sign-on

## 1. Objective

Determine whether an unusual successful sign-in is compatible with the user's established behavior and organizational controls, or whether it indicates misuse of valid credentials or tokens.

## 2. Behavior description

The investigated pattern is a successful cloud sign-in with attributes identified as uncommon for the account. Potentially unusual attributes include location, IP, device, browser, application, client type, and authentication context.

The investigation must establish both:

- Whether the sign-in itself is suspicious
- Whether the authenticated session performed suspicious follow-on activity

## 3. Hypotheses

### H1: Legitimate behavioral change

The user traveled, changed networks, replaced a device, updated software, or accessed a new approved application.

### H2: Geolocation or telemetry variation

The apparent location or device novelty is caused by ISP geolocation, missing device claims, proxying, or inconsistent source normalization.

### H3: Valid-account compromise

An unauthorized actor used stolen credentials, session material, or an access token.

### H4: Service activity misattributed to the user

Microsoft or an authorized application accessed the mailbox under application or service context and appeared alongside interactive activity.

## 4. Minimum input data

- User principal name
- User object ID
- Alert time and timezone
- Alerted IP
- Application or resource
- Detection identifier
- Triggering attribute, when available

## 5. Evidence domains

### Identity context

- Account enabled state
- Member or guest status
- User role and privilege
- Expected country or working region
- Recent password, token, or session reset

### Sign-in context

- Event result
- Source IP and ASN
- Country, region, and city
- Application and resource
- Browser and operating system
- Device ID and trust state
- Interactive status
- Correlation and session identifiers

### Authentication controls

- Authentication requirement
- MFA method and step result
- Conditional Access policy result
- Risk level during sign-in
- Legacy authentication status

### Post-authentication activity

- Mail access
- Attachment access
- Sending activity
- Inbox rules and forwarding
- Mailbox permissions
- Deletion activity
- OAuth consent
- SharePoint or OneDrive access
- Administrative actions

## 6. Interpretation guidance

### Source IP

A repeatedly observed IP is strong evidence of continuity, but it is not sufficient on its own. Confirm application, location, device, session, and post-authentication behavior.

### Location

A city change with the same IP and country may be a geolocation-database variation. Country changes, impossible travel, new ASN, or anonymizing infrastructure carry more weight.

### Device state

`isManaged=false`, `isCompliant=false`, or an empty device ID may reflect BYOD or missing claims. Treat these as contextual risk, not proof of compromise.

### MFA token claim

`MFA requirement satisfied by claim in the token` means that a valid prior MFA claim satisfied the policy. It does not demonstrate a bypass. Validate the token and session context.

### Entra risk

A risk value of `none` lowers concern but does not invalidate a separate behavioral detection.

### Microsoft 365 audit IPs

Additional Microsoft infrastructure IPs may represent automated processing. Use `UserType`, application ID, token object ID, external-access state, and session identifiers before attributing an operation to the interactive user.

## 7. Investigation workflow

1. Identify the sign-in dataset with the best field coverage.
2. Locate the exact alert event.
3. Verify that the event was successful.
4. Build a 30-day user baseline.
5. Compare IP, ASN, country, city, application, browser, and device.
6. Examine failures immediately before the successful event.
7. Validate MFA and Conditional Access.
8. Correlate the session with Microsoft 365 activity.
9. Search for persistence and impact.
10. Contact the user when the remaining ambiguity is business-context dependent.
11. Assign a verdict and document supporting and contradictory evidence.

## 8. Reference findings from the sanitized case

The reference case demonstrated the following general pattern:

- A single public IP was used repeatedly throughout the baseline period.
- The city label changed while the IP and country remained unchanged.
- The user consistently accessed a known web-mail application.
- The browser version changed in a manner compatible with routine software updates.
- Conditional Access succeeded.
- MFA was satisfied using a valid claim already present in the token.
- Entra ID assigned no sign-in risk.
- Post-authentication mailbox activity correlated with the same IP, application, and session.
- Additional infrastructure IPs belonged to automated cloud-service contexts rather than new interactive sessions.
- No inbox-rule persistence, external forwarding, permission abuse, delegated sending, or abnormal deletion was identified in the reviewed evidence.

## 9. Alternative explanations considered

- IP takeover or shared network
- Corporate VPN or secure gateway
- Browser update
- BYOD device
- Stolen session token
- Unauthorized OAuth application
- Automated Microsoft service activity
- Mailbox compromise with hidden persistence

Each alternative should be accepted or rejected using evidence, not assumption.

## 10. Gaps and limitations

- The detection reason may not expose the exact feature considered unusual.
- Device claims may be incomplete.
- Unified Audit Log events do not always represent direct manual actions.
- A limited export may omit relevant workloads or earlier events.
- IP reputation and ownership require current external enrichment.
- A benign historical IP does not prove the current actor is authorized.

## 11. Outcome requirements

A defensible final assessment should include:

- Exact event reviewed
- Historical comparison
- MFA and Conditional Access result
- Entra risk result
- Session correlation
- Post-authentication activity
- Persistence and impact checks
- User validation, if required
- Final classification and confidence
