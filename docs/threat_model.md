# Threat Model — CloudTrail AI Threat Detection

## Objective
Detect anomalous AWS account activity indicative of security threats by analyzing CloudTrail management events related to IAM behavior.

## Assets
- AWS account integrity
- IAM users and roles
- Credentials and access keys
- Administrative privileges

## Adversary Model
The adversary is assumed to have:
- Stolen or misused IAM credentials
- Limited initial access
- No direct control over AWS logging mechanisms

The adversary may attempt to:
- Escalate privileges
- Maintain persistence
- Perform reconnaissance
- Avoid detection by mimicking normal behavior

## Threats in Scope
### Credential Compromise
- ConsoleLogin from new regions
- Sudden increase in API call rate
- Use of previously unseen APIs

### Privilege Escalation
- AttachRolePolicy
- PassRole
- CreateAccessKey

### Persistence
- Creation of new IAM users or keys
- Policy modifications

### Reconnaissance
- High volume of Describe/List API calls
- Broad service enumeration

## Threats Out of Scope
- Network-based attacks (e.g., port scanning)
- Application-layer attacks
- Malware execution
- Insider threats with legitimate long-term behavior patterns

## Detection Strategy
- Behavioral modeling using unsupervised ML
- Time-windowed aggregation of CloudTrail events
- Hybrid scoring using ML anomaly score + risk-weighted rules

## Assumptions
- CloudTrail logs are complete and untampered
- Baseline behavior represents mostly benign activity
- Alerts are reviewed by a human analyst
