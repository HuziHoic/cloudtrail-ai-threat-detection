# CloudTrail-Based AI Threat Detection

## Overview
This project implements an AI-driven threat detection system for AWS environments using CloudTrail logs. The system focuses on detecting anomalous IAM user and role behavior by learning baseline usage patterns and identifying deviations that may indicate security incidents such as credential compromise or privilege escalation.

Unlike rule-only systems, this project applies unsupervised machine learning to model normal AWS behavior and surfaces high-risk anomalies with contextual explanations.

## Detection Scope
**Included**
- IAM users and IAM roles
- AWS CloudTrail *management events*
- Behavioral anomalies across time windows
- Unsupervised ML-based detection (Isolation Forest)

**Explicitly Excluded**
- Data plane events (e.g., S3 object access)
- Network-layer attacks (handled by VPC Flow Logs / IDS)
- Malware detection
- Signature-only rule engines

## Threats Addressed
- Credential compromise
- Privilege escalation
- Persistence via IAM changes
- Reconnaissance and unusual API usage

## High-Level Architecture
CloudTrail → S3 → Log Normalization → Feature Engineering → ML Model → Anomaly Scoring → Alerts

*(Architecture diagram to be added in later phases)*

## Technologies
- AWS CloudTrail, S3, Lambda
- Python, pandas, scikit-learn
- Isolation Forest (initial model)
- SNS / Slack (alerting)

## Project Status
Phase 0 — Project setup and scope definition complete.
