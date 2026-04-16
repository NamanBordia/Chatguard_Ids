# ChatGuard IDS Project Report

Date: 2026-04-16

## 1. Problem Statement

Modern chat systems are vulnerable to both content-based and behavior-based attacks, including spam floods, phishing links, cyberbullying, and anomalous traffic spikes. Traditional secure messaging focuses on transport encryption but often lacks in-line threat detection and policy enforcement before message delivery.

The core problem this project addresses is:

- How to build a real-time chat platform that preserves confidentiality and integrity of communication while also performing active intrusion detection and prevention.
- How to reduce abuse and malicious communication without breaking usability for legitimate users.
- How to provide operational visibility (logs, risk scores, user controls) for security monitoring and incident response.

ChatGuard IDS solves this through a defense-in-depth architecture that combines encrypted transport, authenticated access, multi-layer IDS analysis, approval-based controls, and auditable logging.

## 2. Complete Workflow (End-to-End)

### 2.1 System Initialization

1. Server startup initializes SQLite user DB and seeds default users.
2. Detection engine initializes all models:
   - Cyberbullying model
   - Spam model
   - Phishing model
   - Anomaly model
3. Server starts TCP socket listener and waits for client connections.
4. Optional Streamlit dashboard can start/stop server and monitor runtime state.

### 2.2 Secure Session Setup

1. Client and server derive/share AES-256 key from:
   - `CHAT_AES_KEY_B64` (raw 32-byte key), or
   - `CHAT_AES_PASSPHRASE` (PBKDF2-derived key).
2. All payloads are encrypted using AES-GCM with per-message nonce.
3. Server sends encrypted auth challenge (`auth_required`).
4. Client sends encrypted credentials.
5. Server verifies credentials against salted PBKDF2 password hash in SQLite.
6. On success, user is admitted to active session list; duplicate concurrent login for same user is prevented.

### 2.3 Message Processing Pipeline

For each direct message (`/to <user> <message>`):

1. Input validation
   - Ensure receiver exists online and sender is not messaging self.
2. Multi-layer detection (`detect_all`)
   - Cyberbullying classifier checks abusive/toxic language.
   - Spam classifier checks textual spam likelihood + per-user rate burst rule.
   - Phishing detector checks URL risk patterns + ML URL features.
   - Anomaly detector evaluates user behavior profile against baseline.
3. Decision engine
   - `block`: high-severity threats (except anomaly-only guardrails).
   - `warn`: medium risk, message flow constrained and logged.
   - `allow_with_notice`: low suspicious signals.
   - `allow`: no threat findings.
4. Risk scoring
   - User risk score is incremented by severity and decays slowly on clean behavior.
5. Approval gate
   - First contact between sender->receiver requires receiver approval.
   - Pending request is queued and preview sent to receiver.
   - Receiver responds with approve/deny.
6. Delivery and audit
   - If approved and not blocked, message is delivered.
   - Every major event is logged with timestamp, threat type, severity, and action.

### 2.4 Operations and Monitoring

1. Server CLI dashboard supports:
   - User CRUD (`adduser`, `passwd`, `deluser`, `dbusers`)
   - Runtime stats (`stats`, `users`)
2. Streamlit UI supports:
   - Server lifecycle controls
   - Live online users/risk scores/pending approvals
   - Log tailing
   - Encrypted client chat experience
3. Logs provide an auditable event trail for post-incident investigation.

## 3. What We Used and Why

### 3.1 Core Platform Components

- Python sockets + threading
  - Why: Lightweight low-level network control, real-time bi-directional communication, multi-client concurrency.

- AES-256-GCM (`pycryptodome`)
  - Why: Provides confidentiality + integrity (authenticated encryption), critical against tampering and eavesdropping.

- SQLite + PBKDF2-HMAC password hashing
  - Why: Persistent local auth store with strong, salted, iterative password hashing; practical for project-scale deployment.

### 3.2 IDS/IPS Detection Stack

- Cyberbullying detection: TF-IDF + Logistic Regression
  - Why: Strong baseline for text classification, interpretable and efficient for real-time moderation.

- Spam detection: TF-IDF + Multinomial Naive Bayes + rate-limit heuristic
  - Why: Combines content-based and behavior-based spam signals to reduce false negatives from either method alone.

- Phishing detection: URL heuristics + RandomForest
  - Why: URL attacks need lexical/structural feature checks; hybrid rules+ML catches both known and variant phishing patterns.

- Anomaly detection: Isolation Forest on user behavior metrics
  - Why: Unsupervised anomaly detection identifies unusual traffic/message behavior not represented in labeled datasets.

### 3.3 Supporting Data and Features

- Multi-source toxicity datasets
  - Why: Broader linguistic coverage for abusive language patterns.

- Spam and phishing datasets
  - Why: Improves detector generalization compared to synthetic-only samples.

- Anomaly baseline CSV
  - Why: Establishes expected normal communication behavior for outlier detection.

### 3.4 Security Operations Features

- Approval-based first-contact messaging
  - Why: Human-in-the-loop control limits unsolicited abuse and social engineering.

- Structured logging (`timestamp | user | message | threat | severity | action`)
  - Why: Enables SOC-style traceability, incident triage, and forensic analysis.

- Risk score tracking per user
  - Why: Behavioral risk aggregation supports adaptive response and monitoring.

## 4. Alignment with Network Security Concepts

### 4.1 CIA Triad

- Confidentiality
  - Enforced by AES-256-GCM encrypted payloads over sockets.

- Integrity
  - GCM authentication tag detects payload tampering in transit.

- Availability
  - Threaded architecture supports concurrent clients; anomaly and spam controls mitigate abusive traffic patterns.

### 4.2 AAA (Authentication, Authorization, Accounting)

- Authentication
  - Username/password verification against salted PBKDF2 hashes.

- Authorization
  - Role support (`user`, `admin`) and approval-based sender permission path.

- Accounting
  - Event logging + risk score updates produce accountable user activity records.

### 4.3 IDS/IPS Principles

- Signature/heuristic detection
  - URL and keyword/behavior heuristics in phishing/spam layers.

- Anomaly-based detection
  - Isolation Forest over message frequency, intervals, and lengths.

- Prevention (IPS behavior)
  - High-risk messages are blocked before delivery; suspicious events trigger warnings and constrained flow.

### 4.4 Defense in Depth

The system does not rely on a single control. It layers:

1. Encrypted transport security.
2. Authenticated user access.
3. Content and behavior IDS checks.
4. Decision policy (allow/warn/block).
5. Receiver approval control.
6. Continuous logging and monitoring.

This layered model is aligned with enterprise network security architecture and reduces single-point control failure risk.

### 4.5 Zero Trust and Least Privilege (Project-Level Interpretation)

- Zero Trust mindset
  - Every message is inspected before delivery; no message is implicitly trusted.

- Least privilege
  - Users have minimal default permissions; first-contact messaging requires explicit receiver approval.

## 5. Security Strengths and Practical Limits

### Strengths

- End-to-end secure message envelopes at application layer.
- Hybrid IDS design improves resilience versus single-model systems.
- Real-time policy enforcement and user-facing alerting.
- Operational control plane (CLI + Streamlit) with audit logs.

### Limits

- Shared symmetric key model requires secure key distribution/rotation process.
- Localhost default deployment is suitable for prototype/lab, not internet-exposed production.
- Model performance depends on dataset quality, drift handling, and retraining frequency.
- TLS at transport perimeter, SIEM integration, and formal RBAC hardening can further improve production readiness.

## 6. Conclusion

ChatGuard IDS demonstrates a network-security-aligned secure messaging architecture where cryptography, authentication, multi-layer IDS analytics, and policy enforcement are integrated into one operational workflow. The project aligns strongly with core concepts of confidentiality, integrity, access control, intrusion detection/prevention, and defense in depth, while remaining practical for academic demonstration and iterative security engineering.
