# Secure Chat System with Multi-Layer Intrusion Detection (IDS/IPS)

A Python socket-based client-server chat project where the server acts as an IDS/IPS engine.

## Features

- TCP socket communication (no Flask/HTTP)
- AES-256-GCM encrypted client-server payloads (message confidentiality + integrity)
- Multi-client server using threading
- SQLite user database with secure password hashing (PBKDF2-HMAC)
- Full user CRUD operations (create, read/list, update password, delete)
- Direct messaging only (no message broadcast to everyone)
- Receiver approval required before first sender message is delivered
- Real-time IDS detection pipeline:
  - Cyberbullying detection: TF-IDF + Logistic Regression
  - Spam detection: TF-IDF + Multinomial Naive Bayes + rate rule
  - Phishing detection: URL heuristics + RandomForest URL-feature model
  - Anomaly detection: Isolation Forest on user behavior signals
- Decision engine (allow/warn/block)
- Log storage in `logs/logs.txt`
- Alerts shown on server and client
- Per-user risk score + server CLI dashboard

## Project Structure

project/
- server/
  - server.py
  - detection.py
  - logger.py
  - auth.py
- client/
  - client.py
- models/
  - bullying_model.py
  - spam_model.py
  - phishing_model.py
  - anomaly_model.py
  - train_cyberbullying_model.py
  - train_spam_model.py
  - train_phishing_model.py
  - train_anomaly_model.py
  - train_ids_models.py
- data/
  - sample_dataset.csv
  - bullying_dataset.csv
  - spam_dataset.csv
  - phishing_dataset.csv
  - anomaly_baseline.csv
  - users.db
- logs/
  - logs.txt
- README.md

## Requirements

- Python 3.9+
- `pycryptodome` (`pip install pycryptodome`)
- `streamlit` (`pip install streamlit`)

## Default Users

Seeded automatically into SQLite (`data/users.db`) on first run:

- `alice` / `alice123` (role: user)
- `bob` / `bob123` (role: user)
- `admin` / `admin123` (role: admin)
- `naman` / `naman123` (role: user)

## Run Instructions

1. Set a shared AES secret for both server and every client terminal (recommended):

```bash
# Option A: passphrase (derived to AES-256 key via PBKDF2)
set CHAT_AES_PASSPHRASE=change-this-to-a-strong-secret

# Option B: raw AES-256 key in base64 (32 bytes after decoding)
# set CHAT_AES_KEY_B64=<base64-encoded-32-byte-key>
```

2. Start server first:

```bash
python server/server.py
```

3. Open one or more new terminals and start clients:

```bash
python client/client.py
```

4. Login with a valid username and password.

5. Use client commands:

- `/to <username> <message>` send direct message
- `/approve <sender>` approve sender request
- `/deny <sender>` deny sender request
- `/users` list currently online users
- `/quit` disconnect

When a sender messages a receiver for the first time, the message is checked by IDS first, then held until the receiver approves.

All command, auth, and chat payloads are sent as AES-GCM encrypted envelopes over the socket transport.

## Server Dashboard CRUD Commands

In the server terminal:

- `dbusers` list all users in database (includes id, username, role)
- `adduser <username> <password> [role]` create user
- `passwd <username> <new_password>` update user password
- `deluser <username>` delete user
- `users` list online users
- `stats` show online users and risk scores
- `help` show command list

## IDS Decision Behavior

- SAFE: message is eligible for delivery
- LOW/MEDIUM severity: warning + logging; approval flow continues
- HIGH severity or abusive bullying: blocked before receiver sees it

All messages are always inspected by IDS before delivery.

## Log Format

Every event is appended to `logs/logs.txt` as:

```
timestamp | username | message | threat_type | severity | action_taken
```

Common action values:

- `blocked`
- `pending_approval`
- `pending_approval_flagged`
- `delivered`
- `delivered_flagged`
- `delivered_after_approval`
- `approval_denied`
- `accepted`
- `disconnect`

## Notes

- `models/bullying_model.pkl` is currently a placeholder for ML extension.
- To switch to ML-based bullying detection, replace `detect_cyberbullying()` in `server/detection.py`.

## Detection Engine Models

Each detector uses a separate specialized model:

- Cyberbullying: Logistic Regression + TF-IDF text features
- Spam: Multinomial Naive Bayes + TF-IDF text features + (>5 msgs/10s) rule
- Phishing: URL regex/rules + RandomForest on URL features
- Anomaly: Isolation Forest on live behavior (messages per minute, length, interval)

Model handling is module-based (`.py`), not `.pkl` artifacts.

### Train Models

1. Install dependencies:

```bash
pip install scikit-learn joblib
```

2. Train and save models:

```bash
python models/train_ids_models.py
```

Or train each detector separately:

```bash
python models/train_cyberbullying_model.py
python models/train_spam_model.py
python models/train_phishing_model.py
python models/train_anomaly_model.py
```

### Datasets Used Right Now

Training now uses these exact datasets:

- Cyberbullying:
  - `data/aggression_parsed_dataset.csv`
  - `data/attack_parsed_dataset.csv`
  - `data/kaggle_parsed_dataset.csv`
  - `data/toxicity_parsed_dataset.csv`
  - `data/twitter_parsed_dataset.csv`
  - `data/twitter_racism_parsed_dataset.csv`
  - `data/twitter_sexism_parsed_dataset.csv`
  - `data/youtube_parsed_dataset.csv`
- Spam:
  - `data/spam.csv`
- Phishing:
  - `data/PhiUSIIL_Phishing_URL_Dataset.csv`
- Anomaly baseline:
  - `data/anomaly_baseline.csv`

Recommended public datasets to replace/extend local data:

- Cyberbullying/Toxic: Kaggle Toxic Comment Classification or Cyberbullying Detection datasets
- Spam: SMS Spam Collection (UCI/Kaggle)
- Phishing: Kaggle Phishing URL datasets
- Anomaly: no fixed dataset required; use normal traffic baselines from your own system

Each CSV should have columns:

```csv
text,label
```

Supported labels:

- `safe`
- `abusive` / `bullying` / `toxic` / `hate`
- `spam`
- `phishing` / `scam`

Anomaly baseline CSV format:

```csv
messages_per_minute,message_length,interval_seconds
```

3. Restart the server:

```bash
python server/server.py
```

Important: no IDS can "detect anything" with 100% accuracy. Detection quality mainly depends on training data coverage and periodic retraining.

## Streamlit Frontend

This project includes a Streamlit UI with separate pages for server and client workflows:

- `pages/1_Server_Dashboard.py`: start/stop server, live stats, user CRUD, logs
- `pages/2_Client_Chat.py`: encrypted chat interface with left/right message bubbles

Run the frontend from project root:

```bash
streamlit run streamlit_app.py
```

Then:

1. Open **Server Dashboard** page and click **Start**.
2. Open **Client Chat** page and connect with username/password.
3. Send messages using the chat form.
