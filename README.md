# 🛡️ Insider Threat Detector

A comprehensive security monitoring tool designed to detect, log, and visualize potential insider threats within a file system. This project uses a client-server architecture to monitor file activity in real-time, identifying anomalies based on behavioral patterns and honeyfile interactions.

## ✨ Features

### 🕵️ Real-Time Monitoring
* **Live Tracking:** Uses `watchdog` to instantly detect file creation, modification, and deletion events.
* **Centralized Logging:** The agent sends all activity logs to a Flask server for storage and analysis.

### 🚨 Anomaly Detection Engine
The system analyzes every event against a set of security rules:
* **Time-Based Heuristics:** Flags activity occurring outside standard working hours (e.g., 10 PM - 7 AM IST).
* **Keyword Analysis:** Detects suspicious filenames containing sensitive terms like `confidential`, `salary`, `password`, or `private`.
* **Honeyfile Traps:** Identifies "Critical" threats if a user interacts with decoy files (e.g., `legacy_credentials_`).

### 🍯 Active Defense (Honeyfiles)
* **Automatic Deployment:** If suspicious activity is detected, the agent automatically plants a "honeyfile" (fake credentials) in the affected directory.
* **Trap Logic:** Any interaction with these honeyfiles triggers a high-priority alert.

### 📊 Interactive Dashboard
* **Visual Analytics:** Powered by **Chart.js**, offering graphs for alerts over time, file type distribution, and action breakdown.
* **Live Feed:** A detailed, color-coded table showing timestamp (IST), user, action, and suspicion level.

## 🛠️ Tech Stack

* **Language:** Python 3.9+
* **Backend:** Flask, SQLAlchemy, SQLite
* **Monitoring:** Watchdog Library
* **Frontend:** HTML5, CSS3, Chart.js
* **Utilities:** Requests, Datetime

## 🚀 Installation & Setup

### 1. Prerequisites
Ensure you have **Python** installed.

### 2. Clone the Repository
```bash
git clone [https://github.com/aashi53/InsiderThreatDetector.git](https://github.com/aashi53/InsiderThreatDetector.git)
cd InsiderThreatDetector
```

### 3. Set Up Virtual Environment
# Windows
```bash
python -m venv .venv
.venv\Scripts\activate
```

# Mac/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 💻 Usage
This project requires running two separate terminal instances: one for the Server and one for the Agent.
