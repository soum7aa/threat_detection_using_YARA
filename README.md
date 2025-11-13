# Adaptive Unified Real-time Analyzer (AURA)

## 🛡️ Overview
AURA is a real-time security monitoring system that combines multiple detection engines to identify and analyze threats across processes, network connections, and file systems. It provides a live dashboard with incident tracking and mitigation actions.

---

## ✨ Key Features
- **Multi-Engine Detection**: YARA signature scanning, anomaly detection (ML), heuristic analysis
- **Real-time Monitoring**: Processes, network connections, file system events
- **Web Dashboard**: Live threat stream, file upload and scan, URL safety testing
- **Mitigation**: Quarantine suspicious files, terminate malicious processes

---

## ✅ Prerequisites
- Python 3.7 or higher
- Administrator privileges recommended for full monitoring

---

## 🚀 Quick Start
1) Navigate to the project directory:
```bash
cd C:\Users\usoum\Downloads\threat-main-realtime-v4-frontend
```

2) Create a virtual environment (recommended):
```bash
python -m venv venv
```

3) Activate the virtual environment:
```bash
# Windows (Command Prompt)
venv\Scripts\activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# Linux/Mac
source venv/bin/activate
```
You should see `(venv)` at the start of your prompt.

4) Install dependencies:
```bash
pip install -r requirements.txt
```
Note: If `yara-python` fails to install, AURA automatically falls back to string matching. All features remain available with reduced signature accuracy.

5) Run the application:
```bash
# Option 1 (recommended)
python run_integrated_system.py

# Option 2
python app.py
```

6) Open the dashboard:
- Browser: http://127.0.0.1:5000/
- File Scan: http://127.0.0.1:5000/scan-file
- URL Safety Test: http://127.0.0.1:5000/test-malicious

To stop the app, press `Ctrl+C` in the terminal.

---

## 🧭 Common Commands
```bash
# Activate venv (Windows CMD)
venv\Scripts\activate

# Deactivate venv
deactivate

# Verify sklearn installation
python -c "import sklearn; print('sklearn OK')"
```

---

## 📦 System Components
- `app.py`: Flask application and API
- `detection/`: YARA scanner and anomaly detection
- `monitor/`: Process, network, file system monitors
- `mitigation/`: Threat response actions
- `utils/`: Logging and utilities
- `static/`: Web UI (`index.html`, `scan-file.html`, `test-malicious.html`)
- `yara_rules/`: Signature rules (PE, UPX, PowerShell, miner, EICAR)

---

## 🧪 Testing
- Use the Scan File page or API to upload files and exercise the detection pipeline
- Example: EICAR test detection is supported

---

## 🔌 API Endpoints (advanced)
- `GET /api/stream` — Real-time event stream (SSE)
- `POST /api/upload_scan` — Upload and scan files
- `POST /api/mitigate` — Apply mitigation actions
- `GET /api/incidents` — Retrieve stored incidents
- `POST /api/yara/reload` — Reload YARA rules
- `GET /api/yara/status` — Check YARA engine status
- `POST /api/test_url` — Analyze website safety
- `GET /api/paths` — Get/set watch paths
- `POST /api/scan_paths/start` — Start background scan

---

## 🛠️ Troubleshooting
- **Port 5000 in use**: Change the port in `app.py` (e.g., `app.run(debug=True, port=5001)`).
- **Permission errors**: Run terminal as Administrator (Windows) or use `sudo` (Linux/Mac).
- **ModuleNotFoundError**: Ensure `(venv)` is active, then `pip install -r requirements.txt`.
- **PowerShell activation blocked**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```
- **Typo running launcher**:
  - Wrong: `python run_itegrated_system.py`
  - Correct: `python run_integrated_system.py`

---

## ⚠️ Notes
- Elevated privileges may be required for some monitoring/mitigation features.
- This is a demo/development system; harden before any production use.
- Some rules may generate false positives and may need tuning for your environment.

---

Happy Monitoring! 🛡️


