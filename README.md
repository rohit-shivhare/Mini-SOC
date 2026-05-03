# Mini‑SOC

A lightweight **Security Operations Center (SOC) simulator** built with Flask. It provides:

- A web dashboard that shows synthetic network traffic and alerts.
- An API to run a simple web‑scanner against a target URL.
- Secure file‑transfer utilities (encrypt/decrypt) using the `cryptography` library.
- A background network‑sniffer (simulated on Windows when WinPcap is unavailable).

## Quick start (local)
```bash
# Create a fresh virtual environment (if not already present)
python -m venv .myenv
.\.myenv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```
Open <http://127.0.0.1:5000> in a browser.

## Project structure
```
Mini-SOC/
├─ app.py              # Flask entry point
├─ database.py         # SQLite helpers
├─ modules/            # scanner, secure transfer, network monitor
├─ templates/          # HTML UI
├─ uploads/            # Uploaded files (ignored by git)
├─ requirements.txt    # Python dependencies
├─ .gitignore          # Ignored files (virtual env, secrets, uploads, db, etc.)
└─ README.md           # This file
```

## Security notes
- The secret key (`secret.key`) is **not** committed – it is listed in `.gitignore`.
- The development server is **not** for production use; deploy with a WSGI server for real deployments.

## License
MIT License – feel free to fork, modify, and use.
