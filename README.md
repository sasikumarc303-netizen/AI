# Malware Detection Using AI

AI-powered malware detection web application (Cyber Security domain) built with
**Python · Flask · TensorFlow · scikit-learn · SQLite · ReportLab**.

## Modules

| # | Module | Location | Highlights |
|---|--------|----------|-----------|
| 1 | Login / Auth | `auth/` | Hashed passwords (Werkzeug PBKDF2), sessions, CSRF, rate limiting, show/hide password |
| 2 | Security Dashboard | `main/` | Stat cards, threat chart (dependency-free canvas), recent activity, engine status |
| 3 | File Upload & Analysis | `scanner/` | Drag & drop, size/name validation, temp quarantine, duplicate-submission guard |
| 4 | ML Detection Engine | `ml_engine/` | Static feature extraction (never executes files), TensorFlow MLP, honest UNKNOWN threshold |
| 5 | Result Page | `templates/scanner/result.html` | Verdict, risk, confidence, explanation, recommendation, scan ID |
| 6 | Alerts | `alerts/` | INFO→CRITICAL levels, read/dismiss, filtering — alerts only for MALWARE/SUSPICIOUS |
| 7 | History | `history/` | Debounced search, filters, sort, pagination, CSV export, confirmed delete |
| 8 | Reports | `reports/` | Professional one-scan PDF reports (ReportLab) |
| 9 | Profile | `profile/` | Name/email update, secure password change |
| 10 | USB Protection | `usb_scanner/` | Read-only scanning of mounted volumes; disconnection/permission errors handled |

## Honesty notes (no fake AI)

- The bundled model is trained on a **synthetic feature dataset** that mirrors the
  extractor. The accuracy shown on the dashboard is the **real measured hold-out
  accuracy of that model on that dataset**, and it is labelled as such in the UI.
  For production, retrain on a labelled real dataset (e.g. EMBER) — no app changes needed.
- Confidence below `MDAI_UNKNOWN_THRESHOLD` (default 0.60) is reported as
  **UNKNOWN — Requires Further Analysis**, never guessed as SAFE/MALWARE.
- USB scanning operates on **mounted filesystem paths** (what a web app can genuinely
  access). Files are read-only: never executed, modified, or deleted.

## Setup

```bash
pip install -r requirements.txt

# Secrets via environment (never hard-coded)
export MDAI_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
export MDAI_ADMIN_EMAIL="admin@example.com"
export MDAI_ADMIN_PASSWORD="ChangeMe123!"     # change on first login

python -m ml_engine.train_model               # train + evaluate -> ml_engine/artifacts/
python app.py                                 # http://127.0.0.1:5000
```

## Run the full verification suite

```bash
python tests_e2e.py
```

Covers: login (valid/invalid/empty/CSRF), protected routes, dashboard, uploads
(malware/safe/empty/oversized/missing), temp-file cleanup, alerts (generate/read/dismiss),
history (search/filter/delete/CSV), PDF report, profile update + password change,
USB scan + path rejection + disconnect handling, logout, 404, and a source sweep
proving no `exec()`/`eval()` is used anywhere.

## Security properties

- Passwords hashed; plain text never stored.
- All state-changing routes require a session + CSRF token.
- Login rate-limited (5 attempts / minute / IP); generic failure messages.
- Uploads stored under random server-side names and **deleted after scanning**.
- Files are only ever read as bytes — nothing is executed, opened, or interpreted as code.
- Errors are logged server-side; users see generic messages (no stack traces/paths/secrets).
- USB paths are constrained to an allowed root with symlink resolution.
