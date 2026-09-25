"""End-to-end verification of every module (Section 18/20 checklist)."""
import io
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["MDAI_DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(suffix=".db")
os.environ["MDAI_UPLOAD_DIR"] = tempfile.mkdtemp()

from app import create_app  # noqa: E402

app = create_app()
app.config["TESTING"] = True
client = app.test_client()
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {extra}" if extra and not cond else ""))


def csrf(path):
    html = client.get(path).data.decode()
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


# --- build realistic test samples ---
tmp = tempfile.mkdtemp()
pe_header = bytearray(4096)
pe_header[:2] = b"MZ"
pe_header[0x3C:0x40] = (0x80).to_bytes(4, "little")
pe_header[0x80:0x84] = b"PE\x00\x00"
pe_header[0x86:0x88] = (3).to_bytes(2, "little")
pe_header[0x96:0x98] = (0x0102).to_bytes(2, "little")
malware_path = os.path.join(tmp, "evil.exe")
with open(malware_path, "wb") as f:
    f.write(bytes(pe_header))
    f.write(os.urandom(60_000))  # packed-looking high entropy
    for _ in range(8):
        f.write(b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
                b"URLDownloadToFile\x00cmd.exe\x00powershell\x00")
    f.write(os.urandom(60_000))
safe_path = os.path.join(tmp, "notes.txt")
with open(safe_path, "w") as f:
    f.write("Meeting notes and quarterly planning document.\n" * 500)
empty_path = os.path.join(tmp, "empty.bin")
open(empty_path, "wb").close()

# === AUTH ===
r = client.get("/")
check("protected route redirects to login", r.status_code == 302 and "/auth/login" in r.headers["Location"])
r = client.get("/auth/login")
check("login page renders", r.status_code == 200 and b"Sign in" in r.data)
r = client.post("/auth/login", data={"csrf_token": csrf("/auth/login"),
                                     "email": "admin@example.com", "password": "wrongpass"})
check("invalid login handled with 401", r.status_code == 401 and b"Invalid email or password" in r.data)
r = client.post("/auth/login", data={"csrf_token": csrf("/auth/login"),
                                     "email": "", "password": ""})
check("empty login fields rejected", r.status_code == 400)
r = client.post("/auth/login", data={"email": "admin@example.com", "password": "x"})
check("missing CSRF rejected with 400", r.status_code == 400)
r = client.post("/auth/login", data={"csrf_token": csrf("/auth/login"),
                                     "email": "admin@example.com", "password": "ChangeMe123!"},
                follow_redirects=True)
check("valid login reaches dashboard", r.status_code == 200 and b"Security Dashboard" in r.data)

# === DASHBOARD ===
check("dashboard stat cards present", all(x in r.data for x in
      [b"Total scanned", b"Malware detected", b"Safe files", b"Suspicious", b"Unknown"]))
check("model status online", b"ONLINE" in r.data)
check("real measured accuracy shown", b"Measured accuracy" in r.data and b"synthetic" in r.data)

# === SCANNER ===
with open(malware_path, "rb") as f:
    r = client.post("/scanner/upload",
                    data={"csrf_token": csrf("/scanner/"), "file": (f, "evil.exe")},
                    content_type="multipart/form-data", follow_redirects=True)
check("malware scan completes", r.status_code == 200 and b"Scan Result" in r.data)
mal_detected = b"MALWARE DETECTED" in r.data
check("malware sample classified MALWARE", mal_detected,
      re.search(rb'<div class="status"[^>]*>\s*(\w+)', r.data).group(1).decode() if not mal_detected else "")
check("recommendation shown", b"Recommended action" in r.data)
check("scan id shown", b"Scan ID" in r.data)
with open(safe_path, "rb") as f:
    r_safe = client.post("/scanner/upload",
                         data={"csrf_token": csrf("/scanner/"), "file": (f, "notes.txt")},
                         content_type="multipart/form-data", follow_redirects=True)
check("safe text file completes scan", r_safe.status_code == 200 and b"Scan Result" in r_safe.data)
check("honest wording (no '100% safe' claim)", b"NO MALWARE DETECTED" in r_safe.data
      or b"UNKNOWN" in r_safe.data or b"No malware detected by the configured model" in r_safe.data)
with open(empty_path, "rb") as f:
    r = client.post("/scanner/upload",
                    data={"csrf_token": csrf("/scanner/"), "file": (f, "empty.bin")},
                    content_type="multipart/form-data", follow_redirects=True)
check("empty/corrupt file handled without crash", r.status_code == 200 and
      (b"SCAN ERROR" in r.data or b"UNKNOWN" in r.data))
r = client.post("/scanner/upload", data={"csrf_token": csrf("/scanner/")},
                content_type="multipart/form-data", follow_redirects=True)
check("missing file handled", b"No file was provided" in r.data)
big = io.BytesIO(b"A" * (app.config["MAX_CONTENT_LENGTH"] + 10))
r = client.post("/scanner/upload", data={"csrf_token": csrf("/scanner/"),
                                         "file": (big, "big.bin")},
                content_type="multipart/form-data")
check("oversized file rejected with 413", r.status_code == 413)
check("temp uploads cleaned up", len(os.listdir(app.config["UPLOAD_DIR"])) == 0)

# === ALERTS ===
r = client.get("/alerts/")
check("alerts page renders", r.status_code == 200 and b"Security Alerts" in r.data)
check("malware alert generated", b"evil.exe" in r.data)
m = re.search(r'/alerts/(\d+)', r.data.decode())
if m:
    r = client.get(f"/alerts/{m.group(1)}")
    check("alert detail renders + marks read", r.status_code == 200 and b"Alert Detail" in r.data)
    r = client.post(f"/alerts/{m.group(1)}/dismiss", data={"csrf_token": csrf("/alerts/")},
                    follow_redirects=True)
    check("alert dismissal works", r.status_code == 200)
else:
    check("alert detail renders + marks read", False); check("alert dismissal works", False)

# === HISTORY ===
r = client.get("/history/")
check("history page renders", r.status_code == 200 and b"Scan History" in r.data)
check("scans stored in history", b"evil.exe" in r.data and b"notes.txt" in r.data)
r = client.get("/history/?q=evil")
check("history search works", b"evil.exe" in r.data and b"notes.txt" not in r.data)
r = client.get("/history/?result=MALWARE")
check("history filter works", r.status_code == 200)
r = client.get("/history/export.csv")
check("CSV export works", r.status_code == 200 and b"Scan ID" in r.data)
m = re.search(r'/history/([0-9a-f-]{36})', client.get("/history/").data.decode())
if m:
    su = m.group(1)
    r = client.get(f"/history/{su}")
    check("history detail renders", r.status_code == 200 and b"Scan Record" in r.data)
    r = client.post(f"/history/{su}/delete", data={"csrf_token": csrf("/history/")},
                    follow_redirects=True)
    check("history delete works", r.status_code == 200 and su.encode() not in r.data)
else:
    check("history detail renders", False); check("history delete works", False)

# === REPORTS ===
r = client.get("/reports/")
check("reports page renders", r.status_code == 200)
m = re.search(r'/reports/scan/([0-9a-f-]{36})\.pdf', r.data.decode())
if m:
    r = client.get(f"/reports/scan/{m.group(1)}.pdf")
    check("PDF report generated", r.status_code == 200 and r.data[:5] == b"%PDF-")
    check("PDF is non-trivial", len(r.data) > 2000)
else:
    check("PDF report generated", False); check("PDF is non-trivial", False)

# === PROFILE ===
r = client.get("/profile/")
check("profile renders", r.status_code == 200 and b"Account Settings" in r.data)
r = client.post("/profile/update", data={"csrf_token": csrf("/profile/"),
                                         "name": "Admin User", "email": "admin@example.com"},
                follow_redirects=True)
check("profile update works", b"Profile updated" in r.data)
r = client.post("/profile/password", data={"csrf_token": csrf("/profile/"),
                "current_password": "wrong", "new_password": "NewPass123!",
                "confirm_password": "NewPass123!"}, follow_redirects=True)
check("wrong current password rejected", b"current password is incorrect" in r.data)
r = client.post("/profile/password", data={"csrf_token": csrf("/profile/"),
                "current_password": "ChangeMe123!", "new_password": "NewPass123!",
                "confirm_password": "NewPass123!"}, follow_redirects=True)
check("password change works", b"Password changed successfully" in r.data)

# === USB ===
fake_usb = tempfile.mkdtemp()
shutil.copy(malware_path, os.path.join(fake_usb, "evil.exe"))
shutil.copy(safe_path, os.path.join(fake_usb, "readme.txt"))
app.config["USB_ALLOWED_ROOT"] = os.path.dirname(fake_usb)
r = client.get("/usb/")
check("USB page renders", r.status_code == 200 and b"USB Device Protection" in r.data)
r = client.post("/usb/scan", data={"csrf_token": csrf("/usb/"), "device": fake_usb})
check("USB scan completes", r.status_code == 200 and b"USB Scan Results" in r.data)
check("USB scan classified files", b"evil.exe" in r.data)
r = client.post("/usb/scan", data={"csrf_token": csrf("/usb/"), "device": "/etc"})
check("USB path outside allowed root rejected", r.status_code == 302)
r = client.post("/usb/scan", data={"csrf_token": csrf("/usb/"),
                                   "device": os.path.join(fake_usb, "gone")}, follow_redirects=True)
check("disconnected device handled gracefully", b"Device not found" in r.data)

# === LOGOUT & SESSION ===
r = client.get("/auth/logout", follow_redirects=True)
check("logout works", b"Sign in" in r.data)
r = client.get("/history/")
check("post-logout access blocked", r.status_code == 302)
r = client.get("/definitely-not-a-route")
check("404 handled", r.status_code == 404)

# === SECURITY SWEEP ===
src_issues = []
for root, _, files in os.walk(os.path.dirname(os.path.abspath(__file__))):
    for fn in files:
        if fn.endswith(".py") and fn != "tests_e2e.py":
            code = open(os.path.join(root, fn), encoding="utf-8").read()
            if re.search(r"\bexec\(|\beval\(", code):
                src_issues.append(fn)
check("no exec/eval anywhere in source", not src_issues, str(src_issues))

print(f"\n===== {len(PASS)} passed, {len(FAIL)} failed =====")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
