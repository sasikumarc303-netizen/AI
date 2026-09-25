"""Safe static feature extraction.

Files are NEVER executed, opened as programs, or passed to exec/eval.
Only raw bytes are read and analysed. All parsing is defensive.
"""
import hashlib
import math
import os

MAX_READ_BYTES = 8 * 1024 * 1024  # read at most 8 MB for analysis

FEATURE_NAMES = [
    "size_log1p", "entropy", "printable_ratio", "unique_byte_ratio",
    "mean_byte", "is_pe", "pe_executable", "pe_dll", "n_sections",
    "high_entropy_section_ratio", "suspicious_api_score", "suspicious_str_score",
    "file_type_code", "has_autorun_name", "double_extension",
    "extension_magic_mismatch", "script_marker", "entropy_size_product",
]
NUM_FEATURES = len(FEATURE_NAMES)

SUSPICIOUS_APIS = [
    b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"SetWindowsHookEx",
    b"URLDownloadToFile", b"WinExec", b"ShellExecuteA", b"RegSetValueEx",
    b"CryptEncrypt", b"IsDebuggerPresent", b"AdjustTokenPrivileges", b"OpenProcess",
]
SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"rundll32", b"regsvr32", b"schtasks",
    b"CurrentVersion\\Run", b"WScript.Shell", b"base64 -d", b"FromBase64String",
]
SCRIPT_MARKERS = [b"powershell", b"vbscript", b"jscript", b"eval" + b"(", b"WScript.Shell"]
MAGIC_SIGNATURES = [
    (b"MZ", 0.1), (b"\x7fELF", 0.2), (b"PK\x03\x04", 0.3), (b"%PDF", 0.4),
    (b"\x89PNG", 0.5), (b"\xff\xd8\xff", 0.6), (b"GIF8", 0.7), (b"Rar!", 0.8),
]
EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"}
DOCUMENT_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".png", ".jpg", ".jpeg", ".gif"}


class FeatureExtractionError(Exception):
    """Raised when a file cannot be analysed safely."""


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _parse_pe(data: bytes) -> dict:
    """Minimal, defensive PE header parse. Returns zeros on any anomaly."""
    info = {"is_pe": 0.0, "pe_executable": 0.0, "pe_dll": 0.0,
            "n_sections": 0.0, "high_entropy_section_ratio": 0.0}
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return info
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        if pe_off <= 0 or pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return info
        info["is_pe"] = 1.0
        n_sections = int.from_bytes(data[pe_off + 6:pe_off + 8], "little")
        characteristics = int.from_bytes(data[pe_off + 22:pe_off + 24], "little")
        info["pe_executable"] = 1.0 if characteristics & 0x0002 else 0.0
        info["pe_dll"] = 1.0 if characteristics & 0x2000 else 0.0
        opt_size = int.from_bytes(data[pe_off + 20:pe_off + 22], "little")
        sec_off = pe_off + 24 + opt_size
        if n_sections > 96 or sec_off + 40 * n_sections > len(data):
            info["n_sections"] = 0.0
            return info
        info["n_sections"] = float(n_sections)
        high = 0
        for i in range(n_sections):
            base = sec_off + 40 * i
            raw_size = int.from_bytes(data[base + 16:base + 20], "little")
            raw_ptr = int.from_bytes(data[base + 20:base + 24], "little")
            if 0 < raw_size <= len(data) and 0 <= raw_ptr and raw_ptr + raw_size <= len(data):
                if _entropy(data[raw_ptr:raw_ptr + raw_size]) > 7.2:
                    high += 1
        info["high_entropy_section_ratio"] = high / n_sections if n_sections else 0.0
    except Exception:
        return {"is_pe": 0.0, "pe_executable": 0.0, "pe_dll": 0.0,
                "n_sections": 0.0, "high_entropy_section_ratio": 0.0}
    return info


def _magic_code(head: bytes) -> float:
    for sig, code in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return code
    return 0.0


def extract_feature_vector(path: str, original_name: str | None = None):
    """Return (feature_vector, metadata). Raises FeatureExtractionError on bad input."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise FeatureExtractionError("File is not accessible.") from exc
    if size == 0:
        raise FeatureExtractionError("File is empty.")
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ_BYTES)
    except OSError as exc:
        raise FeatureExtractionError("File could not be read.") from exc

    name = (original_name or os.path.basename(path)).lower()
    ext = os.path.splitext(name)[1]
    head = data[:16]
    magic = _magic_code(head)
    pe = _parse_pe(data)

    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    ent = _entropy(data[:1024 * 1024])
    api_hits = sum(data.count(sig) for sig in SUSPICIOUS_APIS)
    str_hits = sum(data.count(sig) for sig in SUSPICIOUS_STRINGS)
    script_hits = sum(data.lower().count(sig) for sig in SCRIPT_MARKERS)

    parts = name.split(".")
    double_ext = 1.0 if len(parts) > 2 and ("." + parts[-2]) in DOCUMENT_EXTS and ext in EXECUTABLE_EXTS else 0.0
    mismatch = 1.0 if (ext in EXECUTABLE_EXTS and magic not in (0.1, 0.2)) or (ext in DOCUMENT_EXTS and magic in (0.1, 0.2)) else 0.0

    vector = [
        math.log1p(size),
        ent,
        printable / len(data),
        len(set(data)) / 256.0,
        (sum(data) / len(data)) / 255.0,
        pe["is_pe"], pe["pe_executable"], pe["pe_dll"],
        pe["n_sections"] / 20.0,
        pe["high_entropy_section_ratio"],
        min(api_hits, 50) / 50.0,
        min(str_hits, 50) / 50.0,
        magic,
        1.0 if name == "autorun.inf" else 0.0,
        double_ext,
        mismatch,
        min(script_hits, 20) / 20.0,
        ent * math.log1p(size) / 100.0,
    ]
    meta = {
        "sha256": sha256_of(path),
        "size": size,
        "entropy": round(ent, 3),
        "is_pe": bool(pe["is_pe"]),
        "extension": ext or "(none)",
        "signals": _signals(pe, api_hits, str_hits, double_ext, mismatch, ent),
    }
    return vector, meta


def _signals(pe, api_hits, str_hits, double_ext, mismatch, ent):
    out = []
    if ent > 7.2:
        out.append("high entropy (possible packing/encryption)")
    if pe["high_entropy_section_ratio"] > 0.3:
        out.append("high-entropy PE sections")
    if api_hits >= 3:
        out.append(f"{api_hits} suspicious API references")
    if str_hits >= 2:
        out.append(f"{str_hits} suspicious string markers")
    if double_ext:
        out.append("double extension (disguised file type)")
    if mismatch:
        out.append("extension does not match file content")
    if not out:
        out.append("no strong static indicators observed")
    return out
