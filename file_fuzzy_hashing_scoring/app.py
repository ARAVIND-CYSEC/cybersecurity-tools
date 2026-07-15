import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

APP_ROOT = Path(__file__).resolve().parent

MAX_FILE_BYTES = int(os.getenv("FUZZY_ANALYZER_MAX_FILE_BYTES", str(20 * 1024 * 1024)))

app = FastAPI(title="CyberShield File Fuzzy Hashing + Scoring", version="0.1.0")


def sha_hex(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def detect_magic(data: bytes) -> Optional[str]:
    if data.startswith(b"MZ"):
        return "PE (MZ)"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "ZIP"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "GIF"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith(b"RIFF") and b"WEBP" in data[:32]:
        return "WEBP"
    return None


def extract_strings(data: bytes, min_len: int = 6, limit: int = 25) -> List[str]:
    # ASCII printable strings
    try:
        text = data.decode("latin-1", errors="ignore")
    except Exception:
        return []
    # Keep only somewhat realistic strings
    candidates = re.findall(r"[A-Za-z0-9_\-./]{%d,}" % min_len, text)
    # Deduplicate but keep order
    seen = set()
    out = []
    for s in candidates:
        s2 = s.strip()
        if not s2 or s2 in seen:
            continue
        if len(s2) < min_len:
            continue
        seen.add(s2)
        out.append(s2)
        if len(out) >= limit:
            break
    return out


def compute_fuzzy_hashes(_data: bytes) -> Dict[str, Optional[str]]:
    """Best-effort fuzzy hashing.

    This project does not vendor ssdeep/tlsh dependencies.
    We attempt to import them; if unavailable, we return nulls and keep scoring heuristic-only.
    """
    out: Dict[str, Optional[str]] = {"ssdeep": None, "tlsh": None}

    # ssdeep
    try:
        import ssdeep  # type: ignore

        out["ssdeep"] = ssdeep.hash(_data)
    except Exception:
        pass

    # tlsh
    try:
        import tlsh  # type: ignore

        # tlsh expects bytes
        out["tlsh"] = tlsh.hash(_data) if len(_data) > 0 else None
    except Exception:
        pass

    return out


def similarity_from_fuzzy(h1: Optional[str], h2: Optional[str]) -> Optional[int]:
    if not h1 or not h2:
        return None

    # ssdeep similarity
    if isinstance(h1, str) and isinstance(h2, str):
        try:
            import ssdeep  # type: ignore

            if len(h1) > 0 and len(h2) > 0:
                return int(ssdeep.compare(h1, h2))
        except Exception:
            pass

    # tlsh similarity
    try:
        import tlsh  # type: ignore

        # tlsh.diff returns int
        if tlsh.is_valid(h1) and tlsh.is_valid(h2):
            return int(tlsh.diff(h1, h2))
    except Exception:
        pass

    return None


def score_artifact(
    magic: Optional[str],
    entropy: float,
    strings: List[str],
    fuzzy: Dict[str, Optional[str]],
) -> Tuple[int, str, List[str]]:
    score = 0
    reasons: List[str] = []

    if magic in {"PE (MZ)", "ELF"}:
        score += 25
        reasons.append(f"Executable-like magic detected: {magic}")
    elif magic in {"PDF", "ZIP", "PNG", "JPEG", "GIF", "WEBP"}:
        score += 10
        reasons.append(f"Container/type magic detected: {magic}")

    # Entropy heuristic: packed/obfuscated often higher
    if entropy >= 7.2:
        score += 30
        reasons.append(f"High Shannon entropy: {entropy:.2f}")
    elif entropy >= 6.0:
        score += 15
        reasons.append(f"Medium Shannon entropy: {entropy:.2f}")

    # String signals (empty or lots of short gibberish)
    if len(strings) == 0 and magic in {"PE (MZ)", "ELF"}:
        score += 20
        reasons.append("No readable strings extracted; may indicate packing")
    elif len(strings) > 0:
        # suspicious keywords
        joined = "\n".join(strings).lower()
        suspicious_markers = [
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "wget",
            "curl",
            "http://",
            "https://",
            "base64",
            "pastebin",
            "telegram",
            "discord",
            "procmon",
        ]
        hits = [m for m in suspicious_markers if m in joined]
        if hits:
            score += min(35, 5 * len(hits))
            reasons.append(f"Suspicious strings/IOCs observed: {sorted(set(hits))[:5]}")
        else:
            score += 5
            reasons.append(f"Extracted {len(strings)} strings")

    # Fuzzy hashes presence: if computed, boost confidence
    if fuzzy.get("ssdeep"):
        score += 10
        reasons.append("SSDEEP fuzzy hash computed")
    if fuzzy.get("tlsh"):
        score += 10
        reasons.append("TLSH fuzzy hash computed")

    # cap and band
    score = max(0, min(100, score))
    band = "high" if score >= 70 else "medium" if score >= 35 else "low"
    return score, band, reasons


@app.post("/analyze", response_class=JSONResponse)
async def analyze_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="File must have a name")

    # Size guard: read incrementally
    data = bytearray()
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large (>{MAX_FILE_BYTES} bytes)")
        data.extend(chunk)

    raw = bytes(data)

    sha1 = sha_hex(raw, "sha1")
    sha256 = sha_hex(raw, "sha256")

    magic = detect_magic(raw)
    ent = shannon_entropy(raw)
    strings = extract_strings(raw)
    fuzzy = compute_fuzzy_hashes(raw)

    score, band, reasons = score_artifact(magic, ent, strings, fuzzy)

    return {
        "artifact": {
            "fileName": file.filename,
            "fileSize": len(raw),
        },
        "hashes": {
            "sha1": sha1,
            "sha256": sha256,
            "ssdeep": fuzzy.get("ssdeep"),
            "tlsh": fuzzy.get("tlsh"),
        },
        "structure": {
            "magic": magic,
            "entropy": ent,
            "strings": {
                "count": len(strings),
                "sample": strings,
            },
        },
        "behavior": {
            "notes": [
                "Behavior scoring is heuristic-only in this phase (sandbox detonation for files can be added later)."
            ],
            "detonation": {"performed": False},
        },
        "scoring": {
            "score": score,
            "band": band,
            "reasons": reasons,
        },
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "file-fuzzy-analyzer"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8011")))

