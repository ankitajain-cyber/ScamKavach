import re

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co)/[^\s<>\"']+",
    re.I,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
EMAIL_RE = re.compile(r"[\w.\-]+@[\w\-]+\.[\w.\-]+")
UPI_RE = re.compile(r"\b[\w.\-]{2,}@[a-z]{2,}(?!\w|\.[a-z])", re.I)


def _unique(items):
    seen = []
    for item in items:
        item = item.strip().rstrip(".,;:)")
        if item and item not in seen:
            seen.append(item)
    return seen


def extract_indicators(text):
    emails = _unique(EMAIL_RE.findall(text))
    upi = [u for u in _unique(UPI_RE.findall(text)) if not any(u in e for e in emails)]
    return {
        "Links": _unique(URL_RE.findall(text)),
        "Phone numbers": _unique(PHONE_RE.findall(text)),
        "UPI IDs": upi,
        "Emails": emails,
    }