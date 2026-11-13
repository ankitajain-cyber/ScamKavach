import hashlib
import re

_OTP = re.compile(r"(?i)(\b(?:otp|code|pin|cvv)\b[^\d\n]{0,25})(\d{4,8})\b")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_PHONE = re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")


def text_key(text):
    """Cache key: SHA-256 of the stripped text."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def mask_sensitive(text):
    """Hide sensitive numbers before the text goes to the AI. Returns (masked_text, counts)."""
    counts = {}
    out = text

    out, n = _OTP.subn(lambda m: m.group(1) + "[OTP]", out)
    if n:
        counts["OTP / PIN codes"] = n
    for pattern, token, name in (
        (_CARD, "[CARD_NUMBER]", "Card-like numbers"),
        (_AADHAAR, "[AADHAAR]", "Aadhaar-like numbers"),
        (_PHONE, "[PHONE]", "Phone numbers"),
        (_PAN, "[PAN]", "PAN numbers"),
    ):
        out, n = pattern.subn(token, out)
        if n:
            counts[name] = n
    return out, counts