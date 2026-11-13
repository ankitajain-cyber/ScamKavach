import re

# (name, points, patterns), matched against lowercase text
RULES = [
    ("Contains a link", 15,
     [r"https?://", r"www\.", r"\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co)/"]),
    ("Asks for OTP / PIN / CVV", 25,
     [r"\botp\b", r"\bpin\b", r"\bcvv\b", "ओटीपी", "पिन"]),
    ("Urgency", 15,
     [r"\burgent", r"\bimmediately\b", r"\bright now\b", r"\bwithin 24 hours\b",
      r"\babhi\b", r"\bturant\b", r"\bjaldi\b", "तुरंत", "अभी", "आज ही", "फौरन"]),
    ("Fake authority", 20,
     [r"\bcbi\b", r"\bpolice\b", r"\brbi\b", r"\bcustoms\b", r"\bnarcotics\b",
      r"\btrai\b", r"\bincome tax\b", r"\bcyber ?crime\b", "सीबीआई", "पुलिस",
      "आरबीआई", "कस्टम", "नारकोटिक्स"]),
    ("Threat / fear", 20,
     [r"\barrest", r"\bblock", r"\bsuspend", r"\blegal action\b", r"\bwarrant\b",
      r"band ho", "गिरफ्तार", "ब्लॉक", "बंद हो", "जेल", "वारंट"]),
    ("Payment demand", 20,
     [r"\bfee\b", r"\btransfer\b", r"\bsend money\b", r"\brupay", r"\bpaise\b",
      "पैसे", "ट्रांसफर", "शुल्क", "जमा"]),
    ("Secrecy / isolation", 15,
     [r"don'?t tell", r"do not tell", r"keep (?:this )?secret", r"kisi ko (?:na|mat) bata",
      "किसी को न बताएं", "किसी को मत बताना", "गोपनीय"]),
    ("Prize / lottery bait", 15,
     [r"\blottery\b", r"\bprize\b", r"\bcongratulations\b", r"\bjeeta\b",
      "लॉटरी", "इनाम", "जीता"]),
    ("Asks for sensitive ID / KYC", 20,
     [r"\baadhaar\b", r"\baadhar\b", r"\bpan card\b", r"\bkyc\b", r"\bupi\b",
      "आधार", "केवाईसी"]),
]


def check_rules(text):
    lowered = text.lower()
    hits = []
    score = 0
    for name, points, patterns in RULES:
        for pattern in patterns:
            match = re.search(pattern, lowered)
            if match:
                hits.append((name, match.group(0)))
                score += points
                break
    return {"score": min(score, 100), "hits": hits}