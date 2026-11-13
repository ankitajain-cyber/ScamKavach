def analyze_kill_chain_sequence(message_history):
    """
    Analyzes a sequence of messages or an extended transcript 
    to track social engineering psychological kill-chain progression.
    """
    stages = [
        {
            "stage_num": 1,
            "stage_name": "Rapport Building & Hook",
            "keywords": ["dear customer", "dear citizen", "hello sir", "updates", "verification", "kyc", "linked"],
            "tactic_explanation": "Establishing initial fake legitimacy or friendly premise to lower cognitive skepticism."
        },
        {
            "stage_num": 2,
            "stage_name": "Authority Bias & Manufactured Urgency",
            "keywords": ["urgent", "police", "trai", "supreme court", "cyber cell", "rbi", "sebi", "blocked", "suspend", "arrest warrant"],
            "tactic_explanation": "Leveraging institutional fear, legal intimidation, and severe deadlines to induce panic."
        },
        {
            "stage_num": 3,
            "stage_name": "Isolation & Secrecy Enforcement",
            "keywords": ["strictly prohibited", "do not disconnect", "keep this confidential", "don't tell anyone", "video call", "whatsapp call"],
            "tactic_explanation": "Cutting off the victim from external reality, family, or real banking support to prevent reality-checking."
        },
        {
            "stage_num": 4,
            "stage_name": "Financial Coercion & Asset Extortion",
            "keywords": ["transfer", "security deposit", "safe custody", "upi", "qr code", "rtgs", "rs.", "amount", "verify account"],
            "tactic_explanation": "Final monetization phase demanding immediate monetary transfer under threat of legal ruin."
        }
    ]

    text_lower = message_history.lower()
    timeline = []
    detected_count = 0

    for stage in stages:
        matched_words = [kw for kw in stage["keywords"] if kw in text_lower]
        is_detected = len(matched_words) > 0
        if is_detected:
            detected_count += 1
            
        timeline.append({
            "stage_name": stage["stage_name"],
            "tactic_explanation": stage["tactic_explanation"],
            "detected": is_detected,
            "exact_quote": f"Matched indicators: {', '.join(matched_words)}" if matched_words else "No pattern trigger in buffer"
        })

    is_active_kill_chain = detected_count >= 2
    return {
        "is_kill_chain_active": is_active_kill_chain,
        "progression_score": int((detected_count / len(stages)) * 100),
        "timeline": timeline
    }