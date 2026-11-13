import time
from analyzer import analyze_message
from rules import check_rules

# (message, is_scam). All fictional.
TESTS = [
    # Scams
    ("Aapka SBI account block ho jayega. Abhi KYC update karein: bit.ly/sbi-kyc", True),
    ("आपका बैंक खाता आज बंद हो जाएगा। तुरंत OTP भेजें।", True),
    ("मैं CBI अधिकारी बोल रहा हूँ। आपके नाम पर पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं, किसी को न बताएं और तुरंत पैसे ट्रांसफर करें।", True),
    ("Congratulations! Aapne 25 lakh ka lottery jeeta hai. Claim karne ke liye 5000 rupay processing fee bhejein.", True),
    ("Work from home job! Earn Rs 5000 daily. Pay Rs 999 registration fee on UPI to start today.", True),
    ("Your electricity will be disconnected tonight. Call 98XXXXXX10 now and pay the pending bill via this link: http://pay-bijli.xyz", True),
    ("Invest 10,000 today and get 50,000 in 7 days. Guaranteed returns. Join our WhatsApp group now.", True),
    ("Aapka courier customs mein ruka hai. Police case ho sakta hai. Turant 8000 rupay transfer karein.", True),
    ("आपने इनाम जीता है! अपना आधार और बैंक डिटेल भेजें और 2000 रुपये शुल्क जमा करें।", True),
    ("Dear customer, your PAN is not linked. Update immediately at www.pan-update.in or account will be suspended.", True),
    # Safe
    ("Hi, are we still meeting at 5 pm?", False),
    ("कल शाम 5 बजे मीटिंग है, कृपया समय पर आ जाइए।", False),
    ("Bhai, aaj raat dinner ke liye bahar chalein? Mai 8 baje tak ready ho jaunga.", False),
    ("Your OTP for login is 482913. Do not share it with anyone.", False),
    ("Your Swiggy order has been delivered. Rate your experience in the app.", False),
    ("मम्मी का फोन आया था, वो पूछ रही थीं कि आप रविवार को घर आ रहे हैं या नहीं।", False),
    ("Reminder: your electricity bill of Rs 840 is due on 15 Nov. Pay on the official app or at the counter.", False),
    ("Assignment ki deadline Friday tak badh gayi hai. Notes group mein daal diye hain.", False),
    ("Your flight 6E 204 departs at 7:45 pm from Gate 12. Boarding starts 40 minutes before.", False),
    ("Happy birthday! Chai pe milte hain kal, meri taraf se treat.", False),
]


def analyze_with_retry(text, tries=4):
    result = {}
    for t in range(tries):
        result = analyze_message(text)
        if "error" not in result:
            return result
        if "429" in result["error"] or "RESOURCE_EXHAUSTED" in result["error"]:
            wait = 30 * (t + 1)
            print(f"   rate limit, waiting {wait}s...")
            time.sleep(wait)
        else:
            return result
    return result


ai_ok = combined_ok = done = 0
wrong = []

for i, (text, is_scam) in enumerate(TESTS, 1):
    result = analyze_with_retry(text)
    if "error" in result:
        print(f"{i}: ERROR {result['error'][:80]}")
        continue
    done += 1
    label = result.get("label", "Unknown")
    conf = int(result.get("confidence", 0))
    rules = check_rules(text)
    ai_risk = conf if label != "Safe" else 100 - conf
    final = round(0.6 * ai_risk + 0.4 * rules["score"])

    ai_pred = label != "Safe"
    combined_pred = final >= 50
    ai_ok += ai_pred == is_scam
    combined_ok += combined_pred == is_scam
    if ai_pred != is_scam or combined_pred != is_scam:
        wrong.append((i, text[:60], is_scam, label, final))
    print(f"{i:2d} truth={'SCAM' if is_scam else 'SAFE'}  ai={label}  risk={final}")
    time.sleep(13)

n = done
print(f"\nCompleted tests: {done}/{len(TESTS)}")
if n:
    print(f"AI only accuracy:  {ai_ok}/{n} = {round(100 * ai_ok / n)}%")
    print(f"AI + rules:        {combined_ok}/{n} = {round(100 * combined_ok / n)}%")
print("\nWrong cases:")
for w in wrong:
    print(w)
    