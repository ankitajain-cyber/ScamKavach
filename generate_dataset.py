import csv
import random

def generate_500_dataset():
    # Base templates for generating 500 varied payloads
    scam_templates = [
        ("Dear customer, your {bank} account has been suspended due to pending KYC verification. Update now: {url} or call {phone}", "Phishing"),
        ("TRAI/Police Alert: Your mobile numbers and broadband connections are reported for illegal money laundering. Arrest warrant issued: {url}", "Digital-Arrest"),
        ("SEBI Warning: Earn 500% returns in 3 days with our VIP IPO block trading app: {url}", "Phishing"),
        ("CBI Cyber Cell: Supreme Court has issued an interim custody warrant against your Aadhaar card. Join WhatsApp video call immediately: {url}", "Digital-Arrest"),
        ("HDFC Bank Alert: Your reward points worth Rs. 9,850 are expiring today. Redeem immediately at {url}", "Phishing"),
        ("Dear citizen, your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill. Contact officer at {phone}", "Phishing"),
        ("Income Tax Department: Refund of Rs. 24,500 is approved. Verify your bank account details via {url}", "Phishing")
    ]
    
    safe_templates = [
        ("Hey Ankit, are we still meeting at Connaught Place for coffee around 5 PM today?", "Safe"),
        ("Your Amazon order #402-91823 has shipped and will arrive tomorrow via Blue Dart.", "Safe"),
        ("Reminder: Your forensic science lab practical viva is scheduled for tomorrow morning at 10 AM.", "Safe"),
        ("Dad, please pick up some fresh milk and bread on your way back home from the university.", "Safe"),
        ("Your Uber OTP for the ride to Delhi University campus is 8492. Do not share it with anyone.", "Safe"),
        ("Hey! Check out this new short-form video concept for our project review meeting.", "Safe"),
        ("Your Zomato order from Biryani Blues has been delivered. Enjoy your meal!", "Safe")
    ]

    banks = ["SBI", "HDFC", "ICICI", "Axis Bank", "PNB", "Paytm Payments Bank"]
    urls = [
        "https://sbi-update-kyc.com", "https://hdfc-secure-auth.net", "https://trai-verify-portal.in",
        "https://cybercell-legal-notice.org", "https://sebi-vip-ipo.com", "https://income-tax-refund-portal.net"
    ]
    phones = ["+91-9876543210", "+91-8765432109", "+91-7654321098", "+91-9988776655"]

    dataset = []
    
    # Generate ~250 malicious / scam payloads
    while len(dataset) < 250:
        template, label = random.choice(scam_templates)
        msg = template.format(
            bank=random.choice(banks),
            url=random.choice(urls),
            phone=random.choice(phones)
        )
        dataset.append((msg, label))

    # Generate ~250 safe payloads
    while len(dataset) < 500:
        msg, label = random.choice(safe_templates)
        dataset.append((msg, label))

    # Shuffle dataset to mix safe and malicious entries randomly
    random.shuffle(dataset)

    # Write to CSV
    filename = "dataset_500.csv"
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["payload", "expected_label"])
        for payload, label in dataset:
            writer.writerow([payload, label])
            
    print(f"[+] Successfully generated '{filename}' with {len(dataset)} balanced records!")

if __name__ == "__main__":
    generate_500_dataset()