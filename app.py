import hashlib
import html
import io
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import streamlit as st
import streamlit.components.v1 as components

from analyzer import analyze_message
from examples import EXAMPLES
from indicators import extract_indicators
from masking import mask_sensitive, text_key
from report import build_report_html
from rules import check_rules

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    HAS_PDF = True
except ImportError:
    HAS_PDF = False

APP_NAME = "ScamKavach"
MAX_LIVE_SCANS = 10      # live AI scans per browser session
MAX_CHARS = 10_000

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title=f"{APP_NAME} | AI Safety Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- THEME ---
theme_css = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, .stApp { font-family: 'Plus Jakarta Sans', sans-serif; }
    .stApp {
        background: linear-gradient(180deg, #EEF2FF 0%, #F8FAFC 260px) !important;
        color: #334155 !important;
    }
    .block-container { padding-top: 1.2rem !important; max-width: 1280px; }
    #MainMenu, footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent; }

    h1, h2, h3, h4, h5, h6 {
        color: #0F172A; font-weight: 700 !important; letter-spacing: -0.01em;
    }

    /* cards */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background: #FFFFFF;
        border: 1px solid #E2E8F0 !important;
        border-radius: 16px !important;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06);
    }
    div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stVerticalBlockBorderWrapper"] {
        box-shadow: none; border-radius: 10px !important;
    }

    /* input */
    .stTextArea textarea {
        background: #FFFFFF !important;
        border: 1.5px solid #CBD5E1 !important;
        border-radius: 12px !important;
        font-size: 1.02rem !important;
        color: #1E293B !important;
    }
    .stTextArea textarea:focus {
        border-color: #4F46E5 !important;
        box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15) !important;
    }

    /* buttons */
    button[kind="primary"], button[data-testid="stBaseButton-primary"] {
        background: linear-gradient(135deg, #4F46E5 0%, #3730A3 100%) !important;
        color: #FFFFFF !important; border: none !important;
        font-weight: 600; border-radius: 10px !important;
        box-shadow: 0 4px 10px rgba(79, 70, 229, 0.35);
    }
    button[kind="secondary"], button[data-testid="stBaseButton-secondary"] {
        background: #FFFFFF !important; color: #334155 !important;
        border: 1.5px solid #CBD5E1 !important;
        font-weight: 600; border-radius: 10px !important;
    }
    button[kind="secondary"]:hover, button[data-testid="stBaseButton-secondary"]:hover {
        border-color: #4F46E5 !important; color: #4F46E5 !important;
    }

    /* metrics */
    div[data-testid="stMetric"], div[data-testid="metric-container"] {
        background: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 12px !important;
        padding: 14px 16px !important;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
    }

    /* tabs as pills */
    div[data-baseweb="tab-list"] { gap: 6px; border-bottom: none !important; }
    button[data-baseweb="tab"] {
        background: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 999px !important;
        padding: 6px 16px !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: #4F46E5 !important; border-color: #4F46E5 !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] div p {
        color: #FFFFFF !important; font-weight: 700 !important;
    }
    div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] { display: none; }

    /* hero */
    .hero-container {
        background: linear-gradient(120deg, #0F172A 0%, #1E3A8A 55%, #4F46E5 100%) !important;
        padding: 1.8rem 2rem !important;
        border-radius: 18px !important;
        margin-bottom: 0.8rem !important;
        box-shadow: 0 12px 28px -10px rgba(30, 58, 138, 0.55) !important;
    }
    .hero-title {
        color: #FFFFFF !important; margin: 0 0 0.3rem 0 !important;
        font-size: 2.2rem !important; font-weight: 800 !important;
    }
    .hero-subtitle {
        color: #E0E7FF !important; font-size: 1.05rem !important;
        margin: 0 0 0.9rem 0 !important;
    }
    .pill {
        display: inline-block; background: rgba(255, 255, 255, 0.14); color: #FFFFFF;
        border: 1px solid rgba(255, 255, 255, 0.25); padding: 3px 12px;
        border-radius: 999px; font-size: 0.8rem; font-weight: 600; margin: 0 8px 4px 0;
    }

    /* verdict card with risk ring */
    .risk-card {
        display: flex; align-items: center; gap: 20px;
        padding: 1.2rem 1.4rem; border-radius: 14px; margin-bottom: 1.2rem;
    }
    .risk-ring {
        width: 92px; height: 92px; border-radius: 50%; flex-shrink: 0;
        display: flex; align-items: center; justify-content: center;
    }
    .risk-ring-inner {
        width: 70px; height: 70px; border-radius: 50%; background: #FFFFFF;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    </style>
"""
st.markdown(theme_css, unsafe_allow_html=True)

# Ticking clock (runs in the browser, no server load). Report times use the server clock.
CLOCK_HTML = """
<div style="font-family:'Segoe UI',Arial,sans-serif;display:flex;gap:28px;align-items:center;
            background:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;padding:8px 16px;color:#0F172A;">
  <div><div style="font-size:11px;color:#64748B;letter-spacing:1px;">UTC TIME</div>
       <div id="utc" style="font-size:20px;font-weight:700;"></div></div>
  <div><div style="font-size:11px;color:#64748B;letter-spacing:1px;">IST TIME</div>
       <div id="ist" style="font-size:20px;font-weight:700;"></div></div>
</div>
<script>
function p(n){return String(n).padStart(2,'0');}
function fmt(d){
  return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+'  '+
         p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());
}
function tick(){
  var d=new Date();
  document.getElementById('utc').textContent=fmt(d);
  document.getElementById('ist').textContent=fmt(new Date(d.getTime()+19800000));
}
tick(); setInterval(tick,1000);
</script>
"""


# --- BACKEND CORE FUNCTIONS ---
def generate_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_iocs(text):
    text = text or ""
    found = extract_indicators(text)
    ips = re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text,
    )
    return {
        "urls": found["Links"],
        "phones": found["Phone numbers"],
        "upis": found["UPI IDs"],
        "emails": found["Emails"],
        "ips": list(dict.fromkeys(ips)),
    }


def parse_and_analyze_chat(transcript):
    """Keyword-based (not AI) detection of scam stages in a chat log."""
    lines = [line.strip() for line in transcript.split("\n") if line.strip()]
    stages = [
        {"stage_num": 1, "stage_name": "Phase 1: Building Fake Trust",
         "keywords": ["dear customer", "dear citizen", "hello sir", "updates", "verification", "kyc", "linked", "blocked", "sim card"]},
        {"stage_num": 2, "stage_name": "Phase 2: Creating Panic",
         "keywords": ["urgent", "police", "trai", "supreme court", "cyber cell", "rbi", "sebi", "suspend", "arrest warrant", "investigation"]},
        {"stage_num": 3, "stage_name": "Phase 3: Forcing Isolation",
         "keywords": ["strictly prohibited", "do not disconnect", "keep this confidential", "don't tell anyone", "video call", "whatsapp call", "private"]},
        {"stage_num": 4, "stage_name": "Phase 4: Financial Demand",
         "keywords": ["transfer", "security deposit", "safe custody", "upi", "qr code", "rtgs", "rs.", "amount", "verify account", "deposit"]},
    ]
    lowered = transcript.lower()
    breakdown = []
    max_stage = 0
    for stage in stages:
        matched = [kw for kw in stage["keywords"] if kw in lowered]
        triggered = bool(matched)
        if triggered:
            max_stage = max(max_stage, stage["stage_num"])
        breakdown.append(
            {
                "stage_name": stage["stage_name"],
                "status": "TRIGGERED" if triggered else "INACTIVE",
                "indicators": matched,
            }
        )
    return {
        "total_turns": len(lines),
        "max_stage_reached": max_stage,
        "kill_chain_breakdown": breakdown,
    }


def pdf_safe(text):
    """The built-in PDF fonts can't show Hindi; replace unsupported characters."""
    return str(text).encode("cp1252", "replace").decode("cp1252")


def generate_pdf_dossier(analyzed_str, generated_str, result, final_risk, msg_hash, raw_message, rules, iocs):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    def esc(value):
        return html.escape(pdf_safe(value))

    def joined(items):
        return esc(", ".join(items)) if items else "None"

    story = [
        Paragraph(f"<b>{esc(APP_NAME)} | AI Safety Report</b>", styles["Heading1"]),
        Paragraph(f"<b>Message analyzed at:</b> {esc(analyzed_str)} UTC", styles["Normal"]),
        Paragraph(f"<b>Report generated at:</b> {esc(generated_str)} UTC", styles["Normal"]),
        Paragraph(
            f"<b>Source:</b> {esc(result.get('_source', 'live AI'))} | "
            f"<b>Model:</b> {esc(result.get('_model', ''))}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Classification:</b> {esc(str(result.get('label', 'Unknown')).upper())} | "
            f"<b>Risk score:</b> {final_risk}/100",
            styles["Normal"],
        ),
        Paragraph(f"<b>SHA-256 of submitted text:</b> <font name='Courier'>{msg_hash}</font>", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("<b>Message analyzed</b>", styles["Heading2"]),
        Paragraph(esc(raw_message).replace("\n", "<br/>"), styles["Normal"]),
        Spacer(1, 12),
        Paragraph("<b>Explanation (English)</b>", styles["Heading2"]),
        Paragraph(esc(result.get("explanation_en", "")), styles["Normal"]),
        Spacer(1, 6),
        Paragraph(f"<b>Advice:</b> {esc(result.get('advice_en', ''))}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("<b>Red flags</b>", styles["Heading2"]),
        Paragraph(
            "<br/>".join(f"• {esc(f)}" for f in result.get("red_flags", [])) or "None detected",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("<b>Rule-based checks that fired</b>", styles["Heading2"]),
        Paragraph(
            "<br/>".join(f"• {esc(n)} (found: {esc(m)})" for n, m in rules["hits"]) or "None",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("<b>Extracted indicators</b>", styles["Heading2"]),
        Paragraph(
            f"<b>Links:</b> {joined(iocs['urls'])}<br/>"
            f"<b>Phones:</b> {joined(iocs['phones'])}<br/>"
            f"<b>UPI IDs:</b> {joined(iocs['upis'])}<br/>"
            f"<b>Emails:</b> {joined(iocs['emails'])}<br/>"
            f"<b>IP addresses:</b> {joined(iocs['ips'])}",
            styles["Normal"],
        ),
        Spacer(1, 16),
        Paragraph(
            "<i>Note: this PDF cannot display Hindi or other non-Latin scripts (shown as '?'). "
            "Use the HTML report for the full English + Hindi version. Times are from the app's "
            "server clock (UTC). The hash covers the exact text entered into the tool; it does not "
            "prove the original message is authentic. Automated preliminary assessment. "
            "Not legal advice.</i>",
            styles["Italic"],
        ),
    ]
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


# --- LIVE NEWS (auto-refreshing, news sites only) ---
NEWS_QUERIES = [
    "cyber+scam+OR+phishing+OR+%22digital+arrest%22+India+when:7d",
    "cyber+scam+OR+phishing+OR+digital+arrest+India",
]
BLOCKED_SOURCES = ("facebook", "youtube", "instagram", "twitter", "reddit", "quora", "x.com")

SAFETY_TIPS = [
    "Police, CBI or courts never ask for money over a call or video call to 'close a case'.",
    "Never share an OTP, PIN or CVV with anyone, even someone claiming to be your bank.",
    "Lost money to fraud? Call 1930 immediately and report at cybercrime.gov.in.",
]


@st.cache_data(ttl=240, show_spinner=False)
def get_live_news():
    items = []
    for query in NEWS_QUERIES:
        url = f"https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=4) as response:
                root = ET.fromstring(response.read())
            seen = set()
            for item in root.findall(".//item"):
                link = item.findtext("link") or ""
                if not link.startswith("http") or link in seen:
                    continue
                seen.add(link)
                source = item.findtext("source") or "Google News"
                if any(b in source.lower() for b in BLOCKED_SOURCES):
                    continue
                try:
                    dt = parsedate_to_datetime(item.findtext("pubDate") or "").astimezone(timezone.utc)
                except Exception:
                    dt = None
                items.append(
                    {
                        "headline": item.findtext("title") or "News",
                        "source": source,
                        "dt": dt,
                        "url": link,
                    }
                )
        except Exception:
            continue
        if items:
            break
    items.sort(key=lambda x: x["dt"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return {"items": items[:20], "fetched_at": datetime.now(timezone.utc), "live": bool(items)}


@st.fragment(run_every=300)
def news_panel():
    with st.container(border=True):
        st.markdown(
            "<p style='font-weight: 700; color: #0F172A; margin-bottom: 4px;'>📡 Live Scam News Feed</p>",
            unsafe_allow_html=True,
        )
        if st.button("🔄 Refresh now", use_container_width=True, key="refresh_news"):
            get_live_news.clear()
        data = get_live_news()

        if data["live"]:
            st.caption(
                f"Updated {data['fetched_at'].strftime('%H:%M:%S')} UTC | auto-refreshes every 5 minutes | "
                "source: Google News"
            )
        else:
            st.warning("Couldn't reach Google News right now. Showing general safety tips instead.")

        feed_search = st.text_input("🔍 Search headlines:", placeholder="Keyword...", key="feed_srch")
        needle = feed_search.lower().strip()

        with st.container(height=480):
            if data["live"]:
                shown = [i for i in data["items"] if needle in i["headline"].lower()] if needle else data["items"]
                st.caption(f"Showing {len(shown)} headlines, newest first")
                for item in shown:
                    st.markdown(f"**{item['headline']}**")
                    when = item["dt"].strftime("%d %b, %H:%M UTC") if item["dt"] else "date unknown"
                    st.caption(f"{item['source']} | {when}")
                    st.link_button("🔗 Read", url=item["url"], use_container_width=True)
                    st.divider()
            else:
                for tip in SAFETY_TIPS:
                    st.markdown(f"- {tip}")


# --- ANALYSIS PIPELINE: examples -> cache -> limit -> AI -> rules-only fallback ---
@st.cache_resource
def saved_examples():
    try:
        with open(os.path.join(BASE_DIR, "examples_cache.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


@st.cache_resource
def runtime_cache():
    return {}


def rules_only_result(text, reason, detail=""):
    rules = check_rules(text)
    score = rules["score"]
    suspicious = score >= 40
    return {
        "label": "Suspicious (rules only)" if suspicious else "No strong rule-based signs",
        "confidence": 0,
        "red_flags": [m for _, m in rules["hits"]],
        "explanation_en": (
            f"{reason} This result comes only from rule-based checks (known scam patterns), so it is "
            "less reliable than the full AI analysis. "
            + ("Several scam patterns were found." if suspicious else
               "Few or no known scam patterns were found, which does not prove the message is safe.")
        ),
        "explanation_hi": (
            "AI अभी उपलब्ध नहीं है, इसलिए यह नतीजा सिर्फ़ नियम-आधारित जाँच (जाने-पहचाने स्कैम पैटर्न) "
            "से है और कम भरोसेमंद है। "
            + ("कई स्कैम के संकेत मिले हैं।" if suspicious else
               "ज़्यादा संकेत नहीं मिले, पर इससे संदेश के सुरक्षित होने की गारंटी नहीं है।")
        ),
        "advice_en": "Do not click links or share OTPs or PINs. Verify through the official app or number.",
        "advice_hi": "लिंक पर क्लिक न करें, OTP या पिन साझा न करें, और आधिकारिक ऐप या नंबर से जाँच करें।",
        "_model": "rules-only (AI unavailable)",
        "_seconds": 0.0,
        "_source": "rules only",
        "_fallback": True,
        "_detail": detail,
    }


def run_analysis(text):
    text = text.strip()
    if len(text) > MAX_CHARS:
        return {"error": f"Message is too long. Limit it to {MAX_CHARS} characters."}

    key = text_key(text)

    saved = saved_examples().get(key)
    if saved:
        return {**saved, "_seconds": 0.0, "_source": "saved example"}

    cache = runtime_cache()
    if key in cache:
        return {**cache[key], "_seconds": 0.0, "_source": "cache"}

    if st.session_state["live_scans"] >= MAX_LIVE_SCANS:
        return rules_only_result(
            text, f"You have used all {MAX_LIVE_SCANS} live AI scans for this session."
        )

    masked, _ = mask_sensitive(text)
    st.session_state["live_scans"] += 1
    output = analyze_message(masked)
    if "error" in output:
        return rules_only_result(
            text, "The AI service is busy or unavailable right now.", detail=output["error"]
        )

    output["_source"] = "live AI"
    cache[key] = dict(output)
    return output


# --- SESSION STATE ---
defaults = {
    "message": "",
    "result": None,
    "audit_log": [],
    "analyzed_payload": "",
    "analyzed_at": None,
    "live_scans": 0,
    "example_choice": "-- choose an example --",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


def clear_text():
    st.session_state["message"] = ""
    st.session_state["result"] = None
    st.session_state["analyzed_payload"] = ""
    st.session_state["analyzed_at"] = None


def load_example():
    name = st.session_state.get("example_choice")
    if name in EXAMPLES:
        st.session_state["message"] = EXAMPLES[name]


# --- SIDEBAR ---
with st.sidebar:
    st.markdown(f"### {APP_NAME} Core")
    st.markdown("Helping everyday users check suspicious messages and report them with proof.")
    st.divider()

    st.markdown("#### 🤖 AI Model Transparency")
    st.info(
        "**• Hybrid design:** an AI model reads the message in context, and a separate "
        "rule-based checker looks for known scam patterns. The scores are combined.\n\n"
        "**• Explainability:** every verdict shows red-flag phrases quoted from your message "
        "plus an English and Hindi explanation.\n\n"
        "**• Privacy:** phone, Aadhaar-like, card, PAN numbers and OTP codes are masked before the "
        "text is sent to Google's Gemini API. Masking is pattern-based and can miss things, so "
        "don't paste sensitive personal data. Results for identical messages are cached in "
        "server memory (the message text itself is not stored).\n\n"
        "**• Fallback:** if the AI is busy, you still get a rule-based result, clearly labelled.\n\n"
        "**• Limitations:** results can be wrong, especially for short or ambiguous messages "
        "and languages we haven't tested. Not legal advice."
    )
    with st.expander("📊 Evaluation (small test set)"):
        st.markdown(
            "Tested on **30 hand-written fictional messages** (Hindi, Hinglish, English): "
            "**29/30 correct**, 15/15 scams caught, 1 false alarm (a promotional SMS rated Medium).\n\n"
            "This is a tiny test set, so results are indicative only. It was measured before "
            "privacy masking was added. Tamil, Bengali and other languages are not tested."
        )
    with st.expander("🕒 Recent scans (this session only)"):
        if st.session_state["audit_log"]:
            for entry in st.session_state["audit_log"][:10]:
                st.write(f"{entry['time']} UTC | {entry['verdict']} | {entry['source']} | {entry['snippet']}")
        else:
            st.caption("No scans yet.")
    st.caption(f"Live AI scans used: {st.session_state['live_scans']}/{MAX_LIVE_SCANS}")
    st.divider()
    st.caption("v1.2 // AI Safety & Evidence Prototype")

# --- HERO + CLOCK ---
st.markdown(
    f"""
<div class="hero-container">
    <h1 class="hero-title">🛡️ {APP_NAME}</h1>
    <p class="hero-subtitle">Check it in 5 seconds. Report it with proof.</p>
    <span class="pill">हिन्दी • English • Hinglish</span>
    <span class="pill">AI + rule-based checks</span>
    <span class="pill">Evidence report</span>
</div>
""",
    unsafe_allow_html=True,
)
components.html(CLOCK_HTML, height=70)

# --- MAIN SPLIT LAYOUT ---
col_main_left, col_main_right = st.columns([1, 2.5])

with col_main_left:
    news_panel()

with col_main_right:
    with st.container(border=False):
        st.markdown("### AI Threat Intelligence Gateway")
        st.markdown(
            "<p style='color: #64748B;'>Paste a suspicious SMS, email, or chat. The AI will extract "
            "indicators, explain the manipulation tactics, and prepare a report you can use to file a complaint.</p>",
            unsafe_allow_html=True,
        )

        st.selectbox(
            "Try an example (fictional messages):",
            ["-- choose an example --"] + list(EXAMPLES.keys()),
            key="example_choice",
            on_change=load_example,
        )

        raw_message = st.text_area(
            "Message Input:",
            key="message",
            height=140,
            placeholder="e.g., 'URGENT: Your bank account is suspended. Click here to update KYC within 24 hours...'",
            label_visibility="collapsed",
        )
        st.caption(f"{len(raw_message)} characters")

        c1, c2, c3 = st.columns([4, 2, 2])
        analyze_clicked = c1.button("✨ Execute AI Safety Scan", type="primary", use_container_width=True)
        c2.button("Clear Text", on_click=clear_text, use_container_width=True)

    if analyze_clicked:
        if not raw_message.strip():
            st.session_state["result"] = None
            st.toast("Input is empty.", icon="⚠️")
        else:
            with st.status("Analyzing...", expanded=True) as status:
                st.write("Hiding sensitive numbers and running rule-based checks...")
                st.write("Asking the AI model to analyze the message...")
                output = run_analysis(raw_message)
                st.session_state["result"] = output
                st.session_state["analyzed_payload"] = raw_message
                st.session_state["analyzed_at"] = datetime.now(timezone.utc)
                status.update(label="Analysis complete", state="complete", expanded=False)

            res = st.session_state["result"]
            if "error" not in res:
                st.session_state["audit_log"].insert(
                    0,
                    {
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "verdict": str(res.get("label", "Unknown")).upper(),
                        "source": res.get("_source", ""),
                        "snippet": raw_message[:35] + "..." if len(raw_message) > 35 else raw_message,
                    },
                )

    st.write("")

    # --- COMPUTE SCORES ONCE ---
    result = st.session_state["result"]
    payload = st.session_state["analyzed_payload"]
    analyzed_at = st.session_state["analyzed_at"]
    ok = bool(result) and "error" not in result

    if ok:
        fallback = bool(result.get("_fallback"))
        label = result.get("label", "Unknown")
        rules = check_rules(payload)
        valid_rule_score = max(0, min(100, rules.get("score", 0)))
        if fallback:
            confidence = 0
            ai_risk = 0
            final_risk = valid_rule_score
        else:
            confidence = max(0, min(100, int(result.get("confidence", 0))))
            ai_risk = confidence if label != "Safe" else 100 - confidence
            final_risk = max(0, min(100, round(0.6 * ai_risk + 0.4 * valid_rule_score)))

        if final_risk >= 70:
            level_str, banner_color, text_color, icon = "High Risk: Likely a Scam", "#FEF2F2", "#991B1B", "🛑"
            subtext = "Strong scam signs found. Do not reply, click links, or share OTPs."
            level_short = "High"
        elif final_risk >= 40:
            level_str, banner_color, text_color, icon = "Moderate Risk", "#FFFBEB", "#92400E", "⚠️"
            subtext = "Suspicious signs detected. Verify through the official app or number before acting."
            level_short = "Medium"
        else:
            level_str, banner_color, text_color, icon = "Low Risk Indicators", "#F0FDF4", "#166534", "✅"
            subtext = "No strong scam signs found, but this is not a guarantee. If in doubt, verify independently."
            level_short = "Low"

    # --- TABS ---
    tab_summary, tab_deepdive, tab_action, tab_chat = st.tabs(
        ["🛡️ AI Verdict", "🧠 Engine Breakdown", "✅ Safety Checklist", "💬 Conversational Scan"]
    )

    with tab_summary:
        if not result:
            st.info("Awaiting input. Run a scan to see the AI verdict.")
        elif "error" in result:
            st.error(result["error"])
        else:
            if fallback:
                st.warning(
                    "AI unavailable right now. Showing a rule-based result only. It is less reliable, "
                    "so treat it with extra caution."
                )
                if result.get("_detail"):
                    with st.expander("Technical detail"):
                        st.code(result["_detail"])

            ring = f"conic-gradient({text_color} {final_risk * 3.6}deg, #E2E8F0 0deg)"
            st.markdown(
                f"""
<div class="risk-card" style="background:{banner_color};border:1px solid {text_color}33;">
  <div class="risk-ring" style="background:{ring};">
    <div class="risk-ring-inner">
      <span style="font-size:1.5rem;font-weight:800;color:{text_color};line-height:1;">{final_risk}</span>
      <span style="font-size:0.65rem;color:#64748B;">/ 100</span>
    </div>
  </div>
  <div>
    <h3 style="margin:0;color:{text_color} !important;">{icon} {level_str}</h3>
    <p style="margin:4px 0 0 0;color:{text_color};">{subtext}</p>
  </div>
</div>
""",
                unsafe_allow_html=True,
            )

            m1, m2, m3 = st.columns(3)
            m1.metric("Aggregated Threat Score", f"{final_risk}/100", level_short, delta_color="off")
            m2.metric("AI Confidence Index", "n/a" if fallback else f"{confidence}%")
            m3.metric("Execution Latency", f"{result.get('_seconds', 0)}s")
            st.caption(
                f"Result: **{label}** | Source: {result.get('_source')} | Model: {result.get('_model')} | "
                f"Analyzed at: {analyzed_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )

            st.divider()

            flags = result.get("red_flags", [])
            st.markdown("**🚩 Red flags**")
            if flags:
                for flag in flags:
                    st.write(f"- {flag}")
            else:
                st.write("None found.")

            lang_en, lang_hi = st.columns(2)
            with lang_en:
                st.markdown("#### 💡 Plain English Output (XAI)")
                st.info(result.get("explanation_en", ""))
                st.markdown("**What to do**")
                st.write(result.get("advice_en", ""))
            with lang_hi:
                st.markdown("#### 💡 सरल हिंदी विवरण")
                st.success(result.get("explanation_hi", ""))
                st.markdown("**क्या करें**")
                st.write(result.get("advice_hi", ""))

    with tab_deepdive:
        if not ok:
            st.info("Execute a scan to see the engine breakdown.")
        else:
            st.markdown("### Under the Hood: AI + Rules")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**AI-assessed risk**")
                if fallback:
                    st.caption("Not available (AI was unavailable for this scan).")
                else:
                    st.progress(ai_risk / 100)
                    st.caption("Based on the AI's label and confidence (inverted when the label is Safe).")
            with c2:
                st.markdown("**Rule-based score**")
                st.progress(valid_rule_score / 100)
                st.caption("Points from pattern rules: urgency, OTP requests, fake authority, threats, payment demands.")

            st.markdown("**Rule-based checks that fired**")
            if rules["hits"]:
                for name, matched in rules["hits"]:
                    st.write(f"- **{name}** (found: `{matched}`)")
            else:
                st.write("No rule-based red flags found.")
            st.caption(
                "Overall score = rule score only (AI unavailable)."
                if fallback else "Overall score = 60% AI risk + 40% rule score."
            )

            st.divider()

            st.markdown("### 🔒 Privacy: what is hidden before AI analysis")
            masked_text, mask_counts = mask_sensitive(payload.strip())
            if mask_counts:
                st.write(", ".join(f"{k}: {v}" for k, v in mask_counts.items()))
            else:
                st.write("No phone, Aadhaar-like, card, PAN or OTP patterns detected.")
            st.code(masked_text, language="text")
            st.caption("Only this masked text is sent to the AI. The original stays on your device and in your report.")

            st.divider()

            st.markdown("### Extracted Indicators of Compromise (IOCs)")
            iocs = extract_iocs(payload)
            if any(iocs.values()):
                if iocs["urls"]:
                    st.error(f"**Target URLs:** {', '.join(iocs['urls'])}")
                if iocs["phones"]:
                    st.warning(f"**Phone Numbers:** {', '.join(iocs['phones'])}")
                if iocs["upis"]:
                    st.warning(f"**UPI Handles:** {', '.join(iocs['upis'])}")
                if iocs["emails"]:
                    st.warning(f"**Emails:** {', '.join(iocs['emails'])}")
                if iocs["ips"]:
                    st.warning(f"**IP Addresses:** {', '.join(iocs['ips'])}")
            else:
                st.success("No links, phone numbers or UPI IDs found by the pattern matcher.")

            st.divider()
            st.markdown("### Cryptographic Integrity")
            msg_hash = generate_hash(payload)
            st.code(f"SHA-256 Artifact Hash:\n{msg_hash}", language="text")
            st.caption(
                "Covers the exact text entered here. It shows the text wasn't changed after "
                "submission; it does not prove the original message is authentic."
            )

    with tab_action:
        if not ok:
            st.info("Execute a scan to generate your safety checklist and report.")
        else:
            st.markdown("### Interactive Safety Checklist")
            st.caption("Check these off as you handle the situation.")

            st.checkbox("**Understand the risk:** read the plain-English or Hindi explanation.", value=True, disabled=True)
            st.checkbox("**Halt interaction:** don't click links or call the numbers listed.")
            st.checkbox("**Verify sender:** if they claim to be a bank or office, check through its official app or website.")
            st.checkbox("**Preserve evidence:** keep the original message, take screenshots, don't delete the chat.")
            st.checkbox("**Lost money?** Call 1930 right away and tell your bank.")
            st.checkbox("**Export the report** below and attach it when you file a complaint.")

            st.divider()
            st.markdown("### Export & Reporting")
            st.caption(f"Report will show: analyzed at {analyzed_at.strftime('%Y-%m-%d %H:%M:%S')} UTC (plus IST).")

            generated_now = datetime.now(timezone.utc)
            analyzed_str = analyzed_at.strftime("%Y-%m-%d %H:%M:%S")
            generated_str = generated_now.strftime("%Y-%m-%d %H:%M:%S")
            stamp = analyzed_at.strftime("%Y%m%d_%H%M%S")
            iocs = extract_iocs(payload)
            msg_hash = generate_hash(payload)

            col_dl, col_html = st.columns(2)
            with col_dl:
                if HAS_PDF:
                    pdf_bytes = generate_pdf_dossier(
                        analyzed_str, generated_str, result, final_risk, msg_hash, payload, rules, iocs
                    )
                    st.download_button(
                        label="📄 Export PDF Dossier (English)",
                        data=pdf_bytes,
                        file_name=f"{APP_NAME}_Dossier_{stamp}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                else:
                    st.caption("PDF needs reportlab. Run: pip install reportlab")
            with col_html:
                report_html = build_report_html(
                    payload, result, rules, final_risk, level_short,
                    extract_indicators(payload), analyzed_at,
                )
                st.download_button(
                    label="🌐 Export Report (English + Hindi)",
                    data=report_html,
                    file_name=f"{APP_NAME}_Report_{stamp}.html",
                    mime="text/html",
                    use_container_width=True,
                )
            st.caption("Hindi text shows in the HTML report. Open it in your browser and press Ctrl+P → Save as PDF.")

            col_cyber, col_chakshu = st.columns(2)
            with col_cyber:
                st.link_button("🚨 File at cybercrime.gov.in", url="https://cybercrime.gov.in", use_container_width=True)
            with col_chakshu:
                st.link_button(
                    "📞 Report call/SMS (Chakshu)",
                    url="https://sancharsaathi.gov.in/sfc/",
                    use_container_width=True,
                )
            st.caption("For financial fraud, call 1930 immediately. This tool is not legal advice.")

    with tab_chat:
        st.markdown("### Conversational Scam Analyzer")
        st.markdown(
            "<p style='color: #64748B;'>Looks for the stages of a scam (trust, panic, secrecy, payment) "
            "in a pasted WhatsApp/Telegram chat. This part uses keyword matching, not the AI.</p>",
            unsafe_allow_html=True,
        )

        chat_input = st.text_area(
            "Paste Chat Transcript:",
            height=150,
            placeholder="[10/11/2026] Scammer: Your SIM card will be blocked...\n[10/11/2026] Victim: Why?\n[10/11/2026] Scammer: Pay Rs 5000 deposit immediately.",
        )

        if st.button("Evaluate Transcript Vectors", type="secondary"):
            if chat_input.strip():
                chat_analysis = parse_and_analyze_chat(chat_input)

                st.markdown(f"**Processed {chat_analysis['total_turns']} lines.**")
                st.progress(
                    chat_analysis["max_stage_reached"] / 4,
                    text=f"Furthest stage reached: {chat_analysis['max_stage_reached']} of 4",
                )

                for stage_info in chat_analysis["kill_chain_breakdown"]:
                    if stage_info["status"] == "TRIGGERED":
                        st.error(
                            f"🚨 **{stage_info['stage_name']}** | matched: "
                            f"`{', '.join(stage_info['indicators'])}`"
                        )
                    else:
                        st.success(f"✅ {stage_info['stage_name']} (not triggered)")
            else:
                st.warning("Please provide a transcript.")

st.divider()
st.caption("AI-assisted prototype. Results can be wrong. Not legal advice.")