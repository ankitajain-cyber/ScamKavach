st.markdown("<p style='font-weight: 600; color: #1E3A8A;'>💬 Multi-Turn Chat Transcript Kill-Chain Replay</p>", unsafe_allow_html=True)

chat_input = st.text_area(
    "Paste WhatsApp / Telegram Chat Transcript:", 
    height=150, 
    placeholder="[10/11/2026, 10:12:05] Scammer: Dear customer your SIM card will be blocked...\n[10/11/2026, 10:13:20] Victim: Why will it be blocked?"
)

if st.button("Analyze Transcript Sequence"):
    if chat_input:
        # Ensure parse_and_analyze_chat function is defined above in your app.py
        chat_analysis = parse_and_analyze_chat(chat_input)
        
        st.metric("Total Parsed Turns", chat_analysis["total_turns"])
        st.metric("Max Kill-Chain Progression", f"Phase {chat_analysis['max_stage_reached']} / 4")
        
        for stage_info in chat_analysis["kill_chain_breakdown"]:
            if stage_info["status"] == "TRIGGERED":
                st.error(f"🚨 **{stage_info['stage_name']}** — Matched: `{', '.join(stage_info['indicators'])}`")
            else:
                st.success(f"✅ ~{stage_info['stage_name']}~ [Inactive]")
    else:
        st.warning("Please provide a chat transcript to analyze.")