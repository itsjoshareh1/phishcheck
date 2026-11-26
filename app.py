"""Streamlit web app for phishcheck. Run: streamlit run app.py"""
import streamlit as st

from phishcheck import score_text, label

st.set_page_config(page_title="phishcheck", page_icon="🎣")
st.title("🎣 phishcheck")
st.caption("Paste a suspicious email, text or link. Get a risk score and the reasons why.")

text = st.text_area("Paste it here", height=220, placeholder="From: security@...\nSubject: URGENT ...")

if st.button("Check it", type="primary"):
    if not text.strip():
        st.warning("Paste something first.")
    else:
        score, reasons = score_text(text)
        verdict = label(score)
        st.metric("Risk score", f"{score}/100")
        if verdict == "HIGH RISK":
            st.error(verdict)
        elif verdict == "SUSPICIOUS":
            st.warning(verdict)
        else:
            st.success(verdict)
        st.progress(score / 100)
        st.subheader("Why")
        if reasons:
            for reason in reasons:
                st.write(f"- {reason}")
        else:
            st.write("No red flags found by the rules. That does not guarantee it is safe.")

# TODO: show the links found in the text (find_urls) in a table
# TODO: add a Claude explanation under the score
