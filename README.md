# phishcheck

Paste a suspicious email or link and get a risk score from 0 to 100 plus a plain-English list of why.

**Status:** work in progress. A rule-based starter works today; a basic Streamlit web app is included; AI explanations are next.

## Try it

```bash
pip install -r requirements.txt
streamlit run app.py          # opens the web app in your browser
```

Paste `sample_phish.txt` into the box: it should score HIGH RISK. `sample_legit.txt` should score LOOKS OK.

Command line and tests still work:

```bash
python3 phishcheck.py sample_phish.txt
pytest
```

## How it works

1. Pull the links out of the text.
2. Score red flags: urgency language, credential requests, raw-IP links, URL shorteners, scam-prone TLDs, brand lookalike domains.
3. Add up the points, print a label and every reason.

## Roadmap

- [x] Rule-based scorer and CLI
- [ ] Lookalike domains with swapped characters (`paypa1.com`)
- [ ] Link text vs real destination check
- [ ] Sender header checks (From vs Reply-To)
- [ ] Claude explains the verdict in plain language
- [ ] Evaluation on labelled phishing and legit samples
- [x] Streamlit web app (basic)

## Limits

Rules catch common tricks only. A low score does not mean an email is safe.

## License

MIT
