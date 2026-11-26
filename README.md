# phishcheck

Paste a suspicious email or link and get a risk score from 0 to 100 plus a plain-English list of why.

**Status:** work in progress. A rule-based starter works today; AI explanations and a web UI are next.

## Try it

```bash
python phishcheck.py sample_phish.txt     # should score HIGH RISK
python phishcheck.py sample_legit.txt     # should score LOOKS OK
pip install -r requirements.txt && pytest
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
- [ ] Streamlit web app

## Limits

Rules catch common tricks only. A low score does not mean an email is safe.

## License

MIT
