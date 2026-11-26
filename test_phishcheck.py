from phishcheck import score_text, check_url


def test_obvious_phish_scores_high():
    text = "URGENT: verify your account immediately at http://192.168.4.7/paypal-login"
    score, reasons = score_text(text)
    assert score >= 60
    assert reasons


def test_normal_email_scores_low():
    score, _ = score_text("Hi, notes from class are attached. See you Monday.")
    assert score < 30


def test_ip_link_flagged():
    assert any("IP" in reason for _, reason in check_url("http://10.0.0.1/x"))

# TODO: add a test for each new rule you add.
