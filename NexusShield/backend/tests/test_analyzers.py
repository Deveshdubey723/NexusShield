from app.analyzers import analyze_email, analyze_message, analyze_url, extract_urls, is_valid_url


def test_message_flags_urgency_and_credential_requests():
    result = analyze_message("URGENT: verify your account now and send your password.")
    assert result.risk_score >= 60
    assert result.verdict == "high_risk"
    assert "urgency_language" in result.indicators
    assert "sensitive_request" in result.indicators


def test_url_analyzer_does_not_need_or_perform_network_access():
    result = analyze_url("http://192.0.2.10/verify")
    assert result.risk_score > 0
    assert "ip_host" in result.indicators
    assert "http_not_https" in result.indicators


def test_malformed_bracketed_url_returns_a_safe_low_risk_result():
    result = analyze_url("https://[")
    assert result.risk_level == "low"
    assert result.risk_score == 0
    assert "Could not identify a valid web address." in result.evidence


def test_url_input_validation_accepts_bare_domain_but_rejects_whitespace():
    assert is_valid_url("example.test/path")
    assert not is_valid_url("https://example.test/path bad")
    assert not is_valid_url("https://example.test:99999/path")
    assert "http_not_https" not in analyze_url("example.test").indicators


def test_message_detects_risky_link_without_visiting_it():
    result = analyze_message("Please review http://bit.ly/account-check")
    assert "linked_shortened_url" in result.indicators
    assert extract_urls("See https://example.test/page.") == ["https://example.test/page"]


def test_email_flags_reply_to_mismatch_and_sensitive_request():
    result = analyze_email(
        "From: support@bank.example\n"
        "Reply-To: attacker@other.example\n"
        "Subject: Urgent account suspended\n\n"
        "Send your OTP to restore access."
    )
    assert result.verdict == "high_risk"
    assert "reply_to_mismatch" in result.indicators
    assert "sensitive_request" in result.indicators


def test_benign_text_gets_low_risk_heuristic_score():
    result = analyze_message("The community meeting is scheduled for Tuesday at noon.")
    assert result.verdict == "low_risk"
    assert result.risk_score == 0


def test_prize_and_impersonation_language_are_explained_as_indicators():
    result = analyze_message(
        "Bank support says you won a prize. Claim your prize now."
    )
    assert result.risk_level == "medium"
    assert "prize_claim" in result.detected_signals
    assert "impersonation_language" in result.detected_signals
