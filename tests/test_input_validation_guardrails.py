import pytest

from agnoguard.core.base import GuardrailAction, GuardrailSeverity
from agnoguard.guardrails.input_validation import (
    PIIDetectionGuardrailExtended,
    PHIAwarenessGuardrail,
    URLAndFileBlockerGuardrail,
    SecretsInInputGuardrail,
    InputSizeGuardrail,
    DangerousPatternsGuardrail,
    RegexFilterGuardrail,
    LanguageRestrictionGuardrail,
)


def test_pii_detection_no_pii():
    g = PIIDetectionGuardrailExtended(redact=True)
    res = g("Just some harmless text")
    assert res.passed is True
    assert res.action == GuardrailAction.ALLOW


def test_pii_detection_with_pii_and_redact():
    g = PIIDetectionGuardrailExtended(redact=True)
    text = "My email is test@example.com and SSN is 123-45-6789"
    res = g(text)
    assert res.passed is False
    assert res.action in (GuardrailAction.REDACT, GuardrailAction.BLOCK)
    # must indicate specific pii in metadata
    assert "found_pii" in res.metadata
    assert res.modified_content is None or "example.com" not in (res.modified_content or "")


def test_phi_awareness_detects_phi():
    g = PHIAwarenessGuardrail()
    content = "Patient has a diagnosis of diabetes, check their medical record."
    res = g(content)
    assert res.passed is False
    assert res.severity == GuardrailSeverity.CRITICAL
    assert "medical_terms" in res.metadata
    assert len(res.metadata["medical_terms"]) >= 2


def test_phi_awareness_ok():
    g = PHIAwarenessGuardrail()
    res = g("General health tips only.")
    assert res.passed is True


def test_url_file_blocker_no_issues():
    g = URLAndFileBlockerGuardrail(block_urls=True, block_paths=True)
    res = g("Tell me a joke.")
    assert res.passed is True


def test_url_file_blocker_blocks_url_and_paths():
    g = URLAndFileBlockerGuardrail(block_urls=True, block_paths=True)
    content = "Check https://example.com and /etc/passwd"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK
    assert "issues" in res.metadata
    assert any("URL" in issue or "file path" in issue for issue in res.metadata["issues"])


def test_secrets_in_input_detects_secret():
    g = SecretsInInputGuardrail()
    content = "Here is my api_key = ABCDEFGHIJKLMNOPQRST"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK
    assert "api_key" in res.metadata["found_secrets"]


def test_secrets_in_input_ok():
    g = SecretsInInputGuardrail()
    res = g("No secrets here")
    assert res.passed is True


def test_input_size_guardrail_ok():
    g = InputSizeGuardrail(max_chars=20, max_tokens=5)
    res = g("short text")
    assert res.passed is True


def test_input_size_guardrail_too_many_chars():
    g = InputSizeGuardrail(max_chars=5)
    res = g("1234567")
    assert res.passed is False
    assert "char_count" in res.metadata


def test_input_size_guardrail_too_many_tokens():
    g = InputSizeGuardrail(max_chars=100, max_tokens=3)
    res = g("one two three four")
    assert res.passed is False
    assert res.metadata["estimated_tokens"] > 3


def test_dangerous_patterns_ok():
    g = DangerousPatternsGuardrail()
    res = g("Just a story about tables")
    assert res.passed is True


def test_dangerous_patterns_detects_sql_injection():
    g = DangerousPatternsGuardrail()
    content = "UNION SELECT * FROM users; DROP TABLE accounts;"
    res = g(content)
    assert res.passed is False
    assert any(p in res.metadata["patterns"] for p in ["sql_injection", "command_injection"])


def test_regex_filter_no_match():
    g = RegexFilterGuardrail(patterns=[{"pattern": r"secret"}])
    res = g("This is fine")
    assert res.passed is True


def test_regex_filter_match():
    g = RegexFilterGuardrail(patterns=[{"pattern": r"secret", "name": "secret_pattern"}])
    res = g("Here is a secret token")
    assert res.passed is False
    assert "secret_pattern" in res.metadata["matched_patterns"]


def test_language_restriction_en_ok():
    g = LanguageRestrictionGuardrail(allowed_languages=["en"])
    res = g("Hello world")
    assert res.passed is True


def test_language_restriction_warns_on_non_ascii():
    g = LanguageRestrictionGuardrail(allowed_languages=["en"])
    res = g("こんにちは")  # Japanese
    assert res.passed is False
    assert res.action == GuardrailAction.WARN
