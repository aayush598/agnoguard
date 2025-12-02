from agnoguard.core.base import GuardrailAction, GuardrailSeverity
from agnoguard.guardrails.privacy import (
    GDPRDataMinimizationGuardrail,
    UserConsentValidationGuardrail,
    RetentionCheckGuardrail,
)


def test_gdpr_data_minimization_ok():
    g = GDPRDataMinimizationGuardrail(max_personal_fields=3)
    res = g("My name is John and my email is john@example.com")
    assert res.passed is True


def test_gdpr_data_minimization_warns_many_fields():
    g = GDPRDataMinimizationGuardrail(max_personal_fields=2)
    content = "Name, email, phone, address, birthday, ssn"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN
    assert res.metadata["fields_count"] > g.max_personal_fields


def test_user_consent_not_required():
    g = UserConsentValidationGuardrail(require_consent=False)
    res = g("Email: john@example.com")
    assert res.passed is True


def test_user_consent_required_block_without_consent():
    g = UserConsentValidationGuardrail(require_consent=True)
    ctx = {"user_consent": False}
    res = g("Here is my email and phone number", context=ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_user_consent_ok_with_consent():
    g = UserConsentValidationGuardrail(require_consent=True)
    ctx = {"user_consent": True}
    res = g("Here is my email and phone number", context=ctx)
    assert res.passed is True


def test_retention_check_within_limit():
    g = RetentionCheckGuardrail(max_retention_days=90)
    ctx = {"data_age_days": 30}
    res = g("Data", context=ctx)
    assert res.passed is True


def test_retention_check_exceeds_limit():
    g = RetentionCheckGuardrail(max_retention_days=30)
    ctx = {"data_age_days": 90}
    res = g("Data", context=ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK
    assert res.metadata["data_age_days"] == 90
    assert res.metadata["max_days"] == 30