import json

from agnoguard.core.base import GuardrailAction, GuardrailSeverity
from agnoguard.guardrails.output_validation import (
    OutputPIIRedactionGuardrail,
    SecretLeakOutputGuardrail,
    InternalDataLeakGuardrail,
    ConfidentialityGuardrail,
    OutputSchemaValidationGuardrail,
    HallucinationRiskGuardrail,
    CitationRequiredGuardrail,
    CommandInjectionOutputGuardrail,
)


def test_output_pii_redaction_redacts():
    g = OutputPIIRedactionGuardrail()
    content = "SSN: 123-45-6789, email test@example.com"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.REDACT
    assert res.modified_content is not None
    assert "123-45-6789" not in res.modified_content
    assert "test@example.com" not in res.modified_content


def test_output_pii_no_pii():
    g = OutputPIIRedactionGuardrail()
    res = g("Hello world")
    assert res.passed is True


def test_secret_leak_output_redacts():
    g = SecretLeakOutputGuardrail()
    content = "api_key = ABCDEFGHIJKLMNOPQRST and password=supersecret123"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.REDACT
    assert "ABCDEFGHIJKLMNOPQRST" not in res.modified_content
    assert "supersecret123" not in res.modified_content


def test_secret_leak_output_ok():
    g = SecretLeakOutputGuardrail()
    res = g("No secrets here")
    assert res.passed is True


def test_internal_data_leak_detects_domain():
    g = InternalDataLeakGuardrail(internal_domains=["internal"])
    content = "Access internal server at internal.corp"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_internal_data_leak_ok():
    g = InternalDataLeakGuardrail()
    res = g("Public website example.com")
    assert res.passed is True


def test_confidentiality_guardrail_detects():
    g = ConfidentialityGuardrail()
    res = g("This is confidential and not for distribution")
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_confidentiality_guardrail_ok():
    g = ConfidentialityGuardrail()
    res = g("Public information only")
    assert res.passed is True


def test_output_schema_validation_no_schema():
    g = OutputSchemaValidationGuardrail(expected_schema=None)
    res = g('{"any":"thing"}')
    assert res.passed is True


def test_output_schema_validation_missing_fields():
    schema = {"required": ["id", "name"]}
    g = OutputSchemaValidationGuardrail(expected_schema=schema)
    res = g('{"id": 1}')
    assert res.passed is False
    assert "Missing required fields" in res.message


def test_output_schema_validation_ok():
    schema = {"required": ["id", "name"]}
    g = OutputSchemaValidationGuardrail(expected_schema=schema)
    res = g('{"id":1,"name":"John"}')
    assert res.passed is True


def test_output_schema_validation_invalid_json_warns():
    schema = {"required": ["id"]}
    g = OutputSchemaValidationGuardrail(expected_schema=schema)
    res = g("not json")
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_hallucination_risk_detects_high_confidence():
    g = HallucinationRiskGuardrail()
    content = "This is absolutely a proven fact and 100% guaranteed."
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_hallucination_risk_ok():
    g = HallucinationRiskGuardrail()
    res = g("Maybe this is true, but I'm not sure.")
    assert res.passed is True


def test_citation_required_not_required_flag():
    g = CitationRequiredGuardrail(require_citations=False)
    res = g("Long factual-looking text without citations.")
    assert res.passed is True


def test_citation_required_long_factual_without_citations_warns():
    g = CitationRequiredGuardrail(require_citations=True)
    content = "Research shows that statistics and data prove this point. " * 20
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_citation_required_with_citation_ok():
    g = CitationRequiredGuardrail(require_citations=True)
    content = "Research shows [1] that this is true."
    res = g(content)
    assert res.passed is True


def test_command_injection_output_detects():
    g = CommandInjectionOutputGuardrail()
    res = g("Run `rm -rf /` to delete everything.")
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_command_injection_output_ok():
    g = CommandInjectionOutputGuardrail()
    res = g("echo 'Hello'")
    assert res.passed is True
