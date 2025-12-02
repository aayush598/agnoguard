import pytest

from agnoguard.core.base import GuardrailAction, GuardrailSeverity
from agnoguard.guardrails.operational import (
    ModelVersionPinGuardrail,
    TelemetryEnforcementGuardrail,
    QualityThresholdGuardrail,
    APIRateLimitGuardrail,
    FileWriteRestrictionGuardrail,
    EnvironmentVariableLeakGuardrail,
)


def test_model_version_pin_no_requirement():
    g = ModelVersionPinGuardrail(required_version=None)
    res = g("anything")
    assert res.passed is True
    assert "No version requirement" in res.message


def test_model_version_pin_mismatch_warn():
    g = ModelVersionPinGuardrail(required_version="gpt-5-mini")
    ctx = {"model_version": "gpt-4"}
    res = g("hi", ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN
    assert res.metadata["required"] == "gpt-5-mini"


def test_model_version_pin_match():
    g = ModelVersionPinGuardrail(required_version="gpt-5-mini")
    ctx = {"model_version": "gpt-5-mini"}
    res = g("hi", ctx)
    assert res.passed is True


def test_telemetry_not_required():
    g = TelemetryEnforcementGuardrail(require_telemetry=False)
    res = g("x")
    assert res.passed is True


def test_telemetry_required_missing_warn():
    g = TelemetryEnforcementGuardrail(require_telemetry=True)
    ctx = {"telemetry_enabled": False}
    res = g("x", ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_telemetry_required_present():
    g = TelemetryEnforcementGuardrail(require_telemetry=True)
    ctx = {"telemetry_enabled": True}
    res = g("x", ctx)
    assert res.passed is True


def test_quality_threshold_too_short():
    g = QualityThresholdGuardrail(min_confidence=0.7, min_length=10)
    res = g("short", context={"confidence": 0.9})
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_quality_threshold_low_confidence():
    g = QualityThresholdGuardrail(min_confidence=0.9, min_length=5)
    res = g("long enough", context={"confidence": 0.5})
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_quality_threshold_ok():
    g = QualityThresholdGuardrail(min_confidence=0.7, min_length=5)
    res = g("long enough", context={"confidence": 0.9})
    assert res.passed is True


def test_api_rate_limit_within_limit():
    g = APIRateLimitGuardrail(calls_per_minute=2)
    ctx = {"api_key": "k1"}
    assert g("x", ctx).passed is True
    assert g("x", ctx).passed is True


def test_api_rate_limit_exceeded():
    g = APIRateLimitGuardrail(calls_per_minute=1)
    ctx = {"api_key": "k2"}
    assert g("x", ctx).passed is True
    res = g("x", ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_file_write_restriction_blocks_disallowed_path():
    g = FileWriteRestrictionGuardrail(allowed_paths=["/tmp"])
    content = "open('/etc/passwd', 'w')"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_file_write_restriction_allows_allowed_path():
    g = FileWriteRestrictionGuardrail(allowed_paths=["/tmp"])
    content = "open('/tmp/file.txt', 'w')"
    res = g(content)
    assert res.passed is True


def test_env_variable_leak_detects():
    g = EnvironmentVariableLeakGuardrail()
    content = "API_KEY=supersecret1234567890"
    res = g(content)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_env_variable_leak_ok():
    g = EnvironmentVariableLeakGuardrail()
    res = g("No secrets here")
    assert res.passed is True
