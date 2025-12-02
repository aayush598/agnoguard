import time

from agnoguard.core.base import GuardrailAction, GuardrailSeverity
from agnoguard.guardrails.content_safety import (
    NSFWContentGuardrail,
    HateSpeechGuardrail,
    ViolenceGuardrail,
    SelfHarmGuardrail,
    MedicalAdviceGuardrail,
    ToolAccessControlGuardrail,
    DestructiveToolCallGuardrail,
    RateLimitGuardrail,
    CostThresholdGuardrail,
)
import pytest

def test_nsfw_content_detects():
    g = NSFWContentGuardrail()
    res = g("This is explicit NSFW nude porn content")
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_nsfw_content_ok():
    g = NSFWContentGuardrail()
    res = g("Educational text only")
    assert res.passed is True


def test_hate_speech_detects():
    g = HateSpeechGuardrail()
    res = g("I hate those people and use racist slur.")
    assert res.passed is False
    assert res.severity == GuardrailSeverity.CRITICAL


def test_hate_speech_ok():
    g = HateSpeechGuardrail()
    res = g("I dislike the weather today.")
    assert res.passed is True


def test_violence_guardrail_warns():
    g = ViolenceGuardrail()
    text = "He wanted to kill and attack with a weapon in a violent assault."
    res = g(text)
    assert res.passed is False
    assert res.action == GuardrailAction.WARN


def test_violence_guardrail_ok():
    g = ViolenceGuardrail()
    res = g("He walked to the store peacefully.")
    assert res.passed is True


def test_self_harm_detects():
    g = SelfHarmGuardrail()
    res = g("I want to die and end my life.")
    assert res.passed is False
    assert res.severity == GuardrailSeverity.CRITICAL


def test_self_harm_ok():
    g = SelfHarmGuardrail()
    res = g("I'm feeling a bit down today.")
    assert res.passed is True


def test_medical_advice_warn():
    g = MedicalAdviceGuardrail(block=False)
    res = g("What medication should I take for my headache?")
    assert res.passed is True  # warned but not blocked
    assert res.action == GuardrailAction.WARN


def test_medical_advice_block():
    g = MedicalAdviceGuardrail(block=True)
    res = g("What medication should I take for my headache?")
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_tool_access_control_blocked_tool():
    g = ToolAccessControlGuardrail(allowed_tools=["search"], blocked_tools=["delete"])
    res = g.check_tool_call("delete_file", {"path": "/tmp/x"})
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_tool_access_control_disallowed_not_in_allowed_list():
    g = ToolAccessControlGuardrail(allowed_tools=["search"], blocked_tools=[])
    res = g.check_tool_call("calculator", {})
    assert res.passed is False
    assert "not in allowed" in res.message


def test_tool_access_control_allowed_tool():
    g = ToolAccessControlGuardrail(allowed_tools=["search"], blocked_tools=[])
    res = g.check_tool_call("search", {"query": "hello"})
    assert res.passed is True


def test_destructive_tool_call_blocks_destructive():
    g = DestructiveToolCallGuardrail()
    res = g.check_tool_call("delete_user", {"user_id": 1})
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_destructive_tool_call_allows_safe():
    g = DestructiveToolCallGuardrail()
    res = g.check_tool_call("read_user", {"user_id": 1})
    assert res.passed is True


def test_rate_limit_guardrail_within_limit():
    g = RateLimitGuardrail(max_requests=2, window_seconds=60)
    ctx = {"user_id": "u1"}
    assert g("x", ctx).passed is True
    assert g("x", ctx).passed is True


def test_rate_limit_guardrail_exceeds_limit():
    g = RateLimitGuardrail(max_requests=1, window_seconds=60)
    ctx = {"user_id": "u2"}
    assert g("x", ctx).passed is True
    res = g("x", ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK


def test_cost_threshold_within_limit():
    g = CostThresholdGuardrail(max_cost=0.05, cost_per_request=0.01)
    ctx = {"user_id": "u3"}
    for _ in range(5):
        res = g("x", ctx)
        assert res.passed is True
    assert g.accumulated_cost["u3"] == pytest.approx(0.05)


def test_cost_threshold_exceeds_limit():
    g = CostThresholdGuardrail(max_cost=0.02, cost_per_request=0.02)
    ctx = {"user_id": "u4"}
    assert g("x", ctx).passed is True
    res = g("x", ctx)
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK
