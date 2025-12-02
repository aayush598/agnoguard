import pytest

from agnoguard.core.base import (
    BaseGuardrail,
    InputGuardrail,
    OutputGuardrail,
    ToolGuardrail,
    GuardrailResult,
    GuardrailAction,
    GuardrailSeverity,
)


class DummyGuardrail(InputGuardrail):
    def __init__(self, *, should_fail=False, **kwargs):
        super().__init__(**kwargs)
        self.should_fail = should_fail

    def check(self, content: str, context=None) -> GuardrailResult:
        if self.should_fail:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message="failed",
                metadata={"content": content},
            )
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="ok",
            metadata={"content": content},
        )


class ErrorGuardrail(InputGuardrail):
    def check(self, content: str, context=None) -> GuardrailResult:
        raise RuntimeError("boom")


def test_base_guardrail_enabled_pass():
    g = DummyGuardrail()
    result = g("hello")
    assert isinstance(result, GuardrailResult)
    assert result.passed is True
    assert result.action == GuardrailAction.ALLOW
    assert result.metadata["content"] == "hello"


def test_base_guardrail_enabled_fail():
    g = DummyGuardrail(should_fail=True)
    result = g("bad")
    assert result.passed is False
    assert result.action == GuardrailAction.BLOCK
    assert result.severity == GuardrailSeverity.ERROR
    assert result.metadata["content"] == "bad"


def test_base_guardrail_disabled_short_circuit():
    g = DummyGuardrail(enabled=False)
    result = g("whatever")
    assert result.passed is True
    assert result.action == GuardrailAction.ALLOW
    assert result.metadata["enabled"] is False
    assert "guardrail" in result.metadata


def test_base_guardrail_error_handling():
    g = ErrorGuardrail()
    result = g("boom")
    assert result.passed is False
    assert result.action == GuardrailAction.BLOCK
    assert result.severity == GuardrailSeverity.CRITICAL
    assert "Guardrail error" in result.message
    assert result.metadata["guardrail"] == g.name


def test_tool_guardrail_is_abstract():
    class DummyTool(ToolGuardrail):
        def check(self, content: str, context=None) -> GuardrailResult:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="ok",
                metadata={},
            )

        def check_tool_call(self, tool_name, tool_args, context=None) -> GuardrailResult:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message=f"{tool_name}",
                metadata={"args": tool_args},
            )

    t = DummyTool()
    res = t.check_tool_call("tool", {"x": 1})
    assert res.passed is True
    assert res.metadata["args"]["x"] == 1
