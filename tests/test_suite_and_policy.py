import pytest

from agnoguard.core.base import GuardrailAction
from agnoguard.suite import GuardrailSuite, GuardrailViolationError
from agnoguard.policy import apply_policy, PolicyBuilder, apply_policy_suite
from agnoguard.profiles import BUILTIN_PROFILES
from agnoguard.guardrails.input_validation import InputSizeGuardrail
from agnoguard.guardrails.output_validation import OutputPIIRedactionGuardrail


def test_builtin_profiles_sanity():
    # basic existence of profiles
    assert "default" in BUILTIN_PROFILES
    assert "enterprise_security" in BUILTIN_PROFILES
    assert "child_safety" in BUILTIN_PROFILES
    assert "healthcare" in BUILTIN_PROFILES
    assert "financial" in BUILTIN_PROFILES


def test_guardrail_suite_load_profile_default():
    suite = GuardrailSuite.load_profile("default")
    assert len(suite.input_guardrails) > 0
    assert len(suite.output_guardrails) > 0
    # tool guardrails may be empty for default


def test_guardrail_suite_add_guardrail_categories():
    suite = GuardrailSuite("default")
    in_gr = InputSizeGuardrail(max_chars=10)
    out_gr = OutputPIIRedactionGuardrail()

    suite.add_guardrail(in_gr, category="input")
    suite.add_guardrail(out_gr, category="output")

    assert in_gr in suite.input_guardrails
    assert out_gr in suite.output_guardrails


def test_guardrail_suite_check_input_blocks_on_block_action():
    suite = GuardrailSuite("custom", custom_guardrails=[InputSizeGuardrail(max_chars=5)])
    res = suite.check_input("this is too long")
    assert res.passed is False
    assert res.action == GuardrailAction.BLOCK
    assert "failed_guardrails" in res.metadata


def test_guardrail_suite_check_input_allows_and_propagates_redactions():
    from agnoguard.guardrails.output_validation import OutputPIIRedactionGuardrail
    # Use as input guardrail via custom category
    class PIIInput(OutputPIIRedactionGuardrail):
        pass

    pii_gr = PIIInput()
    suite = GuardrailSuite("custom", custom_guardrails=[pii_gr])
    # Force treat as input by category in add_guardrail (already in custom_guardrails input by default)
    content = "My email is test@example.com"
    res = suite.check_input(content)
    assert res.passed is False or res.action in (GuardrailAction.REDACT, GuardrailAction.WARN, GuardrailAction.BLOCK)
    if res.modified_content:
        assert "example.com" not in res.modified_content


def test_guardrail_suite_pre_hook_allows():
    suite = GuardrailSuite("default")
    pre_hook = suite.pre_hooks[0]
    out = pre_hook("hello world")
    assert out == "hello world"


def test_guardrail_suite_pre_hook_raises_on_block():
    suite = GuardrailSuite("custom", custom_guardrails=[InputSizeGuardrail(max_chars=5)])
    pre_hook = suite.pre_hooks[0]
    with pytest.raises(GuardrailViolationError):
        pre_hook("this is too long")


def test_guardrail_suite_post_hook_redacts():
    suite = GuardrailSuite("custom", custom_guardrails=[OutputPIIRedactionGuardrail()])
    post_hook = suite.post_hooks[0]
    content = "Email: test@example.com"
    out = post_hook(content)
    # May be redacted
    assert "example.com" not in out


def test_policy_apply_policy_adds_hooks_to_team():
    class DummyTeam:
        pass

    team = DummyTeam()
    team = apply_policy(team, "default")
    assert hasattr(team, "pre_hooks")
    assert hasattr(team, "post_hooks")
    assert callable(team.pre_hooks[0])
    assert callable(team.post_hooks[0])


def test_policy_builder_build_and_apply():
    class DummyTeam:
        pass

    builder = PolicyBuilder("my_policy")
    builder.add_input_guardrail(InputSizeGuardrail(max_chars=5))
    builder.add_output_guardrail(OutputPIIRedactionGuardrail())

    suite = builder.build()
    assert isinstance(suite, GuardrailSuite)
    assert len(suite.input_guardrails) == 1
    assert len(suite.output_guardrails) == 1

    team = DummyTeam()
    team = builder.apply_to(team)
    assert hasattr(team, "pre_hooks")
    assert hasattr(team, "post_hooks")


def test_apply_policy_suite_uses_existing_hooks_lists():
    class DummyTeam:
        def __init__(self):
            self.pre_hooks = []
            self.post_hooks = []

    suite = GuardrailSuite("default")
    team = DummyTeam()
    team = apply_policy_suite(team, suite)
    # pre_hooks and post_hooks should be extended
    assert len(team.pre_hooks) >= 1
    assert len(team.post_hooks) >= 1
