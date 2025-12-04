import pytest

from agnoguard.suite import GuardrailSuite, GuardrailViolationError
from agnoguard.policy import apply_policy
from agnoguard.guardrails.input_validation import InputSizeGuardrail
from agnoguard.guardrails.output_validation import OutputPIIRedactionGuardrail


class DummyTeam:
    """Minimal team-like object that Agno policy functions can attach hooks to."""
    pass


class FakeLLM:
    """Simple fake LLM to return deterministic outputs."""
    def __init__(self, response: str):
        self.response = response

    def run(self, prompt: str) -> str:
        # pretend the model always returns self.response
        return self.response


def test_apply_policy_attaches_hooks_and_pre_post_run_against_llm():
    team = DummyTeam()
    # Apply the 'default' policy which attaches pre_hooks and post_hooks
    team = apply_policy(team, "default")

    assert hasattr(team, "pre_hooks")
    assert hasattr(team, "post_hooks")
    assert isinstance(team.pre_hooks, list)
    assert isinstance(team.post_hooks, list)
    assert callable(team.pre_hooks[0])
    assert callable(team.post_hooks[0])

    pre = team.pre_hooks[0]
    post = team.post_hooks[0]

    # Use a content that pre_hook will redact (email)
    content = "Contact me at testuser@example.com"
    processed = pre(content)
    assert "testuser@example.com" not in processed

    # Simulate calling an LLM that returns PII and ensure post_hook redacts it
    llm = FakeLLM("Here is my credit card 4111-1111-1111-1111 and SSN 123-45-6789")
    raw_output = llm.run("anything")
    assert "4111-1111-1111-1111" in raw_output
    assert "123-45-6789" in raw_output

    post_processed = post(raw_output)
    # All obvious PII should be removed/redacted by the post hook
    assert "4111-1111-1111-1111" not in post_processed
    assert "123-45-6789" not in post_processed
    assert "REDACTED" in post_processed or "[REDACTED" in post_processed


def test_custom_policy_builder_and_suite_behavior():
    # Create a custom suite via PolicyBuilder-style usage (directly construct suite)
    # Here we'll create a tiny suite with an InputSizeGuardrail and OutputPIIRedactionGuardrail
    suite = GuardrailSuite("minimal")
    # Replace suite guardrails to deterministic set for this test
    suite.input_guardrails = [InputSizeGuardrail(max_chars=10)]
    suite.output_guardrails = [OutputPIIRedactionGuardrail()]

    # Ensure pre_hook blocks inputs longer than 10 chars
    pre = suite.pre_hooks[0]
    with pytest.raises(GuardrailViolationError):
        pre("This is a long input exceeding ten chars")

    # Ensure output redaction works
    post = suite.post_hooks[0]
    out = post("Number is 123-45-6789")
    assert "123-45-6789" not in out
    assert "REDACTED" in out or "[REDACTED" in out
