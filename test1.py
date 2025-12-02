from agnoguard import GuardrailSuite

suite = GuardrailSuite("default")

result = suite.check_input("My email is john@example.com")

print(result.passed)               # False (PII found)
print(result.modified_content)     # PII redacted
