import mirseo_formatter as mf
import pytest
import json
import time

# 1. Test Null Byte Injection
def test_null_byte_injection():
    prompt = "normal text\0with null byte"
    with pytest.raises(ValueError, match="Input contains null bytes"):
        mf.analyze(prompt, lang='en', mode='ids')

# 2. Test ReDoS Mitigation
def test_redos_mitigation():
    # Add a potentially malicious regex to rules.json
    with open("rules.json", "r") as f:
        rules = json.load(f)
    
    evil_rule = {
        "name": "Evil Regex",
        "type": "keyword",
        "patterns": ["(a+)+$"], # A classic evil regex
        "weight": 0.9
    }
    rules["rules"].append(evil_rule)

    with open("rules.json", "w") as f:
        json.dump(rules, f)

    # Reload rules
    mf.reload_rules()

    # This prompt would cause a catastrophic backtrack on a vulnerable regex engine
    prompt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    
    start_time = time.time()
    # The regex engine should be able to handle this without hanging
    # because of the complexity limits set in the Rust code.
    result = mf.analyze(prompt, lang='en', mode='ids')
    end_time = time.time()

    # Assert that the analysis completed quickly
    assert (end_time - start_time) < 1.0 # Should be much faster

    # Clean up rules.json
    rules["rules"].pop()
    with open("rules.json", "w") as f:
        json.dump(rules, f)
    mf.reload_rules()

# Run tests
test_null_byte_injection()
test_redos_mitigation()

print("All security tests passed!")
