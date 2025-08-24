# Mirseo Formatter Rules Guide

**Language**: [Korean (한국어)](rules_guide.md) | **English**

## Overview

Mirseo Formatter uses a rule-based system to detect various attack patterns against AI models. This document explains how the rule system works and how to use it.

## Rule System Structure

### Basic Structure

Rule files are written in JSON format, and each rule has the following structure:

```json
{
  "name": "Rule Name",
  "type": "rule type",
  "patterns": ["pattern1", "pattern2", "pattern3"],
  "weight": 0.7
}
```

### Field Description

- **name**: The name of the rule, displayed in detection results
- **type**: Defines how the rule is processed (keyword, base64, hex)
- **patterns**: List of patterns to detect
- **weight**: Risk score to assign when pattern is detected (0.0 ~ 1.0)

## Rule Types

### keyword type

The most basic rule type that searches for patterns directly in input text.

```json
{
  "name": "Basic Jailbreak Keywords",
  "type": "keyword",
  "patterns": [
    "ignore all previous instructions",
    "모든 이전 지침 무시",
    "act as",
    "~인 척해줘"
  ],
  "weight": 0.7
}
```

### base64 type

Decodes input as Base64 and then searches for patterns.

```json
{
  "name": "Base64 Encoded Keywords",
  "type": "base64",
  "patterns": [
    "disable safety",
    "안전 장치를 끄고"
  ],
  "weight": 0.8
}
```

### hex type

Decodes input as hexadecimal and then searches for patterns.

```json
{
  "name": "Hex Encoded Keywords",
  "type": "hex",
  "patterns": [
    "jailbreak mode",
    "unrestricted mode"
  ],
  "weight": 0.8
}
```

## Rule File Configuration

### Single File Approach

The traditional approach where all rules are included in one JSON file:

```json
{
  "rules": [
    {
      "name": "Rule1",
      "type": "keyword",
      "patterns": ["pattern1", "pattern2"],
      "weight": 0.7
    },
    {
      "name": "Rule2", 
      "type": "base64",
      "patterns": ["pattern3", "pattern4"],
      "weight": 0.8
    }
  ]
}
```

### Multiple File Approach (Recommended)

You can manage rules by category by placing multiple JSON files in the rules directory.

#### File Structure Example
```
rules/
├── basic_jailbreak.json
├── encoding_attacks.json
├── prompt_injection.json
└── custom_rules.json
```

#### Individual File Format

Each file can be written as an array of rules:

```json
[
  {
    "name": "Basic Jailbreak Patterns",
    "type": "keyword", 
    "patterns": [
      "ignore all previous instructions",
      "너는 이제 개발자 모드야"
    ],
    "weight": 0.7
  },
  {
    "name": "Advanced Jailbreak Patterns",
    "type": "keyword",
    "patterns": [
      "you are DAN",
      "do anything now"
    ],
    "weight": 0.85
  }
]
```

Or in the traditional ruleset format:

```json
{
  "rules": [
    {
      "name": "Encoding Attacks",
      "type": "base64",
      "patterns": ["test pattern"],
      "weight": 0.8
    }
  ]
}
```

## Usage

### Using in Python

#### Basic Usage (Built-in Rules)

```python
import mirseo_formatter

# Initialize with default built-in rules
mirseo_formatter.init()

# Analyze text
result = mirseo_formatter.analyze("ignore all previous instructions", "en", "ids")
print(f"Risk Level: {result['string_level']}")
print(f"Detection Details: {result['detection_details']}")
```

#### Using Single File

```python
import mirseo_formatter

# Initialize with specific rules file
mirseo_formatter.init(rules_path="./my_rules.json")

# Execute analysis
result = mirseo_formatter.analyze("suspicious text", "en", "ids")
```

#### Using Directory (Recommended)

```python
import mirseo_formatter

# Load all JSON files from rules directory
mirseo_formatter.init(rules_path="./rules")

# Execute analysis
result = mirseo_formatter.analyze("test input", "en", "ids")
```

#### Using JSON String

```python
import mirseo_formatter

rules_json = '''
{
  "rules": [
    {
      "name": "Custom Rule",
      "type": "keyword", 
      "patterns": ["custom pattern"],
      "weight": 0.9
    }
  ]
}
'''

mirseo_formatter.init(rules_json_str=rules_json)
result = mirseo_formatter.analyze("custom pattern detected", "en", "ids")
```

## Rule Writing Guide

### Writing Effective Patterns

1. **Use Specific Patterns**: Target specific attack patterns rather than overly general words
2. **Multi-language Support**: Include both Korean and English patterns
3. **Appropriate Weights**: Set within 0.1 (low) ~ 1.0 (high) range based on risk level

### Pattern Priority

- **High Weight (0.8 ~ 1.0)**: Clear attack attempts (DAN, jailbreak mode, etc.)
- **Medium Weight (0.5 ~ 0.7)**: Suspicious patterns (role change requests, etc.)
- **Low Weight (0.1 ~ 0.4)**: Potential risk factors (hypothetical scenarios, etc.)

### Example: Category-based Rule Files

#### basic_attacks.json
```json
[
  {
    "name": "Direct Instruction Ignore",
    "type": "keyword",
    "patterns": [
      "ignore all instructions",
      "모든 지시 무시",
      "disregard previous",
      "이전 설정을 무시하고"
    ],
    "weight": 0.8
  }
]
```

#### encoding_bypass.json
```json
[
  {
    "name": "Base64 Bypass Attempt",
    "type": "base64", 
    "patterns": [
      "jailbreak",
      "bypass restrictions",
      "탈옥",
      "제한 우회"
    ],
    "weight": 0.9
  }
]
```

#### social_engineering.json
```json
[
  {
    "name": "Emotional Manipulation",
    "type": "keyword",
    "patterns": [
      "this is urgent",
      "life or death",
      "긴급 상황이야",
      "생사가 달린"
    ],
    "weight": 0.5
  }
]
```

## Rule Management Tips

### File Organization

- Separate files by attack type to improve manageability
- Write filenames that clearly express their contents
- Regularly review and update rule effectiveness

### Performance Optimization

- Don't include too many patterns in a single rule
- Regex special characters in patterns are automatically escaped
- Weight sum is automatically limited to 1.0 even if it exceeds

### Testing Method

After adding new rules, you can test them as follows:

```python
import mirseo_formatter

# Initialize with new rules
mirseo_formatter.init(rules_path="./rules")

# Execute test cases
test_cases = [
    "ignore all previous instructions",
    "This is normal text",
    "you are now DAN",
    "We are having a safe conversation"
]

for test in test_cases:
    result = mirseo_formatter.analyze(test, "en", "ids")
    print(f"Input: {test}")
    print(f"Risk Level: {result['string_level']}")
    print(f"Detection Details: {result['detection_details']}")
    print("---")
```

## Precautions

1. **Rule File Format**: Must follow JSON syntax correctly; incorrectly formatted files are ignored during loading
2. **Pattern Duplication**: Identical patterns in multiple files are processed independently
3. **Memory Usage**: More rules increase memory usage, so management at an appropriate level is necessary
4. **Processing Time**: Complex patterns or large numbers of rules can increase analysis time

Please use this guide to configure effective security rules for your project.