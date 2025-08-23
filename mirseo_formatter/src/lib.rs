//! A high-performance, security-focused string formatter and injection attack detector.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use std::fs;
use std::sync::{Arc, RwLock, OnceLock};
use std::collections::HashMap;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;
use std::time::Instant;
use anyhow::{Result, Context};

// ... (constants remain the same) ...
const MAX_INPUT_SIZE: usize = 1024 * 1024;
const MAX_PROCESSING_TIME_MS: u128 = 100;
const MAX_DETECTION_DETAILS: usize = 50;

#[derive(Deserialize, Debug, Clone)]
struct Rule {
    name: String,
    #[serde(rename = "type")]
    rule_type: String,
    patterns: Vec<String>,
    weight: f64,
}

#[derive(Deserialize, Debug, Clone)]
struct Ruleset {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    rule_type: String,
    patterns: Vec<String>,
    compiled_regexes: Vec<Regex>,
    weight: f64,
}

struct AnalyzerState {
    ruleset: Ruleset,
    compiled_rules: Vec<CompiledRule>,
    normalization_cache: HashMap<String, String>,
    leetspeak_map: HashMap<char, char>,
    cyrillic_map: HashMap<char, char>,
}

static ANALYZER: OnceLock<Arc<RwLock<AnalyzerState>>> = OnceLock::new();

impl AnalyzerState {
    fn new(rules_path: &str) -> Result<Self> {
        let rules_content = fs::read_to_string(rules_path)
            .context(format!("Failed to read rules file from: {}", rules_path))?;
            
        let ruleset: Ruleset = serde_json::from_str(&rules_content)
            .context("Failed to parse rules.json")?;

        let compiled_rules = ruleset.rules.iter().map(|rule| {
            let compiled_regexes = rule.patterns.iter()
                .filter_map(|p| Regex::new(&format!(r"(?i){}", regex::escape(p))).ok())
                .collect();
            CompiledRule {
                name: rule.name.clone(),
                rule_type: rule.rule_type.clone(),
                patterns: rule.patterns.clone(),
                compiled_regexes,
                weight: rule.weight,
            }
        }).collect();

        let leetspeak_map = [
            ('0', 'o'), ('1', 'i'), ('3', 'e'), ('4', 'a'), ('5', 's'),
            ('7', 't'), ('8', 'b'), ('@', 'a'), ('!', 'i'), ('$', 's'),
        ].iter().cloned().collect();

        let cyrillic_map = [
            ('і', 'i'), ('ı', 'i'), ('е', 'e'), ('о', 'o'), ('а', 'a'),
            ('р', 'p'), ('с', 'c'), ('х', 'x'), ('у', 'y'), ('к', 'k'),
            ('н', 'h'), ('м', 'm'), ('т', 't'), ('в', 'b'), ('д', 'd'), ('г', 'g'),
        ].iter().cloned().collect();

        Ok(AnalyzerState {
            ruleset,
            compiled_rules,
            normalization_cache: HashMap::new(),
            leetspeak_map,
            cyrillic_map,
        })
    }
    fn normalize_text(&mut self, text: &str) -> String {
        // 캐시 확인
        if let Some(cached) = self.normalization_cache.get(text) {
            return cached.clone();
        }

        // 길이 제한
        if text.len() > 1000 {
            return text.to_lowercase();
        }

        // Unicode 정규화
        let normalized = text.nfd().collect::<String>();
        
        // 문자 변환
        let mut result = String::with_capacity(normalized.len());
        for c in normalized.chars() {
            if let Some(&replacement) = self.cyrillic_map.get(&c) {
                result.push(replacement);
            } else if let Some(&replacement) = self.leetspeak_map.get(&c) {
                result.push(replacement);
            } else {
                result.push(c.to_lowercase().next().unwrap_or(c));
            }
        }

        // 캐시에 저장 (크기 제한)
        if self.normalization_cache.len() < 1000 {
            self.normalization_cache.insert(text.to_string(), result.clone());
        }

        result
    }
}

fn safe_base64_decode(input: &str) -> Option<String> {
    // 입력 크기 제한
    if input.len() > 10000 {
        return None;
    }

    general_purpose::STANDARD
        .decode(input)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| if s.len() > 10000 { None } else { Some(s) })
}

fn safe_hex_decode(input: &str) -> Option<String> {
    // 입력 크기 제한 및 16진수 형식 확인
    if input.len() > 10000 || input.len() % 2 != 0 {
        return None;
    }

    hex::decode(input)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| if s.len() > 10000 { None } else { Some(s) })
}

fn extract_suspicious_patterns(text: &str) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    
    // 패턴 수 제한
    const MAX_PATTERNS: usize = 10;
    
    // 연속된 특수문자 패턴
    let special_chars_re = Regex::new(r"[.*_-]{3,}")?;
    for mat in special_chars_re.find_iter(text).take(MAX_PATTERNS) {
        patterns.push(mat.as_str().to_string());
    }
    
    // 과도한 공백 패턴
    let excessive_spaces_re = Regex::new(r"[a-zA-Z]s{2,}[a-zA-Z]")?;
    for mat in excessive_spaces_re.find_iter(text).take(MAX_PATTERNS) {
        patterns.push(mat.as_str().to_string());
    }

    // ROT13 변환 (간단한 케이스만)
    if text.len() < 1000 {
        let rot13_text: String = text.chars().map(|c| {
            match c {
                'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
                'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
                _ => c,
            }
        }).collect();
        
        if rot13_text != text {
            patterns.push(rot13_text);
        }
    }

    Ok(patterns)
}

fn initialize_analyzer(rules_path: &str) -> Result<()> {
    let state = AnalyzerState::new(rules_path)?;
    if ANALYZER.set(Arc::new(RwLock::new(state))).is_err() {
        // Already initialized, so we need to reload
        reload_rules_with_path(rules_path)?;
    }
    Ok(())
}

fn reload_rules_with_path(rules_path: &str) -> Result<()> {
    if let Some(analyzer_arc) = ANALYZER.get() {
        let mut analyzer = analyzer_arc.write().map_err(|_| anyhow::anyhow!("Failed to acquire analyzer lock"))?;
        let new_state = AnalyzerState::new(rules_path)?;
        *analyzer = new_state;
        Ok(())
    } else {
        Err(anyhow::anyhow!("Analyzer not initialized. Call init() first."))
    }
}

/// Initializes the analyzer with a specific path to the rules.json file.
#[pyfunction]
fn init(rules_path: &str) -> PyResult<()> {
    initialize_analyzer(rules_path).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Reloads the detection rules from the `rules.json` file.
#[pyfunction]
fn reload_rules() -> PyResult<()> {
    reload_rules_with_path("rules.json").map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}


/// Analyzes a string for potential injection attacks based on a set of rules.
#[pyfunction]
fn analyze(py: Python, input_string: &str, lang: &str, mode: &str) -> PyResult<PyObject> {
    if ANALYZER.get().is_none() {
        if let Err(e) = initialize_analyzer("rules.json") {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to auto-initialize analyzer with 'rules.json'. Please call init('/path/to/rules.json') first. Error: {}", e
            )));
        }
    }

    let start_time = Instant::now();
    
    if input_string.len() > MAX_INPUT_SIZE {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Input too large: {} bytes (max: {})", input_string.len(), MAX_INPUT_SIZE)
        ));
    }

    let analyzer_arc = ANALYZER.get().unwrap();
    let mut analyzer = analyzer_arc.write().map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Failed to acquire analyzer lock"))?;

    let mut string_level: f64 = 0.0;
    let mut detection_details = Vec::new();

    let normalized_string = analyzer.normalize_text(input_string);
    let suspicious_patterns = extract_suspicious_patterns(&normalized_string).unwrap_or_default();

    let compiled_rules = analyzer.compiled_rules.clone();
    for rule in &compiled_rules {
        if start_time.elapsed().as_millis() > MAX_PROCESSING_TIME_MS {
            detection_details.push("Analysis timeout - partial results".to_string());
            break;
        }

        match rule.rule_type.as_str() {
            "keyword" => {
                for (pattern, regex) in rule.patterns.iter().zip(&rule.compiled_regexes) {
                    if regex.is_match(input_string) || regex.is_match(&normalized_string) {
                        string_level += rule.weight;
                        if detection_details.len() < MAX_DETECTION_DETAILS {
                            detection_details.push(format!("{}: {}", rule.name, pattern));
                        }
                    }
                    for suspicious in &suspicious_patterns {
                        if regex.is_match(suspicious) {
                            string_level += rule.weight * 0.8;
                            if detection_details.len() < MAX_DETECTION_DETAILS {
                                detection_details.push(format!("{} (obfuscated): {}", rule.name, pattern));
                            }
                        }
                    }
                }
            }
            "base64" => {
                if let Some(decoded_string) = safe_base64_decode(input_string) {
                    let normalized_decoded = analyzer.normalize_text(&decoded_string);
                    for (pattern, regex) in rule.patterns.iter().zip(&rule.compiled_regexes) {
                        if regex.is_match(&decoded_string) || regex.is_match(&normalized_decoded) {
                            string_level += rule.weight;
                            if detection_details.len() < MAX_DETECTION_DETAILS {
                                detection_details.push(format!("{} (base64): {}", rule.name, pattern));
                            }
                        }
                    }
                }
            }
            "hex" => {
                if let Some(decoded_string) = safe_hex_decode(input_string) {
                    let normalized_decoded = analyzer.normalize_text(&decoded_string);
                    for (pattern, regex) in rule.patterns.iter().zip(&rule.compiled_regexes) {
                        if regex.is_match(&decoded_string) || regex.is_match(&normalized_decoded) {
                            string_level += rule.weight;
                            if detection_details.len() < MAX_DETECTION_DETAILS {
                                detection_details.push(format!("{} (hex): {}", rule.name, pattern));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let heuristic_patterns = [
        (r"[.*_-]{5,}", 0.1),
        (r"[A-Za-z0-9+/]{50,}={0,2}", 0.1),
        (r"[0-9a-fA-F]{64,}", 0.1),
    ];

    for (pattern_str, weight) in heuristic_patterns {
        if let Ok(pattern) = Regex::new(pattern_str) {
            if pattern.is_match(input_string) {
                string_level += weight;
                if detection_details.len() < MAX_DETECTION_DETAILS {
                    detection_details.push(format!("Heuristic: {}", pattern_str));
                }
            }
        }
    }

    string_level = string_level.min(1.0);

    let output_text = if mode == "ips" && string_level > 0.55 {
        match lang {
            "ko" => "기존 프롬프트를 계속 진행하세요.",
            _ => "Please continue with the original prompt.",
        }
    } else {
        input_string
    };

    let processing_time = start_time.elapsed().as_millis();

    let result = PyDict::new_bound(py);
    result.set_item("timestamp", Utc::now().to_rfc3339())?;
    result.set_item("string_level", string_level)?;
    result.set_item("lang", lang)?;
    result.set_item("output_text", output_text)?;
    result.set_item("detection_details", detection_details)?;
    result.set_item("processing_time_ms", processing_time as u64)?;
    result.set_item("input_length", input_string.len())?;

    Ok(result.into())
}

#[pymodule]
fn mirseo_formatter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(reload_rules, m)?)?;
    Ok(())
}