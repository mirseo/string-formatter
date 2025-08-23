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

// 최대 입력 크기 제한 (1MB)
const MAX_INPUT_SIZE: usize = 1024 * 1024;
// 최대 처리 시간 제한 (100ms)  
const MAX_PROCESSING_TIME_MS: u128 = 100;
// 최대 탐지 세부사항 개수
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
    fn new() -> Result<Self> {
        let rules_content = fs::read_to_string("rules.json")
            .context("Failed to read rules.json file")?;
            
        let ruleset: Ruleset = serde_json::from_str(&rules_content)
            .context("Failed to parse rules.json")?;

        let mut compiled_rules = Vec::new();
        
        for rule in &ruleset.rules {
            let mut compiled_regexes = Vec::new();
            
            // 패턴을 정규표현식으로 미리 컴파일
            for pattern in &rule.patterns {
                if let Ok(regex) = Regex::new(&format!(r"(?i){}", regex::escape(pattern))) {
                    compiled_regexes.push(regex);
                }
            }
            
            compiled_rules.push(CompiledRule {
                name: rule.name.clone(),
                rule_type: rule.rule_type.clone(),
                patterns: rule.patterns.clone(),
                compiled_regexes,
                weight: rule.weight,
            });
        }

        // Leetspeak 매핑 테이블 초기화
        let leetspeak_map: HashMap<char, char> = [
            ('0', 'o'), ('1', 'i'), ('3', 'e'), ('4', 'a'), ('5', 's'),
            ('7', 't'), ('8', 'b'), ('@', 'a'), ('!', 'i'), ('$', 's'),
        ].iter().cloned().collect();

        // Cyrillic 매핑 테이블 초기화
        let cyrillic_map: HashMap<char, char> = [
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

fn initialize_analyzer() -> Result<()> {
    if ANALYZER.get().is_none() {
        let state = AnalyzerState::new()?;
        ANALYZER.set(Arc::new(RwLock::new(state)))
            .map_err(|_| anyhow::anyhow!("Failed to initialize analyzer"))?;
    }
    Ok(())
}

/// Analyzes a string for potential injection attacks based on a set of rules.
///
/// This function processes an input string to detect various malicious patterns,
/// including jailbreaking, prompt injection, and obfuscation techniques.
/// It returns a detailed analysis in a Python dictionary.
///
/// Args:
///     input_string (str): The string to analyze.
///     lang (str): The language of the input string (e.g., 'en', 'ko'). 
///                 This affects the output message in 'ips' mode.
///     mode (str): The analysis mode. Can be 'ids' (Intrusion Detection System) 
///                 or 'ips' (Intrusion Prevention System).
///
/// Returns:
///     dict: A dictionary containing the analysis results, including:
///         - timestamp (str): The UTC timestamp of the analysis.
///         - string_level (float): A score from 0.0 to 1.0 indicating the likelihood of an attack.
///         - lang (str): The language of the input.
///         - output_text (str): The original string or a filtered version in 'ips' mode.
///         - detection_details (list[str]): A list of detected rules and heuristics.
///         - processing_time_ms (int): The time taken for the analysis in milliseconds.
///         - input_length (int): The length of the input string.
///
/// Raises:
///     ValueError: If the input string exceeds the maximum allowed size.
///     RuntimeError: If the analyzer fails to initialize or acquire a lock.
#[pyfunction]
fn analyze(py: Python, input_string: &str, lang: &str, mode: &str) -> PyResult<PyObject> {
    let start_time = Instant::now();
    
    // 입력 검증
    if input_string.len() > MAX_INPUT_SIZE {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Input too large: {} bytes (max: {})", input_string.len(), MAX_INPUT_SIZE)
        ));
    }

    if input_string.is_empty() {
        let result = PyDict::new_bound(py);
        result.set_item("timestamp", Utc::now().to_rfc3339())?;
        result.set_item("string_level", 0.0)?;
        result.set_item("lang", lang)?;
        result.set_item("output_text", input_string)?;
        result.set_item("detection_details", Vec::<String>::new())?;
        result.set_item("processing_time_ms", 0)?;
        return Ok(result.into());
    }

    // 분석기 초기화
    if let Err(e) = initialize_analyzer() {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(
            format!("Failed to initialize analyzer: {}", e)
        ));
    }

    let analyzer_arc = ANALYZER.get().unwrap();
    let mut analyzer = match analyzer_arc.write() {
        Ok(guard) => guard,
        Err(_) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Failed to acquire analyzer lock"
            ));
        }
    };

    let mut string_level: f64 = 0.0;
    let mut detection_details = Vec::new();

    // 텍스트 정규화
    let normalized_string = analyzer.normalize_text(input_string);
    
    // 의심스러운 패턴 추출 (에러 처리)
    let suspicious_patterns = match extract_suspicious_patterns(&normalized_string) {
        Ok(patterns) => patterns,
        Err(_) => Vec::new(), // 패턴 추출 실패시 빈 벡터 반환
    };

    // 규칙 기반 분석
    let compiled_rules = analyzer.compiled_rules.clone();
    for rule in &compiled_rules {
        // 처리 시간 체크
        if start_time.elapsed().as_millis() > MAX_PROCESSING_TIME_MS {
            detection_details.push("Analysis timeout - partial results".to_string());
            break;
        }

        match rule.rule_type.as_str() {
            "keyword" => {
                // 컴파일된 정규표현식 사용
                for (pattern, regex) in rule.patterns.iter().zip(&rule.compiled_regexes) {
                    if regex.is_match(input_string) || regex.is_match(&normalized_string) {
                        string_level += rule.weight;
                        if detection_details.len() < MAX_DETECTION_DETAILS {
                            detection_details.push(format!("{}: {}", rule.name, pattern));
                        }
                    }
                    
                    // 의심스러운 패턴에서도 검사
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

    // 추가 휴리스틱 검사 (안전하게)
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

    // 최종 점수 정규화
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

/// Reloads the detection rules from the `rules.json` file.
///
/// This allows for dynamic updates to the detection logic without restarting the application.
///
/// Raises:
///     RuntimeError: If the `rules.json` file cannot be read or parsed, or if the
///                   analyzer lock cannot be acquired.
#[pyfunction]
fn reload_rules() -> PyResult<()> {
    match initialize_analyzer() {
        Ok(_) => {
            // 기존 분석기 상태를 새로 초기화
            if let Some(analyzer_arc) = ANALYZER.get() {
                if let Ok(mut analyzer) = analyzer_arc.write() {
                    match AnalyzerState::new() {
                        Ok(new_state) => {
                            *analyzer = new_state;
                            Ok(())
                        }
                        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(
                            format!("Failed to reload rules: {}", e)
                        ))
                    }
                } else {
                    Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Failed to acquire analyzer lock"
                    ))
                }
            } else {
                Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "Analyzer not initialized"
                ))
            }
        }
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(
            format!("Failed to initialize analyzer: {}", e)
        ))
    }
}

#[pymodule]
fn mirseo_formatter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(reload_rules, m)?)?;
    Ok(())
}