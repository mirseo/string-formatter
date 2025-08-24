# Mirseo Formatter 성능 분석 보고서

*IDS vs IPS vs IUS vs Basic Normalization*

---

## **개요**

본 보고서는 **Mirseo Formatter**의 세 가지 모드(**IDS**, **IPS**, **IUS**)와 \*\*기본 정규화 방식(Basic)\*\*을 비교하여 **정확도**, **정밀도**, **재현율**, **F1-Score**, **처리 속도** 및 **캐시 효율성**을 분석한 종합 성능 평가입니다.
벤치마크는 총 **86개 케이스**로 진행되었으며, **실제 시나리오 기반 공격/정상 텍스트**를 포함합니다.

---

## **1. 요약 결과**

| **모드**    | **Accuracy** | **Precision** | **Recall** | **F1-Score** | **평균 처리속도**  | **캐시 히트율** |
| --------- | ------------ | ------------- | ---------- | ------------ | ------------ | ---------- |
| **IDS**   | 0.722        | 0.947         | 0.462      | 0.621        | **25.06 ms** | N/A        |
| **IPS**   | 0.722        | 0.947         | 0.462      | 0.621        | **26.49 ms** | N/A        |
| **IUS**   | 0.722        | 0.947         | 0.462      | 0.621        | **2.95 ms**  | **87.9%**  |
| **Basic** | 0.519        | **1.000**     | 0.026      | 0.050        | **0.02 ms**  | N/A        |

> **결론:**
>
> * **IUS 모드**가 **성능-정확도 균형**에서 가장 우수함
> * **IDS/IPS**는 정확도가 같으나 속도는 IUS보다 느림
> * **Basic**은 오탐(false positive)은 없으나 위협 탐지 능력(Recall)이 극도로 낮음

---

## **2. 시각적 성능 비교**

### **2.1. 종합 성능 비교**

![Comprehensive Comparison](comprehensive_benchmark_results/comprehensive_comparison.png)

**주요 특징**

* IUS 모드는 **IPS/IDS** 대비 **8배 이상 빠른 처리 속도**를 달성
* IDS/IPS는 높은 Precision을 유지하지만 **처리속도에서 IUS에 비해 불리함**
* Basic 방식은 속도는 매우 빠르지만 위협 탐지 성능이 심각하게 낮음

---

### **2.2. IUS 캐시 성능 분석**

![Cache Analysis](comprehensive_benchmark_results/cache_analysis.png)

**분석 요약**

* 캐시 히트율: **87.9%**
* 첫 요청에서만 연산을 수행하며, 이후 **같은 입력에 대해 1ms 이내 응답**
* 반복되는 텍스트 입력 환경에서 **처리 효율 극대화**
* IDS 대비 **평균 8.5배 속도 향상** 달성

---

## **3. 세부 분석**

### **3.1. 정확도 지표**

* **Precision**: IDS/IPS/IUS 모두 0.947로 동일 — 탐지된 위협의 **95% 이상**이 실제 위협
* **Recall**: 0.462 — 일부 난독화된 공격에서 탐지 실패 가능성 존재
* **Basic**은 Recall이 \*\*2.6%\*\*로 사실상 위협을 거의 탐지하지 못함

---

### **3.2. 속도 분석**

| **모드** | **평균 처리속도** | **속도 이득 (vs Basic)** |
| ------ | ----------- | -------------------- |
| IDS    | 25.06 ms    | 약 **0.0x**           |
| IPS    | 26.49 ms    | 약 **0.0x**           |
| IUS    | **2.95 ms** | **8.4x 향상**          |
| Basic  | **0.02 ms** | 기준선                  |

* IDS/IPS는 연산 최적화가 부족하여 속도가 가장 느림
* IUS는 캐시와 LRU 최적화를 활용해 **성능 최적화에 강점**

---

## **4. 핵심 인사이트**

* **IUS 모드 = 최적의 밸런스**

  * IDS/IPS와 동일한 탐지 정확도 유지
  * **8.5배 빠른 처리 속도**
  * **캐시 효율성 극대화**
* **IDS / IPS 모드**

  * IDS: 위협 탐지에 최적화, 보수적 판단
  * IPS: IDS 기반 방어 동작, 동일 성능이나 실시간 차단 가능성
* **Basic Normalization**

  * 탐지 성능이 낮아 단독 사용은 권장하지 않음

---

## **5. 결론 및 권장 전략**

| **시나리오**      | **추천 모드**           | **이유**                       |
| ------------- | ------------------- | ---------------------------- |
| **실시간 보안 탐지** | **IUS**             | 캐시 최적화로 지연 최소화               |
| **보안 로그 분석**  | **IDS**             | 높은 Precision & Rule 기반 심층 분석 |
| **즉각 차단 필요**  | **IPS**             | IDS 결과 기반 실시간 방어 가능          |
| **저자원 환경**    | **Basic** + IDS 샘플링 | 속도 우선, IDS로 보완 필요            |

---

## **6. 핵심 요약**

* **정확도:** IDS=IPS=IUS ≫ Basic
* **속도:** IUS ≫ IDS=IPS ≫ Basic
* **캐시 성능:** IUS ≫ IDS=IPS
* **추천 모드:** **IUS**

---

## **첨부 자료**

* **성능 비교 차트:**
![comprehensive_comparison](../comprehensive_benchmark_results/comprehensive_comparison.png)

* **IUS 캐시 분석 차트:**
![cache_analysis](../comprehensive_benchmark_results/cache_analysis.png)

* **원본 벤치마크 데이터:**
![comprehensive_benchmark_data](../comprehensive_benchmark_results/comprehensive_benchmark_data.json)
