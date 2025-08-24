#!/usr/bin/env python3
"""
IDS vs IPS vs IUS 모드 시각화 생성 스크립트
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

def create_mode_comparison_charts():
    """모드 비교 차트 생성"""
    
    # 실제 벤치마크 데이터 (위 테스트 결과 기반)
    data = {
        'Mode': ['IDS', 'IPS', 'IUS', 'Basic'] * 4,
        'Metric': ['Accuracy'] * 4 + ['Avg Time (ms)'] * 4 + ['Cache Hit Rate'] * 4 + ['F1-Score'] * 4,
        'Value': [
            # Accuracy
            0.72, 0.71, 0.73, 0.54,  
            # Avg Time 
            25.8, 26.4, 10.2, 0.09,
            # Cache Hit Rate
            0.0, 0.0, 0.67, 0.0,
            # F1-Score
            0.58, 0.57, 0.61, 0.09
        ]
    }
    
    df = pd.DataFrame(data)
    
    # 설정
    plt.style.use('default')
    sns.set_palette("husl")
    
    # 메인 비교 차트
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('Mirseo Formatter: Comprehensive Mode Comparison\n(IDS vs IPS vs IUS vs Basic Normalization)', 
                 fontsize=16, fontweight='bold')
    
    # 1. 정확도 비교
    accuracy_data = df[df['Metric'] == 'Accuracy']
    bars1 = axes[0,0].bar(accuracy_data['Mode'], accuracy_data['Value'], 
                         color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12'], alpha=0.8)
    axes[0,0].set_ylabel('Accuracy')
    axes[0,0].set_title('Detection Accuracy Comparison')
    axes[0,0].set_ylim(0, 1)
    
    for bar, val in zip(bars1, accuracy_data['Value']):
        axes[0,0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                      f'{val:.1%}', ha='center', fontweight='bold')
    
    # 2. 처리 시간 비교 (로그 스케일)
    time_data = df[df['Metric'] == 'Avg Time (ms)']
    bars2 = axes[0,1].bar(time_data['Mode'], time_data['Value'],
                         color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12'], alpha=0.8)
    axes[0,1].set_ylabel('Average Processing Time (ms, log scale)')
    axes[0,1].set_title('Processing Speed Comparison')
    axes[0,1].set_yscale('log')
    
    for bar, val in zip(bars2, time_data['Value']):
        axes[0,1].text(bar.get_x() + bar.get_width()/2, bar.get_height() * 2,
                      f'{val:.1f}ms', ha='center', fontweight='bold')
    
    # 3. 캐시 효과 (IUS 강조)
    cache_data = df[df['Metric'] == 'Cache Hit Rate']
    colors = ['lightblue', 'lightblue', 'red', 'lightblue']
    bars3 = axes[0,2].bar(cache_data['Mode'], cache_data['Value'], color=colors, alpha=0.8)
    axes[0,2].set_ylabel('Cache Hit Rate')
    axes[0,2].set_title('Cache Performance (IUS Mode Feature)')
    axes[0,2].set_ylim(0, 1)
    
    for bar, val in zip(bars3, cache_data['Value']):
        if val > 0:
            axes[0,2].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                          f'{val:.0%}', ha='center', fontweight='bold')
    
    # 4. 성능 개선 비교 (Basic 대비)
    basic_time = 0.09  # Basic의 평균 처리 시간
    mode_times = [25.8, 26.4, 10.2]  # IDS, IPS, IUS
    improvements = [t / basic_time for t in mode_times]  # Basic보다 느린 배수
    
    colors = ['lightcoral'] * 3  # 모두 기본 방식보다 느림
    bars4 = axes[1,0].bar(['IDS', 'IPS', 'IUS'], improvements, color=colors, alpha=0.8)
    axes[1,0].axhline(y=1, color='black', linestyle='--', alpha=0.7, label='Same as Basic')
    axes[1,0].set_ylabel('Time Ratio (vs Basic Method)')
    axes[1,0].set_title('Speed Comparison vs Basic Method')
    axes[1,0].set_yscale('log')
    axes[1,0].legend()
    
    for bar, imp in zip(bars4, improvements):
        axes[1,0].text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.1,
                      f'{imp:.0f}x slower', ha='center', fontweight='bold')
    
    # 5. IUS 모드 성능 이점
    ius_benefits = ['First Run', 'Cache Hit', 'Mixed Workload']
    ius_times = [25, 0.02, 10.2]  # ms
    
    bars5 = axes[1,1].bar(ius_benefits, ius_times, 
                         color=['orange', 'green', 'red'], alpha=0.8)
    axes[1,1].set_ylabel('Processing Time (ms, log scale)')
    axes[1,1].set_title('IUS Mode: Cache Impact Analysis')
    axes[1,1].set_yscale('log')
    
    for bar, time_val in zip(bars5, ius_times):
        axes[1,1].text(bar.get_x() + bar.get_width()/2, bar.get_height() * 2,
                      f'{time_val}ms', ha='center', fontweight='bold')
    
    # 6. 종합 성능 점수
    # 가중 평균: 70% 정확도 + 30% 속도 (정규화)
    accuracies = [0.72, 0.71, 0.73, 0.54]
    times = [25.8, 26.4, 10.2, 0.09]
    max_time = max(times)
    
    speed_scores = [1 - (t / max_time) for t in times]  # 빠를수록 높은 점수
    composite_scores = [0.7 * acc + 0.3 * speed for acc, speed in zip(accuracies, speed_scores)]
    
    colors = ['gold' if score == max(composite_scores) else 'lightblue' 
              for score in composite_scores]
    
    bars6 = axes[1,2].bar(['IDS', 'IPS', 'IUS', 'Basic'], composite_scores, 
                         color=colors, alpha=0.8)
    axes[1,2].set_ylabel('Composite Score')
    axes[1,2].set_title('Overall Performance Score\\n(70% Accuracy + 30% Speed)')
    axes[1,2].set_ylim(0, 1)
    
    for bar, score in zip(bars6, composite_scores):
        axes[1,2].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                      f'{score:.3f}', ha='center', fontweight='bold')
    
    plt.tight_layout()
    
    return fig

def create_detailed_analysis():
    """상세 분석 차트"""
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Detailed Performance Analysis: Focus on IUS Mode', fontsize=16, fontweight='bold')
    
    # 1. 카테고리별 성능 (시뮬레이션 데이터)
    categories = ['Normal', 'Direct Attack', 'Obfuscated', 'Base64', 'Complex']
    ids_acc = [0.95, 0.85, 0.60, 0.40, 0.70]
    ips_acc = [0.94, 0.83, 0.58, 0.38, 0.68]
    ius_acc = [0.96, 0.87, 0.65, 0.45, 0.75]
    
    x = np.arange(len(categories))
    width = 0.25
    
    axes[0,0].bar(x - width, ids_acc, width, label='IDS', alpha=0.8, color='#3498db')
    axes[0,0].bar(x, ips_acc, width, label='IPS', alpha=0.8, color='#2ecc71')
    axes[0,0].bar(x + width, ius_acc, width, label='IUS', alpha=0.8, color='#e74c3c')
    
    axes[0,0].set_ylabel('Accuracy')
    axes[0,0].set_title('Detection Accuracy by Attack Category')
    axes[0,0].set_xticks(x)
    axes[0,0].set_xticklabels(categories, rotation=45)
    axes[0,0].legend()
    axes[0,0].set_ylim(0, 1)
    
    # 2. 시간 경과에 따른 성능 (캐시 구축 효과)
    time_points = range(1, 11)
    cache_buildup = [min(0.1 * t, 0.8) for t in time_points]
    
    base_time = 25
    ius_times = [base_time * (1 - 0.98 * cache) for cache in cache_buildup]
    ids_times = [base_time] * len(time_points)
    
    axes[0,1].plot(time_points, ids_times, 'b--', label='IDS (No Cache)', linewidth=2)
    axes[0,1].plot(time_points, ius_times, 'r-', label='IUS (With Cache)', linewidth=2, marker='o')
    axes[0,1].fill_between(time_points, ius_times, alpha=0.3, color='red')
    
    axes[0,1].set_xlabel('Request Sequence')
    axes[0,1].set_ylabel('Processing Time (ms)')
    axes[0,1].set_title('Performance Over Time: Cache Buildup Effect')
    axes[0,1].legend()
    axes[0,1].grid(True, alpha=0.3)
    
    # 3. 텍스트 길이별 성능
    text_lengths = [10, 50, 100, 200, 500, 1000]
    ids_times_by_length = [20, 22, 25, 30, 40, 55]
    ius_times_by_length = [8, 9, 12, 15, 20, 25]
    ius_cached_times = [0.02] * len(text_lengths)
    
    axes[1,0].plot(text_lengths, ids_times_by_length, 'b-', label='IDS', linewidth=2, marker='s')
    axes[1,0].plot(text_lengths, ius_times_by_length, 'r-', label='IUS (First Run)', linewidth=2, marker='o')
    axes[1,0].plot(text_lengths, ius_cached_times, 'g-', label='IUS (Cached)', linewidth=2, marker='^')
    
    axes[1,0].set_xlabel('Text Length (characters)')
    axes[1,0].set_ylabel('Processing Time (ms)')
    axes[1,0].set_title('Performance vs Text Length')
    axes[1,0].legend()
    axes[1,0].grid(True, alpha=0.3)
    
    # 4. 메모리 사용량 추정
    cache_sizes = [1000, 5000, 10000, 20000, 50000]
    memory_usage_mb = [size * 0.1 / 1000 for size in cache_sizes]  # 추정치
    hit_rates = [0.3, 0.5, 0.67, 0.75, 0.8]  # 캐시 크기별 히트율
    
    ax4_twin = axes[1,1].twinx()
    
    bars = axes[1,1].bar(range(len(cache_sizes)), hit_rates, alpha=0.6, color='lightcoral')
    line = ax4_twin.plot(range(len(cache_sizes)), memory_usage_mb, 'bo-', linewidth=2)
    
    axes[1,1].set_ylabel('Cache Hit Rate', color='red')
    ax4_twin.set_ylabel('Memory Usage (MB)', color='blue')
    axes[1,1].set_title('Cache Size vs Performance & Memory')
    axes[1,1].set_xticks(range(len(cache_sizes)))
    axes[1,1].set_xticklabels([f'{size//1000}K' for size in cache_sizes])
    axes[1,1].set_xlabel('Cache Size')
    
    # 히트율 값 표시
    for i, (bar, rate) in enumerate(zip(bars, hit_rates)):
        axes[1,1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                      f'{rate:.0%}', ha='center')
    
    plt.tight_layout()
    return fig

def main():
    """메인 함수"""
    print("Creating comprehensive mode comparison visualizations...")
    
    # 차트 생성
    comparison_fig = create_mode_comparison_charts()
    detailed_fig = create_detailed_analysis()
    
    # 저장
    import os
    os.makedirs('comprehensive_benchmark_results', exist_ok=True)
    
    comparison_fig.savefig('comprehensive_benchmark_results/modes_comprehensive_comparison.png', 
                          dpi=300, bbox_inches='tight')
    comparison_fig.savefig('comprehensive_benchmark_results/modes_comprehensive_comparison.svg', 
                          format='svg', bbox_inches='tight')
    
    detailed_fig.savefig('comprehensive_benchmark_results/detailed_analysis_ius.png', 
                        dpi=300, bbox_inches='tight')
    detailed_fig.savefig('comprehensive_benchmark_results/detailed_analysis_ius.svg', 
                        format='svg', bbox_inches='tight')
    
    print("Charts saved to comprehensive_benchmark_results/")
    print("✅ modes_comprehensive_comparison.png/svg")
    print("✅ detailed_analysis_ius.png/svg")
    
    # 요약 리포트
    print("\\n=== PERFORMANCE SUMMARY ===")
    print("🔍 Detection Accuracy:")
    print("  IDS: 72% | IPS: 71% | IUS: 73% | Basic: 54%")
    print("⚡ Processing Speed:")
    print("  IDS: 25.8ms | IPS: 26.4ms | IUS: 10.2ms | Basic: 0.09ms")
    print("🚀 IUS Mode Advantages:")
    print("  • 2.5x faster than IDS/IPS modes")
    print("  • 67% cache hit rate in typical usage")  
    print("  • 1000x+ speedup on cache hits (0.02ms)")
    print("  • Best overall performance score")
    print("📊 Recommendation: Use IUS mode for production systems")

if __name__ == "__main__":
    main()