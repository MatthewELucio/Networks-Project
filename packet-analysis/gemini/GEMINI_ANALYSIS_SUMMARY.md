# Gemini Feature Analysis Summary - LLM vs Non-LLM Classification

## Overview
Analysis of which features are most important for distinguishing between Gemini and non-LLM network flowlets.

## Dataset
- **Total flowlets analyzed**: 75,202
- **Gemini flowlets**: 3,064 (4.1%)
- **Non-LLM flowlets**: 72,138 (95.9%)

## Key Findings - Gemini vs ChatGPT

### Most Correlated Features with LLM Label

| Feature | Gemini Correlation | ChatGPT Correlation | Difference |
|---------|-------------------|---------------------|------------|
| **packet_size_std** | **+0.406** | +0.186 | **+0.220** ⬆️ |
| **inter_packet_time_std** | **+0.398** | +0.179 | **+0.219** ⬆️ |
| **inter_packet_time_mean** | **+0.398** | +0.181 | **+0.217** ⬆️ |
| **duration** | **+0.303** | +0.115 | **+0.188** ⬆️ |
| packet_count | +0.176 | +0.139 | +0.037 |
| total_bytes | +0.085 | +0.165 | -0.080 ⬇️ |
| packet_size_mean | +0.080 | **+0.291** | **-0.211** ⬇️ |

**Key Insight**: Gemini traffic is characterized by **variability** (std dev features) rather than absolute size. ChatGPT is characterized by **packet size mean**.

### Feature Importance Comparison

#### Random Forest

| Feature | Gemini | ChatGPT | Difference |
|---------|--------|---------|------------|
| duration | **21.0%** | 2.5% | **+18.5%** ⬆️ |
| packet_size_mean | **20.0%** | **48.0%** | **-28.0%** ⬇️ |
| packet_count | 18.4% | 1.6% | +16.8% ⬆️ |
| total_bytes | 18.2% | **45.3%** | **-27.1%** ⬇️ |
| inter_packet_time_mean | 11.8% | 1.7% | +10.1% ⬆️ |

**Key Insight**: Gemini classification relies on **more diverse features** (no single dominant feature), while ChatGPT relies heavily on just 2 features.

#### XGBoost

| Feature | Gemini | ChatGPT | Difference |
|---------|--------|---------|------------|
| **duration** | **91.2%** | 11.3% | **+79.9%** ⬆️ |
| packet_size_mean | 3.7% | **42.3%** | **-38.6%** ⬇️ |
| packet_count | 2.3% | 0.5% | +1.8% |
| total_bytes | 1.7% | **42.1%** | **-40.4%** ⬇️ |

**Key Insight**: XGBoost finds **duration** overwhelmingly important for Gemini (91%!), suggesting Gemini sessions have distinctive timing patterns.

### Effect Sizes (Cohen's d)

| Feature | Gemini | ChatGPT | Effect Size Category |
|---------|--------|---------|---------------------|
| packet_size_std | **+0.641** | +0.277 | Medium → Medium |
| packet_size_mean | **+0.641** | **+0.808** | Medium → **Large** |
| inter_packet_time_std | **+0.627** | +0.267 | Medium → Small |
| inter_packet_time_mean | **+0.630** | +0.271 | Medium → Small |
| duration | **+0.459** | +0.169 | Small → Small |
| packet_count | +0.258 | +0.206 | Small → Small |
| total_bytes | +0.134 | +0.248 | Small → Small |

**Key Insight**: Gemini has **medium effect sizes** across multiple features, while ChatGPT has one **large effect** (packet_size_mean) and many small effects.

## Model Performance Comparison

### Gemini vs Non-LLM

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 96.24% | 86.58% | 33.83% | 48.65% |
| SVM | 95.98% | 80.84% | 31.09% | 44.91% |
| XGBoost | 96.14% | 86.64% | 31.59% | 46.29% |

### ChatGPT vs Non-LLM

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 95.04% | 98.03% | 59.23% | 73.85% |
| SVM | 94.63% | 93.78% | 58.46% | 72.02% |
| XGBoost | 95.00% | 97.77% | 59.08% | 73.65% |

### Performance Comparison

| Metric | Gemini | ChatGPT | Winner |
|--------|--------|---------|--------|
| Accuracy | 96.24% | 95.04% | ✅ Gemini (+1.2%) |
| Precision | 86.58% | 98.03% | ❌ ChatGPT (+11.5%) |
| Recall | 33.83% | 59.23% | ❌ ChatGPT (+25.4%) |
| F1 Score | 48.65% | 73.85% | ❌ ChatGPT (+25.2%) |

**Key Insight**: Gemini is **much harder to detect** than ChatGPT:
- Higher accuracy but much lower recall (misses 66% of Gemini traffic)
- Lower precision (more false positives)
- Overall worse F1 score

## Why Gemini is Harder to Detect

### 1. Different Traffic Patterns
- **ChatGPT**: Large, consistent packet sizes (streaming text)
- **Gemini**: More variable timing and packet sizes (different architecture?)

### 2. Feature Distribution
- **ChatGPT**: Dominated by 2 features (packet_size_mean, total_bytes)
- **Gemini**: Spread across many features (duration, timing variability, packet variability)

### 3. Dataset Size
- **ChatGPT**: 5,299 flowlets (more training data)
- **Gemini**: 3,064 flowlets (42% less data)

### 4. Signature Strength
- **ChatGPT**: Strong, consistent signature (large effect size on packet_size_mean)
- **Gemini**: Weaker, distributed signature (medium effect sizes across multiple features)

## Recommendations

### For Improving Gemini Detection

1. **Collect more Gemini data** - 3,064 flowlets may not be enough
2. **Focus on timing features** - Duration and inter-packet timing are key
3. **Use ensemble methods** - Combine multiple weak signals
4. **Feature engineering**:
   - Add burst detection (Gemini may have different burst patterns)
   - Add session-level features (aggregate across multiple flowlets)
   - Add sequence-based features (temporal patterns)

### For Multi-LLM Detection

Since ChatGPT and Gemini have **very different signatures**:
- **ChatGPT**: Size-based (large packets)
- **Gemini**: Timing-based (duration, variability)

A multi-class classifier should:
1. Use **all features** (don't drop any)
2. Consider **hierarchical classification**:
   - First: LLM vs non-LLM
   - Second: ChatGPT vs Gemini vs Claude
3. Use **provider-specific models** rather than one-size-fits-all

## Files Generated

- `model_results_gemini.json` - Model performance metrics
- `analysis_results_gemini.json` - Feature analysis results
- `analysis_plots_gemini/correlation_heatmap.png` - Feature correlations
- `analysis_plots_gemini/feature_importance.png` - RF and XGBoost importance
- `analysis_plots_gemini/feature_distributions.png` - Distribution comparisons
- `analysis_plots_gemini/target_correlations.png` - Target correlations

## Conclusion

**Gemini traffic has a fundamentally different signature than ChatGPT:**

| Characteristic | ChatGPT | Gemini |
|----------------|---------|--------|
| **Primary Signal** | Packet size (large) | Duration & timing variability |
| **Feature Concentration** | 2 features (93%) | Distributed (no single dominant) |
| **Effect Size** | 1 large, rest small | Multiple medium |
| **Detection Difficulty** | Easier (59% recall) | Harder (34% recall) |
| **Best Feature** | packet_size_mean | duration |

This suggests different LLM providers use **different streaming architectures** or **different protocols**, requiring provider-specific detection strategies.
