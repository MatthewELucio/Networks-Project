# Feature Analysis Summary - LLM vs Non-LLM Classification (Gemini)

## Overview
This analysis examines which features are most important for distinguishing between LLM (Gemini) and non-LLM network flowlets.

## Dataset
- **Total flowlets analyzed**: 75,202
- **LLM flowlets**: 3,064 (4.1%)
- **Non-LLM flowlets**: 72,138 (95.9%)

## Features Analyzed (7 Statistical Features)
1. `duration` - Time span of the flowlet
2. `packet_count` - Number of packets in the flowlet
3. `total_bytes` - Sum of all packet sizes
4. `inter_packet_time_mean` - Average time gap between packets
5. `inter_packet_time_std` - Standard deviation of inter-packet times
6. `packet_size_mean` - Average packet size
7. `packet_size_std` - Standard deviation of packet sizes

## Key Findings

### 1. Most Correlated Features with LLM Label

| Feature | Correlation | Interpretation |
|---------|-------------|----------------|
| **packet_size_std** | **+0.406** | Gemini traffic has highly variable packet sizes |
| **inter_packet_time_std** | **+0.398** | Gemini traffic has highly variable timing |
| **inter_packet_time_mean** | **+0.398** | Gemini traffic has longer gaps between packets |
| **duration** | **+0.303** | Gemini flowlets last longer |
| **packet_count** | +0.176 | Gemini flowlets have more packets |

**Key Insight**: Gemini is characterized by **variability** rather than absolute size:
- Highly variable packet sizes and timing
- Longer flowlet durations
- Different signature than ChatGPT (which is size-based)

### 2. Feature Importance (Random Forest)

| Feature | Importance | Rank |
|---------|------------|------|
| **duration** | **0.210** | 1st |
| **packet_size_mean** | **0.200** | 2nd |
| **packet_count** | **0.184** | 3rd |
| **total_bytes** | **0.182** | 4th |
| **inter_packet_time_mean** | **0.118** | 5th |
| inter_packet_time_std | 0.058 | 6th |
| packet_size_std | 0.048 | 7th |

**Key Insight**: Gemini classification is more **distributed** across features - no single dominant feature like ChatGPT.

### 3. Feature Importance (XGBoost)

| Feature | Importance | Rank |
|---------|------------|------|
| **duration** | **0.912** | 1st |
| packet_size_mean | 0.037 | 2nd |
| packet_count | 0.023 | 3rd |
| total_bytes | 0.017 | 4th |
| packet_size_std | 0.006 | 5th |

**Key Insight**: XGBoost finds **duration overwhelmingly important** (91%!) for Gemini detection.

### 4. Statistical Significance (Mann-Whitney U Test)

**All 7 features are statistically significant (p < 0.05)** in distinguishing Gemini from non-LLM traffic.

#### Effect Sizes (Cohen's d)

| Feature | Cohen's d | Effect Size | Interpretation |
|---------|-----------|-------------|----------------|
| **packet_size_std** | **+0.641** | **Medium** | Strong discriminator |
| **packet_size_mean** | **+0.641** | **Medium** | Strong discriminator |
| **inter_packet_time_std** | **+0.627** | **Medium** | Strong discriminator |
| **inter_packet_time_mean** | **+0.630** | **Medium** | Strong discriminator |
| **duration** | **+0.459** | **Small-Medium** | Moderate discriminator |
| packet_count | +0.258 | Small | Weak discriminator |
| total_bytes | +0.134 | Small | Weak discriminator |

**Key Insight**: Gemini has **multiple medium-effect features** rather than one large-effect feature like ChatGPT.

## Comparison with ChatGPT

### Feature Correlation Differences

| Feature | Gemini | ChatGPT | Difference |
|---------|--------|---------|------------|
| **packet_size_std** | **+0.406** | +0.186 | **+0.220** ⬆️ |
| **inter_packet_time_std** | **+0.398** | +0.179 | **+0.219** ⬆️ |
| **duration** | **+0.303** | +0.115 | **+0.188** ⬆️ |
| packet_size_mean | +0.080 | **+0.291** | **-0.211** ⬇️ |
| total_bytes | +0.085 | +0.165 | -0.080 ⬇️ |

### Key Differences

| Characteristic | ChatGPT | Gemini |
|----------------|---------|--------|
| **Primary Signal** | Packet size (large) | Duration & timing variability |
| **Feature Concentration** | 2 features (93%) | Distributed across many |
| **Effect Size Pattern** | 1 large, rest small | Multiple medium |
| **Detection Difficulty** | Easier (59% recall) | Harder (34% recall) |
| **Best Discriminator** | packet_size_mean | duration |

## Model Performance

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| **Random Forest** | **96.24%** | **86.58%** | 33.83% | 48.65% |
| SVM | 95.98% | 80.84% | 31.09% | 44.91% |
| **XGBoost** | **96.14%** | **86.64%** | 31.59% | 46.29% |

**Performance vs ChatGPT:**
- ✅ Higher accuracy (96% vs 95%)
- ❌ Lower precision (87% vs 98%)
- ❌ Much lower recall (34% vs 59%)
- ❌ Lower F1 score (49% vs 74%)

## Recommendations

### For Improving Gemini Detection

1. **Focus on timing features** - Duration and variability are key
2. **Collect more Gemini data** - Only 3,064 flowlets vs 5,299 for ChatGPT
3. **Feature engineering**:
   - Add burst pattern detection
   - Session-level timing aggregations
   - Sequence-based temporal features

### For Multi-LLM Classification

Since ChatGPT and Gemini have fundamentally different signatures:
- **ChatGPT**: Size-based (large packets)
- **Gemini**: Timing-based (duration, variability)

Use **provider-specific models** rather than one-size-fits-all approach.

## Files Generated

- `model_results_gemini.json` - Model performance metrics
- `analysis_results_gemini.json` - Feature analysis results
- `analysis_plots_gemini/correlation_heatmap.png` - Feature correlations
- `analysis_plots_gemini/feature_importance.png` - RF and XGBoost importance
- `analysis_plots_gemini/feature_distributions.png` - Distribution comparisons
- `analysis_plots_gemini/target_correlations.png` - Target correlations

## Conclusion

**Gemini traffic has a fundamentally different signature than ChatGPT:**

The analysis reveals that Gemini relies on **timing and variability patterns** while ChatGPT relies on **packet size patterns**. This suggests different LLM providers use different streaming architectures, requiring provider-specific detection strategies.

**Key takeaway**: Duration is the most important feature for Gemini detection (91% importance in XGBoost), making it the primary distinguishing characteristic of Gemini network traffic.