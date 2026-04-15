import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TARGET_FOLDERS = ["3providers", "chatgpt", "claude", "gemini"]
MODEL_FILES = ["bidirectional_models", "incoming_models", "outgoing_models"]
OUTPUT_CSV = ROOT / "compiled_model_results.csv"


def safe_get(dct, *keys, default=None):
    cur = dct
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def parse_confusion_matrix(matrix):
    # Expected format: [[tn, fp], [fn, tp]]
    if (
        isinstance(matrix, list)
        and len(matrix) == 2
        and all(isinstance(row, list) and len(row) == 2 for row in matrix)
    ):
        return matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]
    return None, None, None, None


def flatten_records(folder_name, file_name, payload):
    dataset = payload.get("dataset_info", {})
    models = payload.get("models", {})

    llm_sources = dataset.get("llm_sources")
    if isinstance(llm_sources, list):
        llm_sources = ";".join(str(x) for x in llm_sources)

    input_sources = dataset.get("input_sources")
    if isinstance(input_sources, list):
        input_sources = ";".join(str(x) for x in input_sources)

    filter_stats = dataset.get("filter_stats", {})

    rows = []
    for model_name, metrics in models.items():
        cm_tn, cm_fp, cm_fn, cm_tp = parse_confusion_matrix(metrics.get("confusion_matrix"))
        report = metrics.get("classification_report", {})

        row = {
            "folder": folder_name,
            "source_file": file_name,
            "direction": dataset.get("direction"),
            "llm_sources": llm_sources,
            "total_flowlets": dataset.get("total_flowlets"),
            "train_size": dataset.get("train_size"),
            "test_size": dataset.get("test_size"),
            "feature_dim": dataset.get("feature_dim"),
            "train_class_distribution": json.dumps(dataset.get("train_class_distribution")),
            "test_class_distribution": json.dumps(dataset.get("test_class_distribution")),
            "kept_llm": filter_stats.get("kept_llm"),
            "kept_non_llm": filter_stats.get("kept_non_llm"),
            "skipped_llm_source": filter_stats.get("skipped_llm_source"),
            "skipped_llm_direction": filter_stats.get("skipped_llm_direction"),
            "skipped_other": filter_stats.get("skipped_other"),
            "input_sources": input_sources,
            "model": model_name,
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1": metrics.get("f1"),
            "cm_tn": cm_tn,
            "cm_fp": cm_fp,
            "cm_fn": cm_fn,
            "cm_tp": cm_tp,
            "non_llm_precision": safe_get(report, "non_llm", "precision"),
            "non_llm_recall": safe_get(report, "non_llm", "recall"),
            "non_llm_f1": safe_get(report, "non_llm", "f1-score"),
            "non_llm_support": safe_get(report, "non_llm", "support"),
            "llm_precision": safe_get(report, "llm", "precision"),
            "llm_recall": safe_get(report, "llm", "recall"),
            "llm_f1": safe_get(report, "llm", "f1-score"),
            "llm_support": safe_get(report, "llm", "support"),
            "macro_precision": safe_get(report, "macro avg", "precision"),
            "macro_recall": safe_get(report, "macro avg", "recall"),
            "macro_f1": safe_get(report, "macro avg", "f1-score"),
            "macro_support": safe_get(report, "macro avg", "support"),
            "weighted_precision": safe_get(report, "weighted avg", "precision"),
            "weighted_recall": safe_get(report, "weighted avg", "recall"),
            "weighted_f1": safe_get(report, "weighted avg", "f1-score"),
            "weighted_support": safe_get(report, "weighted avg", "support"),
        }
        rows.append(row)

    return rows


def main():
    all_rows = []
    missing_files = []

    for folder in TARGET_FOLDERS:
        folder_path = ROOT / folder
        for file_name in MODEL_FILES:
            file_path = folder_path / file_name
            if not file_path.exists():
                missing_files.append(str(file_path))
                continue

            try:
                with file_path.open("r", encoding="utf-8") as f:
                    payload = json.load(f)
            except Exception as exc:
                print(f"Skipping {file_path}: {exc}")
                continue

            all_rows.extend(flatten_records(folder, file_name, payload))

    if not all_rows:
        raise RuntimeError("No model records found. Check source files and JSON structure.")

    fieldnames = list(all_rows[0].keys())

    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Wrote {len(all_rows)} rows to: {OUTPUT_CSV}")
    if missing_files:
        print("Missing files:")
        for path in missing_files:
            print(f"  - {path}")


if __name__ == "__main__":
    main()
