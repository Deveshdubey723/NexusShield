"""Optional supervised evaluation. Input must be a genuine, labeled dataset."""

from __future__ import annotations

import io
import argparse
import json
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

LABELS = {"scam", "legitimate"}
MAX_ROWS = 100_000


class DatasetError(ValueError):
    pass


def evaluate_dataset(csv_text: str) -> dict:
    """Train/test on supplied real examples; nothing is fabricated or saved."""
    try:
        frame = pd.read_csv(io.StringIO(csv_text), dtype=str, keep_default_na=False)
        columns = {str(name).strip().lower(): name for name in frame.columns}
        if not {"text", "label"}.issubset(columns):
            raise DatasetError("CSV must have 'text' and 'label' columns.")
        text_column = columns["text"]
        label_column = columns["label"]
        rows = [
            (str(text).strip(), str(label).strip().lower())
            for text, label in zip(frame[text_column], frame[label_column], strict=True)
        ]
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        raise DatasetError("Could not parse the supplied CSV dataset.") from exc
    rows = [(text, label) for text, label in rows if text and label]
    if len(rows) > MAX_ROWS:
        raise DatasetError(f"Dataset exceeds the {MAX_ROWS} row limit.")
    if len(rows) < 10:
        raise DatasetError("At least 10 labeled examples are required for evaluation.")
    labels = [label for _, label in rows]
    counts = Counter(labels)
    if not set(labels).issubset(LABELS):
        raise DatasetError("Labels must be exactly 'scam' or 'legitimate'.")
    if len(counts) != 2 or min(counts.values()) < 2:
        raise DatasetError("Both labels need at least two examples.")
    texts = [text for text, _ in rows]
    try:
        train_x, test_x, train_y, test_y = train_test_split(
            texts, labels, test_size=0.25, random_state=42, stratify=labels
        )
        model = make_pipeline(
            TfidfVectorizer(ngram_range=(1, 2), max_features=20_000),
            LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced"),
        )
        model.fit(train_x, train_y)
        predictions = model.predict(test_x)
    except ValueError as exc:
        raise DatasetError(
            "Dataset cannot be split or vectorized; provide enough varied labeled text."
        ) from exc
    matrix = confusion_matrix(
        test_y, predictions, labels=["legitimate", "scam"]
    ).tolist()
    report = classification_report(
        test_y, predictions, labels=["legitimate", "scam"], output_dict=True, zero_division=0
    )
    return {
        "dataset_rows": len(rows),
        "train_rows": len(train_x),
        "test_rows": len(test_x),
        "label_counts": dict(counts),
        "accuracy": round(float(accuracy_score(test_y, predictions)), 4),
        "classification_report": report,
        "confusion_matrix": {
            "labels": ["legitimate", "scam"],
            "matrix": matrix,
        },
        "note": (
            "Evaluation metrics describe this supplied dataset and are not guarantees of "
            "real-world performance. Use only genuine, appropriately collected labeled data; "
            "no synthetic examples were generated."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate a genuine labeled CSV dataset without saving a trained model."
    )
    parser.add_argument("dataset", type=Path, help="CSV file with text,label columns")
    args = parser.parse_args()
    try:
        result = evaluate_dataset(args.dataset.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, DatasetError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
