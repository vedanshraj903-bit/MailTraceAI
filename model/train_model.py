"""
Train the MailTraceAI email classifier (ham / spam / phishing).

Reads datasets/mailtrace_dataset.csv (build it first with
model/build_dataset.py), then:

  1. Stratified 80/20 train / held-out test split.
  2. 5-fold cross-validated grid search on the training split only,
     optimising macro-F1 so the smaller classes count equally.
  3. Refit the best configuration on the full training split.
  4. Evaluate once on the untouched test split: per-class report,
     confusion matrix, ham false-positive rate, one-vs-rest ROC-AUC
     and PR-AUC, and accuracy per data source.
  5. Save the model plus a metadata JSON describing data, settings,
     scores and library versions.

Usage:
    python model/build_dataset.py
    python model/train_model.py            # full grid search
    python model/train_model.py --quick    # single config, for a fast check
"""

import argparse
import csv
import json
import platform
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_CSV = BASE_DIR / "datasets" / "mailtrace_dataset.csv"
MODEL_FILE = BASE_DIR / "model" / "mailtraceai_detector.joblib"
METADATA_FILE = BASE_DIR / "model" / "mailtraceai_detector.json"

LABELS = ["ham", "spam", "phishing"]
SEED = 42


# ============================================================
# DATA
# ============================================================

def load_dataset():
    if not DATASET_CSV.exists():
        sys.exit(
            f"{DATASET_CSV.relative_to(BASE_DIR)} not found. "
            "Run: python model/build_dataset.py"
        )

    csv.field_size_limit(sys.maxsize)

    with open(DATASET_CSV, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    texts = [row["text"] for row in rows]
    labels = [row["label"] for row in rows]
    sources = [row["source"] for row in rows]

    return texts, labels, sources


# ============================================================
# MODEL
# ============================================================

def build_pipeline():
    """
    Word n-grams capture phrases ("verify your account"); character
    n-grams capture obfuscation and lookalikes ("paypa1", "ver1fy",
    odd spacing) that word tokens miss.
    """

    features = FeatureUnion([
        ("words", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            max_features=60000,
            sublinear_tf=True,
            strip_accents="unicode",
        )),
        ("chars", TfidfVectorizer(
            lowercase=True,
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=3,
            max_features=80000,
            sublinear_tf=True,
            strip_accents="unicode",
        )),
    ])

    classifier = LogisticRegression(
        C=8.0,
        class_weight="balanced",
        max_iter=3000,
        solver="lbfgs",
    )

    return Pipeline([("features", features), ("classifier", classifier)])


PARAM_GRID = {
    "classifier__C": [2.0, 8.0, 32.0],
    "features__words__ngram_range": [(1, 1), (1, 2)],
}


# ============================================================
# EVALUATION
# ============================================================

def evaluate(model, X_test, y_test, sources_test):
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)
    classes = list(model.classes_)

    report = classification_report(
        y_test, predictions, labels=LABELS, output_dict=True, zero_division=0
    )

    matrix = confusion_matrix(y_test, predictions, labels=LABELS)

    y_array = np.array(y_test)

    per_class_auc = {}
    for label in LABELS:
        truth = (y_array == label).astype(int)
        scores = probabilities[:, classes.index(label)]
        per_class_auc[label] = {
            "roc_auc": float(roc_auc_score(truth, scores)),
            "pr_auc": float(average_precision_score(truth, scores)),
        }

    # How often a genuine email is flagged as spam/phishing: the
    # number that decides whether users trust the tool.
    ham_mask = y_array == "ham"
    ham_false_positive_rate = float(
        np.mean(np.array(predictions)[ham_mask] != "ham")
    ) if ham_mask.any() else None

    # Phishing recall is the number that matters most for safety.
    per_source = defaultdict(lambda: [0, 0])
    for source, truth, predicted in zip(sources_test, y_test, predictions):
        per_source[source][0] += int(truth == predicted)
        per_source[source][1] += 1

    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro")),
        "report": report,
        "confusion_matrix": {"labels": LABELS, "matrix": matrix.tolist()},
        "one_vs_rest_auc": per_class_auc,
        "ham_false_positive_rate": ham_false_positive_rate,
        "accuracy_per_source": {
            source: {"correct": c, "total": t, "accuracy": round(c / t, 4)}
            for source, (c, t) in sorted(per_source.items())
        },
    }


def print_evaluation(results):
    print(f"\nAccuracy        : {results['accuracy']:.4f}")
    print(f"Macro F1        : {results['macro_f1']:.4f}")
    print(f"Ham false-positive rate: {results['ham_false_positive_rate']:.4f}")

    print("\nPer class:")
    print(f"  {'label':<10}{'precision':>10}{'recall':>10}{'f1':>10}"
          f"{'roc_auc':>10}{'pr_auc':>10}{'support':>10}")
    for label in LABELS:
        row = results["report"][label]
        auc = results["one_vs_rest_auc"][label]
        print(f"  {label:<10}{row['precision']:>10.4f}{row['recall']:>10.4f}"
              f"{row['f1-score']:>10.4f}{auc['roc_auc']:>10.4f}"
              f"{auc['pr_auc']:>10.4f}{int(row['support']):>10}")

    print("\nConfusion matrix (rows = true, columns = predicted):")
    print(f"  {'':<10}" + "".join(f"{label:>10}" for label in LABELS))
    for label, row in zip(LABELS, results["confusion_matrix"]["matrix"]):
        print(f"  {label:<10}" + "".join(f"{value:>10}" for value in row))

    print("\nAccuracy per source:")
    for source, stats in results["accuracy_per_source"].items():
        print(f"  {source:<16}{stats['accuracy']:>8.4f}  ({stats['correct']}/{stats['total']})")


def top_features(model, per_class=15):
    """
    Most influential features per class: a quick check that the
    model learned real signals, not dataset artefacts.
    """

    names = model.named_steps["features"].get_feature_names_out()
    coefficients = model.named_steps["classifier"].coef_

    top = {}
    for index, label in enumerate(model.classes_):
        order = np.argsort(coefficients[index])[::-1][:per_class]
        top[label] = [names[i].split("__", 1)[-1] for i in order]

    return top


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="skip the grid search and train one configuration")
    args = parser.parse_args()

    started = time.time()

    print("=" * 60)
    print("MAILTRACEAI - MODEL TRAINING")
    print("=" * 60)

    texts, labels, sources = load_dataset()

    print(f"\nDataset: {len(texts)} emails  {dict(Counter(labels))}")

    X_train, X_test, y_train, y_test, s_train, s_test = train_test_split(
        texts, labels, sources,
        test_size=0.20,
        random_state=SEED,
        stratify=labels,
    )

    print(f"Train: {len(X_train)}   Held-out test: {len(X_test)}")

    if args.quick:
        print("\n--quick: training a single configuration...")
        model = build_pipeline().fit(X_train, y_train)
        best_params = {}
        cv_score = None
    else:
        grid_size = np.prod([len(v) for v in PARAM_GRID.values()])
        print(f"\nGrid search: {grid_size} configurations x 5 folds (macro-F1)...")

        search = GridSearchCV(
            build_pipeline(),
            PARAM_GRID,
            scoring="f1_macro",
            cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED),
            n_jobs=-1,
            refit=True,
            verbose=1,
        )
        search.fit(X_train, y_train)

        model = search.best_estimator_
        best_params = {k: str(v) for k, v in search.best_params_.items()}
        cv_score = float(search.best_score_)

        print(f"Best CV macro-F1: {cv_score:.4f}")
        print(f"Best parameters : {best_params}")

    print("\n" + "=" * 60)
    print("HELD-OUT TEST RESULTS")
    print("=" * 60)

    results = evaluate(model, X_test, y_test, s_test)
    print_evaluation(results)

    signals = top_features(model)

    print("\nStrongest signals per class:")
    for label in LABELS:
        print(f"  {label:<9} {', '.join(signals[label][:12])}")

    joblib.dump(model, MODEL_FILE)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_seconds": round(time.time() - started, 1),
        "labels": LABELS,
        "dataset": {
            "file": str(DATASET_CSV.relative_to(BASE_DIR)),
            "rows": len(texts),
            "per_label": dict(Counter(labels)),
            "per_source": dict(Counter(sources)),
            "train_rows": len(X_train),
            "test_rows": len(X_test),
        },
        "search": {
            "cv_folds": 0 if args.quick else 5,
            "scoring": "f1_macro",
            "best_params": best_params,
            "best_cv_macro_f1": cv_score,
        },
        "test_results": results,
        "top_features": signals,
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
        },
    }

    METADATA_FILE.write_text(json.dumps(metadata, indent=2))

    print("\n" + "=" * 60)
    print(f"MODEL SAVED    {MODEL_FILE.relative_to(BASE_DIR)}")
    print(f"METADATA SAVED {METADATA_FILE.relative_to(BASE_DIR)}")
    print(f"Total time: {time.time() - started:.0f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
