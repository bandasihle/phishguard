"""
Train the phishing URL classifier.

Usage:
    python train_model.py                          # uses Training Dataset.arff (UCI)
    python train_model.py path/to/urls.csv         # CSV with columns: url, label (0/1)

The ARFF dataset uses pre-extracted binary features (-1/0/1 encoding).
The CSV mode extracts features from raw URLs using feature_extractor.py.
"""

import pickle
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from feature_extractor import FEATURE_NAMES, extract_features

ARFF_PATH = "../Training Dataset.arff"


def load_arff(path: str):
    rows = []
    in_data = False
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.lower() == "@data":
                in_data = True
                continue
            if in_data and line and not line.startswith("%"):
                try:
                    vals = [int(v) for v in line.split(",")]
                    if len(vals) == 31:
                        rows.append(vals)
                except ValueError:
                    continue

    data = np.array(rows)
    X = data[:, :30]
    y = np.where(data[:, 30] == 1, 0, 1)  # ARFF: 1=legit→0, -1=phishing→1
    return X, y


def load_csv(path: str):
    import pandas as pd
    df = pd.read_csv(path)
    df.columns = df.columns.str.lower().str.strip()
    urls = df["url"].tolist()
    labels = df["label"].tolist()
    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)
    return X, y


def train(data_path: str = None):
    print("\n[phish-detector] training\n")

    if data_path and data_path.endswith(".csv"):
        print(f"source : {data_path} (url csv)")
        X, y = load_csv(data_path)
    else:
        path = data_path or ARFF_PATH
        print(f"source : {path} (uci arff)")
        X, y = load_arff(path)

    print(f"samples: {len(y)}  phishing={y.sum()}  legit={len(y)-y.sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\naccuracy: {acc:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("top features:")
    for name, imp in importances[:5]:
        print(f"  {name:<32} {imp:.4f}")

    with open("model.pkl", "wb") as f:
        pickle.dump({"model": clf, "feature_names": FEATURE_NAMES, "accuracy": acc}, f)

    print("\nmodel saved → model.pkl\n")


if __name__ == "__main__":
    train(sys.argv[1] if len(sys.argv) > 1 else None)
