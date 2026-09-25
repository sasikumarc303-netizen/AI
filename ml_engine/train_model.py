"""Train the demonstration malware-classification model.

IMPORTANT (honesty note): this trains on a SYNTHETIC feature dataset that
mirrors the extractor in `features.py`. The reported accuracy is the REAL,
measured hold-out accuracy of this model on that dataset — it is displayed
in the UI labelled exactly as such. For production use, retrain on a
labelled real-world dataset (e.g. EMBER) without changing the app code.

Run:  python -m ml_engine.train_model
"""
import json
import os
import pickle
import time

import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
N_PER_CLASS = 4000
RANDOM_SEED = 42


def _gen_class(rng, cls, n):
    """Class-conditional feature distributions matching features.py (18 features)."""
    if cls == 0:    # SAFE: documents, media, small utilities
        size = rng.uniform(5, 15, n)
        ent = np.clip(rng.normal(5.6, 0.9, n), 2, 8)
        api = np.clip(rng.normal(0.01, 0.02, n), 0, 1)
        sstr = np.clip(rng.normal(0.01, 0.02, n), 0, 1)
        is_pe = rng.binomial(1, 0.25, n).astype(float)
        hesr = np.clip(rng.normal(0.02, 0.05, n), 0, 1)
        dbl = rng.binomial(1, 0.01, n).astype(float)
        mism = rng.binomial(1, 0.01, n).astype(float)
        scr = np.clip(rng.normal(0.01, 0.03, n), 0, 1)
    elif cls == 1:  # SUSPICIOUS: adware/PUP-like, some indicators
        size = rng.uniform(8, 16, n)
        ent = np.clip(rng.normal(6.6, 0.7, n), 3, 8)
        api = np.clip(rng.normal(0.15, 0.12, n), 0, 1)
        sstr = np.clip(rng.normal(0.12, 0.10, n), 0, 1)
        is_pe = rng.binomial(1, 0.7, n).astype(float)
        hesr = np.clip(rng.normal(0.2, 0.15, n), 0, 1)
        dbl = rng.binomial(1, 0.15, n).astype(float)
        mism = rng.binomial(1, 0.12, n).astype(float)
        scr = np.clip(rng.normal(0.15, 0.12, n), 0, 1)
    else:           # MALWARE: packed, many indicators
        size = rng.uniform(9, 17, n)
        ent = np.clip(rng.normal(7.5, 0.4, n), 4, 8)
        api = np.clip(rng.normal(0.45, 0.2, n), 0, 1)
        sstr = np.clip(rng.normal(0.4, 0.2, n), 0, 1)
        is_pe = rng.binomial(1, 0.85, n).astype(float)
        hesr = np.clip(rng.normal(0.55, 0.25, n), 0, 1)
        dbl = rng.binomial(1, 0.25, n).astype(float)
        mism = rng.binomial(1, 0.2, n).astype(float)
        scr = np.clip(rng.normal(0.3, 0.18, n), 0, 1)

    printable = np.clip(1.05 - ent / 9 + rng.normal(0, 0.08, n), 0, 1)
    unique = np.clip(ent / 8 + rng.normal(0, 0.06, n), 0, 1)
    mean_b = np.clip(rng.normal(0.5, 0.08, n), 0, 1)
    pe_exe = is_pe * rng.binomial(1, 0.9, n)
    pe_dll = is_pe * (1 - pe_exe) * rng.binomial(1, 0.5, n)
    nsec = np.where(is_pe > 0, np.clip(rng.normal(0.25 if cls == 0 else 0.2, 0.1, n), 0.05, 1), 0)
    ftype = rng.uniform(0, 0.9, n)
    autorun = rng.binomial(1, 0.002 if cls == 0 else (0.02 if cls == 1 else 0.05), n).astype(float)
    X = np.column_stack([
        size, ent, printable, unique, mean_b, is_pe, pe_exe, pe_dll, nsec,
        hesr, api, sstr, ftype, autorun, dbl, mism, scr, ent * size / 100.0,
    ])
    return X.astype(np.float32)


def main():
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    import tensorflow as tf

    rng = np.random.default_rng(RANDOM_SEED)
    X = np.vstack([_gen_class(rng, c, N_PER_CLASS) for c in range(3)])
    y = np.concatenate([np.full(N_PER_CLASS, c) for c in range(3)]).astype(np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)
    scaler = StandardScaler().fit(X_train)
    X_train_s, X_test_s = scaler.transform(X_train), scaler.transform(X_test)

    tf.keras.utils.set_random_seed(RANDOM_SEED)
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(X.shape[1],)),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(3, activation="softmax"),
    ])
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    model.fit(X_train_s, y_train, validation_split=0.15, epochs=40, batch_size=64, verbose=0,
              callbacks=[tf.keras.callbacks.EarlyStopping(
                  monitor="val_loss", patience=5, restore_best_weights=True)])

    y_pred = np.argmax(model.predict(X_test_s, verbose=0), axis=1)
    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(y_test, y_pred,
                                   target_names=["SAFE", "SUSPICIOUS", "MALWARE"], output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(os.path.join(MODEL_DIR, "model.keras"))
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as fh:
        pickle.dump(scaler, fh)
    metrics = {
        "model_version": time.strftime("synthetic-%Y%m%d"),
        "dataset": "synthetic demonstration dataset (12,000 samples, 18 static features)",
        "disclaimer": "Accuracy measured on the bundled synthetic test split only; "
                      "retrain on a labelled real-world dataset for production use.",
        "holdout_accuracy": round(acc, 4),
        "per_class": {k: {"precision": round(v["precision"], 4),
                          "recall": round(v["recall"], 4),
                          "f1": round(v["f1-score"], 4)}
                      for k, v in report.items() if k in ("SAFE", "SUSPICIOUS", "MALWARE")},
        "confusion_matrix": cm,
        "classes": ["SAFE", "SUSPICIOUS", "MALWARE"],
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"[train] hold-out accuracy = {acc:.4f}")
    print(f"[train] artefacts written to {MODEL_DIR}")


if __name__ == "__main__":
    main()
