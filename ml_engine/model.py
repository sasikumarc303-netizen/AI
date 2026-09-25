"""TensorFlow model wrapper.

The model and scaler are loaded ONCE (lazy singleton) and reused for every
scan, per the performance requirements. Any load/predict failure raises a
domain exception instead of crashing the application.
"""
import json
import os
import pickle
import threading

import numpy as np

from constants import RESULT_MALWARE, RESULT_SAFE, RESULT_SUSPICIOUS, RESULT_UNKNOWN

MODEL_VERSION = "unknown"
CLASSES = [RESULT_SAFE, RESULT_SUSPICIOUS, RESULT_MALWARE]  # index-aligned with training

_lock = threading.Lock()
_model = None
_scaler = None
_metrics = {}
_loaded = False
_load_error = None


class ModelUnavailableError(Exception):
    """Model artefacts are missing, corrupted, or unusable."""


class PredictionError(Exception):
    """The model failed to produce a prediction for a valid input."""


def _artifact_paths(model_dir):
    return (os.path.join(model_dir, "model.keras"),
            os.path.join(model_dir, "scaler.pkl"),
            os.path.join(model_dir, "metrics.json"))


def load_artifacts(model_dir: str, unknown_threshold: float = 0.60) -> None:
    """Load model, scaler and metrics once. Thread-safe, idempotent."""
    global _model, _scaler, _metrics, _loaded, _load_error, MODEL_VERSION
    with _lock:
        if _loaded:
            return
        model_path, scaler_path, metrics_path = _artifact_paths(model_dir)
        try:
            if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
                raise ModelUnavailableError(
                    "Model artefacts not found. Run `python -m ml_engine.train_model` first.")
            import tensorflow as tf  # deferred import keeps app boot fast
            _model = tf.keras.models.load_model(model_path)
            with open(scaler_path, "rb") as fh:
                _scaler = pickle.load(fh)
            if os.path.exists(metrics_path):
                with open(metrics_path, "r", encoding="utf-8") as fh:
                    _metrics = json.load(fh)
                MODEL_VERSION = _metrics.get("model_version", "unknown")
            _loaded = True
        except ModelUnavailableError as exc:
            _load_error = str(exc)
            _loaded = True  # do not retry every request; error is cached
        except Exception as exc:  # corrupted model, TF error, etc.
            _load_error = f"Failed to load model artefacts: {exc.__class__.__name__}"
            _loaded = True


def is_ready() -> bool:
    return _model is not None and _scaler is not None


def status() -> dict:
    return {"ready": is_ready(), "error": _load_error, "model_version": MODEL_VERSION,
            "metrics": _metrics}


def predict_features(vector, unknown_threshold: float = 0.60) -> dict:
    """Classify one feature vector. Honest UNKNOWN below the confidence threshold."""
    if not is_ready():
        raise ModelUnavailableError(_load_error or "Model is not loaded.")
    arr = np.asarray([vector], dtype=np.float32)
    if arr.shape[1] != _scaler.n_features_in_:
        raise PredictionError("Feature vector has an unexpected dimension.")
    try:
        with _lock:
            scaled = _scaler.transform(arr)
            probs = _model.predict(scaled, verbose=0)[0]
    except Exception as exc:
        raise PredictionError(f"Model inference failed: {exc.__class__.__name__}") from exc

    idx = int(np.argmax(probs))
    confidence = float(probs[idx])
    result = CLASSES[idx] if confidence >= unknown_threshold else RESULT_UNKNOWN
    return {
        "result": result,
        "confidence": round(confidence, 4),
        "probabilities": {CLASSES[i]: round(float(probs[i]), 4) for i in range(len(CLASSES))},
        "model_version": MODEL_VERSION,
        "below_threshold": result == RESULT_UNKNOWN,
    }
