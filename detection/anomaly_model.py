# detection/anomaly_model.py
from sklearn.ensemble import IsolationForest
import numpy as np

class SimpleAnomalyModel:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self._trained = False

    def train(self, X):
        self.model.fit(X)
        self._trained = True

    def predict(self, features):
        arr = np.array(features).reshape(1, -1)
        if not self._trained:
            # fallback heuristics: cpu > 80 or mem > 50
            cpu, mem = arr[0][0], arr[0][1]
            return -1 if (cpu>80 or mem>60) else 1
        return int(self.model.predict(arr)[0])

    def score(self, features):
        if not self._trained:
            return 0.0
        return float(self.model.decision_function(np.array(features).reshape(1,-1))[0])
